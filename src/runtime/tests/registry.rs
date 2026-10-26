use super::support::*;
use super::*;

#[test]
fn wbem_connect_server_registry_machine_guid_mismatch_guard() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("wbem-identity");
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::WbemLocatorConnectServer);
        let out_ptr = 0x42_000_u32;
        memory.map_bytes(out_ptr as u64, &[0u8; 8]);
        // IWbemLocator::ConnectServer(this, server, user, password, locale,
        // flags, authority, ctx, ppNamespace).
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0, 0, 0, 0, 0, 0, 0, 0, out_ptr],
        );
        assert_eq!(result, 0); // S_OK
        let identity = crate::hardware_identity::host_identity();
        let stored = runtime
            .win32
            .ge()
            .registry_get_value(
                "HKLM",
                crate::hardware_identity::MACHINE_GUID_KEY,
                crate::hardware_identity::MACHINE_GUID_VALUE,
                crate::ge::RegistryView::Native,
            )
            .expect("registry read")
            .expect("machine guid is mirrored into the guest registry");
        assert_eq!(
            stored.data.as_str(),
            Some(identity.install.machine_guid.as_str())
        );
    })
}

#[test]
fn reg_close_key_on_non_key_handle_is_invalid_handle() {
    // RegCloseKey(event) must fail with ERROR_INVALID_HANDLE and must
    // NOT close the event.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "rck-event", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let (event, _) = runtime.win32.create_event(true, false, false, None);
        let close_key_thunk = runtime.alloc_host_thunk(HostThunk::RegCloseKey);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, close_key_thunk, &[event]);
        assert_eq!(result, ERROR_INVALID_HANDLE as u64);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        runtime
            .win32
            .set_event(event)
            .expect("event survives RegCloseKey misuse");

        // A real key still closes.
        let key = runtime.win32.open_registry_key(
            "HKEY_CURRENT_USER",
            "Software\\Casa1\\probe",
            crate::ge::RegistryView::Native,
            false,
        );
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, close_key_thunk, &[key]);
        assert_eq!(result, 0, "ERROR_SUCCESS");
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn evidence_shlwapi_fs_registry_and_url_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-shlwapi-fsreg");
        let mut memory = MemoryImage::default();
        let file_exists = runtime.alloc_host_thunk(HostThunk::PathFileExistsW);
        let is_directory = runtime.alloc_host_thunk(HostThunk::PathIsDirectoryW);
        let reg_get = runtime.alloc_host_thunk(HostThunk::SHRegGetValueW);
        let reg_set = runtime.alloc_host_thunk(HostThunk::SHRegSetValueW);
        let reg_delete = runtime.alloc_host_thunk(HostThunk::SHDeleteKeyW);
        let reg_delete_empty = runtime.alloc_host_thunk(HostThunk::SHDeleteEmptyKeyW);
        let search_map = runtime.alloc_host_thunk(HostThunk::SHSearchMapInt);
        let get_help_id = runtime.alloc_host_thunk(HostThunk::GetMenuContextHelpId);
        let set_help_id = runtime.alloc_host_thunk(HostThunk::SetMenuContextHelpId);
        let url_canonicalize = runtime.alloc_host_thunk(HostThunk::UrlCanonicalizeW);
        let url_combine = runtime.alloc_host_thunk(HostThunk::UrlCombineW);

        // PathFileExistsW / PathIsDirectoryW consult the win32 filesystem.
        runtime
            .win32
            .create_directory_w("C:\\Games")
            .expect("create Games directory");
        runtime
            .win32
            .create_file_w(
                "C:\\Games\\demo.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        let dir_w = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games")
            .expect("wide dir");
        let file_w = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\demo.txt")
            .expect("wide file");
        let missing_w = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\missing.txt")
            .expect("wide missing");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, file_exists, &[file_w as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, file_exists, &[dir_w as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, file_exists, &[missing_w as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, is_directory, &[dir_w as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, is_directory, &[file_w as u32]),
            0
        );

        // SHRegSetValueW writes a value (creating the key path);
        // SHRegGetValueW reads it back with type filtering.
        let sub_key = runtime
            .alloc_utf16_string(&mut memory, r"Software\Casa1\Demo")
            .expect("wide subkey");
        let value_name = runtime
            .alloc_utf16_string(&mut memory, "Mode")
            .expect("wide value name");
        let dword_data = 0x43_600;
        memory.map_bytes(dword_data, &7_u32.to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                reg_set,
                &[
                    0x8000_0001, // HKEY_CURRENT_USER
                    sub_key as u32,
                    value_name as u32,
                    0,
                    4, // REG_DWORD
                    dword_data as u32,
                    4,
                ]
            ),
            0
        );
        let type_out = 0x43_610;
        memory.map_bytes(type_out, &[0_u8; 4]);
        let data_out = 0x43_620;
        memory.map_bytes(data_out, &[0_u8; 8]);
        let size_out = 0x43_630;
        memory.map_bytes(size_out, &4_u32.to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                reg_get,
                &[
                    0x8000_0001,
                    sub_key as u32,
                    value_name as u32,
                    0x0020, // SRRF_RT_REG_DWORD
                    type_out as u32,
                    data_out as u32,
                    size_out as u32,
                ]
            ),
            0
        );
        assert_eq!(memory.read_u32(type_out).unwrap(), 4);
        assert_eq!(memory.read_u32(data_out).unwrap(), 7);
        assert_eq!(memory.read_u32(size_out).unwrap(), 4);
        // A REG_DWORD value under a REG_SZ-only filter fails.
        let dword_filter = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            reg_get,
            &[
                0x8000_0001,
                sub_key as u32,
                value_name as u32,
                0x0002, // SRRF_RT_REG_SZ only
                type_out as u32,
                data_out as u32,
                size_out as u32,
            ],
        );
        assert_eq!(dword_filter, ERROR_INVALID_PARAMETER as u64);
        // A missing value reports ERROR_FILE_NOT_FOUND.
        let missing_value = runtime
            .alloc_utf16_string(&mut memory, "Absent")
            .expect("wide absent value");
        let not_found = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            reg_get,
            &[
                0x8000_0001,
                sub_key as u32,
                missing_value as u32,
                0xFFFF,
                type_out as u32,
                data_out as u32,
                size_out as u32,
            ],
        );
        assert_eq!(not_found, ERROR_FILE_NOT_FOUND as u64);

        // SHDeleteKeyW removes the key (recursively).
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            reg_delete,
            &[0x8000_0001, sub_key as u32],
        );
        assert_eq!(result, 0);
        // SHDeleteEmptyKeyW fails on a key that still has values.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                reg_set,
                &[
                    0x8000_0001,
                    sub_key as u32,
                    value_name as u32,
                    0,
                    4,
                    dword_data as u32,
                    4,
                ]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                reg_delete_empty,
                &[0x8000_0001, sub_key as u32]
            ),
            ERROR_DIR_NOT_EMPTY as u64
        );
        // SHDeleteKeyW removes the non-empty key recursively.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                reg_delete,
                &[0x8000_0001, sub_key as u32]
            ),
            0
        );

        // SHSearchMapInt: first matching key wins; -1 when absent.
        let keys = 0x43_640;
        let mut key_bytes = Vec::new();
        key_bytes.extend(10_i32.to_le_bytes());
        key_bytes.extend(20_i32.to_le_bytes());
        key_bytes.extend(30_i32.to_le_bytes());
        memory.map_bytes(keys, &key_bytes);
        let values = 0x43_650;
        let mut value_bytes = Vec::new();
        value_bytes.extend(100_i32.to_le_bytes());
        value_bytes.extend(200_i32.to_le_bytes());
        value_bytes.extend(300_i32.to_le_bytes());
        memory.map_bytes(values, &value_bytes);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                search_map,
                &[keys as u32, values as u32, 3, 20]
            ),
            200
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                search_map,
                &[keys as u32, values as u32, 3, 99]
            ),
            u64::from(-1_i32 as u32)
        );

        // SetMenuContextHelpId / GetMenuContextHelpId round-trip per HMENU.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_help_id, &[0x1000]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_help_id, &[0x1000, 0xABCD]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_help_id, &[0x1000]),
            0xABCD
        );

        // UrlCanonicalizeW lowercases the scheme/host, resolves dot
        // segments, and keeps the query/fragment tail.
        let canonical_cases: &[(&str, &str)] = &[
            (
                "HTTP://Example.COM/Path/../file.txt",
                "http://example.com/file.txt",
            ),
            ("http://example.com/a/./b", "http://example.com/a/b"),
            ("http://example.com", "http://example.com/"),
            ("http://example.com/a/..", "http://example.com/"),
            (
                "http://example.com/a?x=1#frag",
                "http://example.com/a?x=1#frag",
            ),
            ("", ""),
        ];
        for (input, expected) in canonical_cases {
            let out = 0x43_700;
            memory.map_bytes(out, &[0_u8; 0x200]);
            let len_out = 0x43_D10;
            memory.map_bytes(len_out, &0x100_u32.to_le_bytes());
            let url = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide url");
            let result = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                url_canonicalize,
                &[url as u32, out as u32, len_out as u32, 0],
            );
            assert_eq!(result, 0, "UrlCanonicalizeW({input:?})");
            assert_eq!(
                read_guest_utf16_string(&memory, out, 256),
                *expected,
                "UrlCanonicalizeW({input:?})"
            );
        }
        // A too-small buffer returns E_POINTER with the required size.
        let long = runtime
            .alloc_utf16_string(&mut memory, "http://example.com/toolong")
            .expect("wide long url");
        let out = 0x43_900;
        memory.map_bytes(out, &[0_u8; 0x40]);
        let len_out = 0x43_910;
        memory.map_bytes(len_out, &4_u32.to_le_bytes());
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            url_canonicalize,
            &[long as u32, out as u32, len_out as u32, 0],
        );
        assert_eq!(result, 0x8000_4003);
        assert_eq!(memory.read_u32(len_out).unwrap(), 27);

        // UrlCombineW resolves a relative URL against the base (the base's
        // last leaf is replaced).
        let combine_cases: &[(&str, &str, &str)] = &[
            (
                "http://example.com/a/b.html",
                "c.html",
                "http://example.com/a/c.html",
            ),
            (
                "http://example.com/a/b.html",
                "/root.html",
                "http://example.com/root.html",
            ),
            (
                "http://example.com/a/b.html",
                "http://other.org/x",
                "http://other.org/x",
            ),
        ];
        for (base, relative, expected) in combine_cases {
            let out = 0x43_A00;
            memory.map_bytes(out, &[0_u8; 0x200]);
            let len_out = 0x43_D00;
            memory.map_bytes(len_out, &0x100_u32.to_le_bytes());
            let base_ptr = runtime
                .alloc_utf16_string(&mut memory, base)
                .expect("wide base");
            let rel_ptr = runtime
                .alloc_utf16_string(&mut memory, relative)
                .expect("wide relative");
            let result = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                url_combine,
                &[
                    base_ptr as u32,
                    rel_ptr as u32,
                    out as u32,
                    len_out as u32,
                    0,
                ],
            );
            assert_eq!(result, 0, "UrlCombineW({base:?}, {relative:?})");
            assert_eq!(
                read_guest_utf16_string(&memory, out, 256),
                *expected,
                "UrlCombineW({base:?}, {relative:?})"
            );
        }
    })
}

// ── evidence-mid: advapi32 registry leftovers + event source ──────────
#[test]
fn evidence_mid_advapi32_registry_event_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-registry");
        let mut memory = MemoryImage::default();

        // RegCreateKeyExW + RegSetValueExW provision the key.
        let root = HKEY_CURRENT_USER;
        let subkey_ptr = runtime
            .alloc_utf16_string(&mut memory, "Software\\Game")
            .expect("subkey");
        let key_out = 0x64_000;
        memory.map_bytes(key_out, &[0; 4]);
        let create_key = runtime.alloc_host_thunk(HostThunk::RegCreateKeyExW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_key,
                &[
                    root,
                    subkey_ptr as u32,
                    0,
                    0,
                    0,
                    0x20019,
                    0,
                    key_out as u32,
                    0
                ]
            ),
            0
        );
        let hkey = read_u32(&memory, key_out).expect("hkey");
        let set_value = runtime.alloc_host_thunk(HostThunk::RegSetValueExW);
        let value_name = runtime
            .alloc_utf16_string(&mut memory, "Score")
            .expect("value name");
        let dword_data = 0x64_100;
        memory.map_bytes(dword_data, &42_u32.to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_value,
                &[hkey, value_name as u32, 0, REG_DWORD, dword_data as u32, 4]
            ),
            0
        );

        // RegQueryInfoKeyW reports the key's statistics.
        let subkeys_out = 0x64_200;
        let values_out = 0x64_210;
        let max_value_out = 0x64_220;
        memory.map_bytes(subkeys_out, &[0; 4]);
        memory.map_bytes(values_out, &[0; 4]);
        memory.map_bytes(max_value_out, &[0; 4]);
        let query_info = runtime.alloc_host_thunk(HostThunk::RegQueryInfoKeyW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query_info,
                &[
                    hkey,
                    0,
                    0,
                    0,
                    subkeys_out as u32,
                    0,
                    0,
                    values_out as u32,
                    max_value_out as u32,
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(read_u32(&memory, subkeys_out).expect("subkeys"), 0);
        assert_eq!(read_u32(&memory, values_out).expect("values"), 1);
        assert!(read_u32(&memory, max_value_out).expect("max value") >= 5);

        // RegEnumValueW enumerates "Score" with its REG_DWORD payload.
        let name_buf = 0x64_300;
        memory.map_bytes(name_buf, &[0; 32]);
        let name_size = 0x64_310;
        memory.map_bytes(name_size, &16_u32.to_le_bytes());
        let type_out = 0x64_320;
        memory.map_bytes(type_out, &[0; 4]);
        let data_buf = 0x64_330;
        memory.map_bytes(data_buf, &[0; 16]);
        let data_size = 0x64_340;
        memory.map_bytes(data_size, &16_u32.to_le_bytes());
        let enum_value = runtime.alloc_host_thunk(HostThunk::RegEnumValueW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_value,
                &[
                    hkey,
                    0,
                    name_buf as u32,
                    name_size as u32,
                    0,
                    type_out as u32,
                    data_buf as u32,
                    data_size as u32
                ]
            ),
            0
        );
        assert_eq!(
            read_utf16_string(&memory, name_buf).expect("value name"),
            "Score"
        );
        assert_eq!(read_u32(&memory, type_out).expect("type"), REG_DWORD);
        assert_eq!(read_u32(&memory, data_buf).expect("data"), 42);
        // Exhaustion reports ERROR_NO_MORE_ITEMS.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_value,
                &[
                    hkey,
                    1,
                    name_buf as u32,
                    name_size as u32,
                    0,
                    type_out as u32,
                    data_buf as u32,
                    data_size as u32
                ]
            ),
            ERROR_NO_MORE_ITEMS as u64
        );

        // RegFlushKey succeeds on the write-through registry.
        let flush = runtime.alloc_host_thunk(HostThunk::RegFlushKey);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, flush, &[hkey]),
            0
        );

        // RegOpenCurrentUser mints an HKCU root handle usable with
        // RegQueryInfoKeyW.
        let user_key_out = 0x64_400;
        memory.map_bytes(user_key_out, &[0; 4]);
        let open_current_user = runtime.alloc_host_thunk(HostThunk::RegOpenCurrentUser);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_current_user,
                &[0x20019, user_key_out as u32]
            ),
            0
        );
        let user_key = read_u32(&memory, user_key_out).expect("user key");
        assert_ne!(user_key, 0);
        let user_values = 0x64_410;
        memory.map_bytes(user_values, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query_info,
                &[user_key, 0, 0, 0, 0, 0, 0, user_values as u32, 0, 0, 0, 0]
            ),
            0,
            "the HKCU root handle resolves for RegQueryInfoKeyW"
        );

        // EventRegister → EventWrite → EventUnregister: the documented
        // ERROR_SUCCESS contract.
        let provider_guid = 0x64_500;
        write_test_guid(&mut memory, provider_guid, 0x1122_3344);
        let reg_handle_out = 0x64_510;
        memory.map_bytes(reg_handle_out, &[0; 8]);
        let event_register = runtime.alloc_host_thunk(HostThunk::EventRegister);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                event_register,
                &[provider_guid as u32, 0, 0, reg_handle_out as u32]
            ),
            0
        );
        let reg_handle = read_u64(&memory, reg_handle_out).expect("reg handle");
        assert_ne!(reg_handle, 0);
        let event_write = runtime.alloc_host_thunk(HostThunk::EventWrite);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                event_write,
                &[reg_handle as u32, 0, 0, 0]
            ),
            0
        );
        let event_unregister = runtime.alloc_host_thunk(HostThunk::EventUnregister);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                event_unregister,
                &[reg_handle as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                event_write,
                &[reg_handle as u32, 0, 0, 0]
            ),
            ERROR_INVALID_PARAMETER as u64,
            "writing through an unregistered handle fails"
        );
    })
}
