use super::support::*;
use super::*;

#[test]
fn win_verify_trust_rejects_non_file_union_choice() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "wvt-choice", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // dwUnionChoice = 2 (WTD_CHOICE_CATALOG) — unsupported subject form.
        let wvt_ptr = build_x86_wintrust_data(&mut runtime, &mut memory, "C:\\game\\app.exe", 2);
        let thunk = runtime.alloc_host_thunk(HostThunk::WinVerifyTrust);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 0, wvt_ptr as u32]);

        // TRUST_E_SUBJECT_FORM_UNKNOWN
        assert_eq!(result, 0x800B_0003);
    })
}

#[test]
fn win_verify_trust_rejects_invalid_signature_on_disk() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "wvt-invalid", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let guest_path = "C:\\game\\app.exe";
        write_guest_pe_file(&runtime, guest_path, &pe_with_garbage_certificate_table());
        let wvt_ptr = build_x86_wintrust_data(&mut runtime, &mut memory, guest_path, 1);
        let thunk = runtime.alloc_host_thunk(HostThunk::WinVerifyTrust);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 0, wvt_ptr as u32]);

        // TRUST_E_BAD_DIGEST
        assert_eq!(result, 0x8009_6010);
    })
}

#[test]
fn get_cp_info_and_is_valid_code_page_cover_the_standard_code_pages() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("cp-info");
        let mut memory = MemoryImage::default();
        let get_cp_info = runtime.alloc_host_thunk(HostThunk::GetCPInfo);
        let is_valid = runtime.alloc_host_thunk(HostThunk::IsValidCodePage);
        let cp_info_ptr = 0x41_000_u32;
        memory.map_bytes(cp_info_ptr as u64, &[0; 16]);

        // ANSI SBCS page 1252: 1 byte/char.
        let result =
            dispatch_x86_thunk(&mut runtime, &mut memory, get_cp_info, &[1252, cp_info_ptr]);
        assert_eq!(result, 1);
        assert_eq!(
            memory.read_u32(cp_info_ptr as u64).expect("max char size"),
            1
        );
        // DBCS page 932 (Shift-JIS): 2 bytes/char.
        let result =
            dispatch_x86_thunk(&mut runtime, &mut memory, get_cp_info, &[932, cp_info_ptr]);
        assert_eq!(result, 1);
        assert_eq!(
            memory.read_u32(cp_info_ptr as u64).expect("max char size"),
            2
        );
        // UTF-8: 4 bytes/char.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_cp_info,
            &[65001, cp_info_ptr],
        );
        assert_eq!(result, 1);
        assert_eq!(
            memory.read_u32(cp_info_ptr as u64).expect("max char size"),
            4
        );
        // Unknown code pages fail with ERROR_INVALID_PARAMETER.
        let result =
            dispatch_x86_thunk(&mut runtime, &mut memory, get_cp_info, &[9999, cp_info_ptr]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // IsValidCodePage mirrors the same table.
        for valid in [437, 850, 932, 936, 949, 950, 1250, 1252, 1258, 65001] {
            let result = dispatch_x86_thunk(&mut runtime, &mut memory, is_valid, &[valid]);
            assert_eq!(result, 1, "code page {valid} must be valid");
            assert_eq!(runtime.last_error, 0);
        }
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, is_valid, &[9999]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

#[test]
fn critical_section_thunks_use_x86_stack_argument() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "critical-sections",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        let critical_section = 0x41_000_u32;
        memory.map_bytes(critical_section as u64, &[0; 24]);

        let initialize = runtime.alloc_host_thunk(HostThunk::InitializeCriticalSection);
        let enter = runtime.alloc_host_thunk(HostThunk::EnterCriticalSection);
        let try_enter = runtime.alloc_host_thunk(HostThunk::TryEnterCriticalSection);
        let leave = runtime.alloc_host_thunk(HostThunk::LeaveCriticalSection);
        let delete = runtime.alloc_host_thunk(HostThunk::DeleteCriticalSection);

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, initialize, &[critical_section]),
            1
        );
        assert_eq!(
            runtime
                .critical_sections
                .get(&(critical_section as u64))
                .copied(),
            Some(0)
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 4).expect("lock count"),
            u32::MAX
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 8).expect("recursion count"),
            0
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 12).expect("owner thread"),
            0
        );

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, enter, &[critical_section]),
            0
        );
        assert_eq!(
            runtime
                .critical_sections
                .get(&(critical_section as u64))
                .copied(),
            Some(1)
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 4).expect("lock count after enter"),
            0
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 8).expect("recursion after enter"),
            1
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 12).expect("owner after enter"),
            1
        );

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_enter, &[critical_section]),
            1
        );
        assert_eq!(
            runtime
                .critical_sections
                .get(&(critical_section as u64))
                .copied(),
            Some(2)
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 4).expect("lock count after try enter"),
            1
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 8).expect("recursion after try enter"),
            2
        );

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, leave, &[critical_section]),
            0
        );
        assert_eq!(
            runtime
                .critical_sections
                .get(&(critical_section as u64))
                .copied(),
            Some(1)
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 4).expect("lock count after leave"),
            0
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 8).expect("recursion after leave"),
            1
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 12).expect("owner after leave"),
            1
        );

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delete, &[critical_section]),
            0
        );
        assert!(
            !runtime
                .critical_sections
                .contains_key(&(critical_section as u64))
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 4).expect("lock count after delete"),
            u32::MAX
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 8).expect("recursion after delete"),
            0
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 12).expect("owner after delete"),
            0
        );
    })
}

#[test]
fn condition_variable_thunks_use_x86_stack_arguments() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "condition-variables",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        let critical_section = 0x41_000_u32;
        let condition_variable = 0x42_000_u32;
        memory.map_bytes(critical_section as u64, &[0; 24]);
        memory.map_bytes(condition_variable as u64, &[0; 4]);

        let initialize = runtime.alloc_host_thunk(HostThunk::InitializeCriticalSection);
        let enter = runtime.alloc_host_thunk(HostThunk::EnterCriticalSection);
        let sleep_condition = runtime.alloc_host_thunk(HostThunk::SleepConditionVariableCS);
        let wake_all = runtime.alloc_host_thunk(HostThunk::WakeAllConditionVariable);

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, initialize, &[critical_section]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, enter, &[critical_section]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sleep_condition,
                &[condition_variable, critical_section, 0],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_TIMEOUT);
        assert_eq!(
            runtime
                .critical_sections
                .get(&(critical_section as u64))
                .copied(),
            Some(1)
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 4).expect("lock count after sleep"),
            0
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 8).expect("recursion after sleep"),
            1
        );
        assert_eq!(
            read_u32(&memory, critical_section as u64 + 12).expect("owner after sleep"),
            1
        );

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wake_all, &[condition_variable]),
            0
        );
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn decode_current_instruction_cache_evicts_old_entries_without_clearing_hot_entries() {
    with_big_stack(|| {
        let base_rip = 0xB000;
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        let mut instruction_cache = U64Map::default();
        let mut instruction_cache_lru = VecDeque::new();
        let mut instruction_cache_generation = 0;

        memory.map_bytes(base_rip, &[0x90; 15]);
        memory.map_bytes(
            base_rip + 0x10,
            &[
                0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90,
            ],
        );
        memory.map_bytes(
            base_rip + 0x20,
            &[
                0x50, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90,
            ],
        );

        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip,
        )
        .expect("decode first instruction");
        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip + 0x10,
        )
        .expect("decode second instruction");
        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip,
        )
        .expect("refresh first instruction");
        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip + 0x20,
        )
        .expect("decode third instruction");

        assert!(instruction_cache.contains_key(&base_rip));
        assert!(instruction_cache.contains_key(&(base_rip + 0x20)));
        assert!(!instruction_cache.contains_key(&(base_rip + 0x10)));
        assert_eq!(instruction_cache.len(), 2);
    })
}

#[test]
fn decode_basic_block_cache_refreshes_when_block_bytes_change() {
    with_big_stack(|| {
        let rip = 0xE000;
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let mut engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        let mut instruction_cache = U64Map::default();
        let mut instruction_cache_lru = VecDeque::new();
        let mut instruction_cache_generation = 0;
        let mut basic_block_cache = U64Map::default();
        let mut basic_block_cache_lru = VecDeque::new();
        let mut basic_block_cache_generation = 0;

        let mut bytes = vec![0x90; 32];
        bytes[2] = 0xC3;
        memory.map_bytes(rip, &bytes);
        let first = decode_basic_block_cached(
            &mut engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            &mut basic_block_cache,
            &mut basic_block_cache_lru,
            &mut basic_block_cache_generation,
            BASIC_BLOCK_CACHE_LIMIT,
            rip,
        )
        .expect("decode cached block");
        assert_eq!(first.bytes, vec![0x90, 0x90, 0xC3]);

        memory.map_bytes(
            rip,
            &[
                0xB8, 0x78, 0x56, 0x34, 0x12, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                0x90, 0x90,
            ],
        );
        let second = decode_basic_block_cached(
            &mut engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            &mut basic_block_cache,
            &mut basic_block_cache_lru,
            &mut basic_block_cache_generation,
            BASIC_BLOCK_CACHE_LIMIT,
            rip,
        )
        .expect("re-decode after self-modification");

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.bytes, vec![0xB8, 0x78, 0x56, 0x34, 0x12, 0xC3]);
        assert_eq!(second.end_rip - second.start_rip, 6);
    })
}

// -----------------------------------------------------------------------
// Phase 0.4 — Forwarded export chaining
// -----------------------------------------------------------------------
// -----------------------------------------------------------------------
// Phase 0.5 — Synthetic DLL DllMain callbacks
// -----------------------------------------------------------------------
// -----------------------------------------------------------------------
// HMODULE tracking (DllInfo table)
// -----------------------------------------------------------------------
// -----------------------------------------------------------------------
// call_dll_entry_points — DllMain notification for all loaded DLLs
// -----------------------------------------------------------------------
// -----------------------------------------------------------------------
// GetProcAddress with forwarded exports
// -----------------------------------------------------------------------
#[test]
fn get_proc_address_sets_error_on_unknown_export() {
    with_big_stack(|| {
        // PeHostRuntime is very large; run on a thread with a bigger stack to
        // avoid overflowing the default test-thread stack.
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let temp_dir = TempDir::new().expect("temp dir");
                let ge = GameEnvironment::create_in(
                    temp_dir.path(),
                    "gpa-err",
                    GeArch::X86,
                    "win11-23h2",
                )
                .expect("create ge");
                let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
                configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
                let mut memory = MemoryImage::default();

                let kernel32_handle = runtime.get_or_create_module_handle("kernel32.dll");
                assert_ne!(kernel32_handle, 0);

                let name_addr = runtime
                    .alloc_c_string(&mut memory, "NonExistentExport")
                    .expect("alloc name string");
                let proc_addr = runtime.alloc_host_thunk(HostThunk::GetProcAddress);

                let rax = dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    proc_addr,
                    &[kernel32_handle as u32, name_addr as u32],
                );
                assert_eq!(rax, 0, "GetProcAddress of unknown export should return 0");
                assert_eq!(
                    runtime.last_error, ERROR_PROC_NOT_FOUND,
                    "last_error should be ERROR_PROC_NOT_FOUND (127)"
                );
            })
            .expect("thread spawn")
            .join()
            .expect("test thread panicked");
    })
}

#[test]
fn fast_thunk_register_populates_index() {
    with_big_stack(|| {
        // Fast-thunks are intentionally disabled (the direct-call bridge
        // crashes the guest on a subset of thunks).  register_fast_thunk is
        // now a no-op, so it must NOT populate thunk_to_fast_index.  Host
        // calls instead route through the normal EXIT_THUNK → dispatcher
        // path, which is correct for every thunk.
        let (mut runtime, _memory) = setup_fast_thunk_runtime();

        let thunk_addr = runtime.next_thunk_address;
        runtime
            .host_thunks
            .insert(thunk_addr, HostThunk::GetModuleHandleA);
        runtime.register_fast_thunk(thunk_addr);

        assert!(
            !runtime.thunk_to_fast_index.contains_key(&thunk_addr),
            "register_fast_thunk is a no-op now (fast-thunks disabled); \
                 thunk_to_fast_index must stay empty",
        );
    })
}

#[test]
fn fast_thunk_alloc_host_thunk_registers_fast_thunk() {
    with_big_stack(|| {
        // alloc_host_thunk must still record the thunk in host_thunks (so the
        // normal dispatcher can handle it) but must NOT register a fast-thunk.
        let (mut runtime, _memory) = setup_fast_thunk_runtime();

        let thunk_addr = runtime.alloc_host_thunk(HostThunk::GetModuleHandleA);

        assert!(
            !runtime.thunk_to_fast_index.contains_key(&thunk_addr),
            "alloc_host_thunk must not register a fast-thunk (disabled)",
        );
        assert!(
            runtime.host_thunks.contains_key(&thunk_addr),
            "alloc_host_thunk should populate host_thunks",
        );
    })
}

#[test]
fn fast_thunk_dispatch_fallback_for_unregistered() {
    with_big_stack(|| {
        let (mut runtime, mut memory) = setup_fast_thunk_runtime();

        let unknown_addr = 0xBADD_CAFE_u64;
        let result = runtime
            .dispatch_import_if_present(
                unknown_addr,
                &mut CpuState::new(GuestArch::X64),
                &mut memory,
            )
            .expect("dispatch_import_if_present should not error for unknown thunk");

        assert_eq!(result, None, "unregistered thunk should return None");
    })
}

#[test]
fn fast_thunk_import_resolution_registers_fast_thunk() {
    with_big_stack(|| {
        // Verify that creating a host thunk from a ResolvedImport (as done by
        // bind_imports) and then calling register_fast_thunk correctly populates
        // both the thunk_to_fast_index and the JIT runtime's trampoline table.
        let (mut runtime, _memory) = setup_fast_thunk_runtime();

        // Simulate what bind_imports does for each imported function:
        // 1. Create a thunk from the import descriptor
        let import = ResolvedImport {
            requested_module: "kernel32.dll".to_string(),
            resolved_module: "kernel32.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: "GetModuleHandleA".to_string(),
            },
            iat_rva: 0,
            export: ExportSymbol {
                ordinal: 0,
                name: None,
                target: ExportTarget::Rva(0),
            },
        };
        let thunk_addr = runtime.next_thunk_address;
        runtime.next_thunk_address += 0x10;
        runtime
            .host_thunks
            .insert(thunk_addr, HostThunk::from_import(&import));
        assert!(
            runtime.host_thunks.contains_key(&thunk_addr),
            "host_thunks should contain the import thunk",
        );

        // 2. Register the fast-thunk trampoline (as bind_imports does via
        //    register_fast_thunk) — now a no-op since fast-thunks are disabled.
        runtime.register_fast_thunk(thunk_addr);

        // 3. Verify NO fast-thunk mapping exists (disabled).
        assert!(
            !runtime.thunk_to_fast_index.contains_key(&thunk_addr),
            "fast-thunks are disabled; thunk_to_fast_index must stay empty",
        );
    })
}

#[test]
fn test_pe_resolve_imports_missing_dll() {
    with_big_stack(|| {
        use crate::pe::{ImportDescriptor, ImportThunk};
        let image = crate::pe::ParsedPe {
            machine: 0x14c,
            number_of_sections: 0,
            characteristics: 0,
            optional_header_magic: 0x10b,
            subsystem: 3,
            dll_characteristics: 0,
            address_of_entry_point: 0,
            image_base: 0x400000,
            size_of_image: 0x1000,
            size_of_headers: 0x200,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            data_directories: vec![],
            sections: vec![],
            debug_entries: vec![],
            load_config: None,
            imports: vec![ImportDescriptor {
                dll_name: "nonexistent.dll".to_string(),
                imports: vec![ImportThunk {
                    symbol: ImportSymbol::ByName {
                        hint: 0,
                        name: "SomeFunc".to_string(),
                    },
                    iat_rva: 0x1000,
                }],
                delay_load: false,
            }],
            delay_imports: vec![],
            exports: vec![],
            relocations: vec![],
            tls_directory: None,
            version_info: Default::default(),
            embedded_manifest: None,
            external_manifest: None,
            is_dotnet: false,
            clr_header: None,
            bound_imports: vec![],
            arm64: None,
        };
        let export_tables = BTreeMap::new();
        let resolver = crate::pe::ApiSetResolver::new();
        let result = crate::pe::resolve_imports(&image, &export_tables, &resolver);
        assert!(
            result.is_err(),
            "missing DLL should cause import resolution failure"
        );
        let err = result.unwrap_err();
        assert_eq!(err.code, ReasonCode::RcImportMissing);
    })
}

// -----------------------------------------------------------------------
// Item 112: Tests for relocation edge cases and malformed relocation blocks
// -----------------------------------------------------------------------
#[test]
fn test_relocation_unsupported_type_rejected() {
    with_big_stack(|| {
        use crate::pe::{RelocationBlock, RelocationEntry, RelocationType};
        let image = crate::pe::ParsedPe {
            machine: 0x14c,
            number_of_sections: 0,
            characteristics: 0,
            optional_header_magic: 0x10b,
            subsystem: 3,
            dll_characteristics: 0x40,
            address_of_entry_point: 0,
            image_base: 0x400000,
            size_of_image: 0x1000,
            size_of_headers: 0x200,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            data_directories: vec![],
            sections: vec![],
            debug_entries: vec![],
            load_config: None,
            imports: vec![],
            delay_imports: vec![],
            exports: vec![],
            relocations: vec![RelocationBlock {
                page_rva: 0x1000,
                entries: vec![RelocationEntry {
                    kind: RelocationType::Unsupported(7),
                    offset: 0x10,
                }],
            }],
            tls_directory: None,
            version_info: Default::default(),
            embedded_manifest: None,
            external_manifest: None,
            is_dotnet: false,
            clr_header: None,
            bound_imports: vec![],
            arm64: None,
        };
        let mut mapped = crate::pe::MappedImage {
            preferred_base: 0x400000,
            selected_base: 0x500000,
            memory: vec![0u8; 0x2000],
            sections: vec![],
        };
        let result = crate::pe::apply_relocations(&image, &mut mapped);
        assert!(result.is_err(), "unsupported relocation type should fail");
    })
}

// -----------------------------------------------------------------------
// Item 116: Tests for guest register and stack invariant preservation
// -----------------------------------------------------------------------
// -----------------------------------------------------------------------
// Item 103: Thunk metadata consistency tests
// -----------------------------------------------------------------------
#[test]
fn test_host_thunk_x86_arg_bytes_setlasterror() {
    with_big_stack(|| {
        assert_eq!(HostThunk::SetLastError.x86_arg_bytes(), 4);
    })
}

#[test]
fn test_host_thunk_supported_vs_unsupported() {
    with_big_stack(|| {
        // GetVersion is a supported thunk
        assert!(!matches!(
            HostThunk::GetVersion,
            HostThunk::Unsupported { .. }
        ));
        // Unsupported variant exists for unknown APIs
        assert!(matches!(
            HostThunk::Unsupported {
                dll: "fake.dll".into(),
                symbol: "FakeFunc".into()
            },
            HostThunk::Unsupported { .. }
        ));
    })
}

#[test]
fn bcrypt_thunk_hash_random_and_aes_roundtrip() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "bcrypt-thunks", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let open = runtime.alloc_host_thunk(HostThunk::BCryptOpenAlgorithmProvider);
        let close = runtime.alloc_host_thunk(HostThunk::BCryptCloseAlgorithmProvider);
        let sha_alg = runtime
            .alloc_utf16_string(&mut memory, "SHA256")
            .expect("sha alg");
        let provider_out = 0x61_000;
        memory.map_bytes(provider_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open,
                &[provider_out as u32, sha_alg as u32, 0, 0],
            ),
            0
        );
        let provider = read_guest_pointer(&memory, provider_out, GuestArch::X86).expect("provider");
        assert_ne!(provider, 0);
        // An unsupported algorithm is STATUS_NOT_SUPPORTED.
        let bad_alg = runtime
            .alloc_utf16_string(&mut memory, "NOPE")
            .expect("bad alg");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open,
                &[provider_out as u32, bad_alg as u32, 0, 0],
            ),
            0xC000_00BB
        );

        // BCryptHash one-shot matches the SHA-256("abc") vector.
        let one_shot = runtime.alloc_host_thunk(HostThunk::BCryptHash);
        let input = 0x61_100;
        memory.map_bytes(input, b"abc");
        let digest = 0x61_200;
        memory.map_bytes(digest, &[0_u8; 32]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                one_shot,
                &[provider as u32, 0, 0, input as u32, 3, digest as u32, 32],
            ),
            0
        );
        assert_eq!(
            memory.read_bytes(digest, 32).expect("sha256"),
            [
                0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
                0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
                0xF2, 0x00, 0x15, 0xAD,
            ]
        );

        // BCryptCreateHash + BCryptHashData + BCryptDestroyHash lifecycle.
        let create_hash = runtime.alloc_host_thunk(HostThunk::BCryptCreateHash);
        let hash_data = runtime.alloc_host_thunk(HostThunk::BCryptHashData);
        let destroy_hash = runtime.alloc_host_thunk(HostThunk::BCryptDestroyHash);
        let hash_out = 0x61_300;
        memory.map_bytes(hash_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_hash,
                &[provider as u32, hash_out as u32, 0, 0, 0, 0, 0],
            ),
            0
        );
        let hash = read_guest_pointer(&memory, hash_out, GuestArch::X86).expect("hash");
        assert_ne!(hash, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                hash_data,
                &[hash as u32, input as u32, 3, 0],
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy_hash, &[hash as u32]),
            0
        );

        // BCryptGetProperty reports the AES block length; unknown names
        // on a live provider are tolerated.
        let get_property = runtime.alloc_host_thunk(HostThunk::BCryptGetProperty);
        let block_length = runtime
            .alloc_utf16_string(&mut memory, "BCRYPT_BLOCK_LENGTH")
            .expect("prop");
        let prop_out = 0x61_400;
        let prop_len = 0x61_500;
        memory.map_bytes(prop_out, &[0_u8; 8]);
        memory.map_bytes(prop_len, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_property,
                &[
                    provider as u32,
                    block_length as u32,
                    prop_out as u32,
                    4,
                    prop_len as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(read_u32(&memory, prop_out).expect("block length"), 16);
        assert_eq!(read_u32(&memory, prop_len).expect("result len"), 4);
        // BCryptSetProperty is accepted on a live provider.
        let set_property = runtime.alloc_host_thunk(HostThunk::BCryptSetProperty);
        let chaining = runtime
            .alloc_utf16_string(&mut memory, "BCRYPT_CHAINING_MODE")
            .expect("chaining");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_property,
                &[provider as u32, chaining as u32, prop_out as u32, 4, 0],
            ),
            0
        );

        // BCryptGenRandom fills the buffer from the secure RNG.
        let gen_random = runtime.alloc_host_thunk(HostThunk::BCryptGenRandom);
        let rng_a = 0x61_600;
        let rng_b = 0x61_700;
        memory.map_bytes(rng_a, &[0_u8; 32]);
        memory.map_bytes(rng_b, &[0_u8; 32]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, gen_random, &[rng_a as u32, 32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, gen_random, &[rng_b as u32, 32]),
            0
        );
        let a = memory.read_bytes(rng_a, 32).expect("rng a");
        let b = memory.read_bytes(rng_b, 32).expect("rng b");
        assert!(
            a.iter().any(|byte| *byte != 0),
            "RNG output must not be all zeros"
        );
        assert_ne!(a, b, "two draws must differ");

        // AES: BCryptGenerateSymmetricKey → BCryptEncrypt → BCryptDecrypt.
        let aes_alg = runtime
            .alloc_utf16_string(&mut memory, "AES")
            .expect("aes alg");
        let aes_provider_out = 0x61_800;
        memory.map_bytes(aes_provider_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open,
                &[aes_provider_out as u32, aes_alg as u32, 0, 0],
            ),
            0
        );
        let aes_provider =
            read_guest_pointer(&memory, aes_provider_out, GuestArch::X86).expect("aes provider");
        let generate_key = runtime.alloc_host_thunk(HostThunk::BCryptGenerateSymmetricKey);
        let key_bytes = 0x62_000;
        memory.map_bytes(key_bytes, &[0x11_u8; 16]);
        let key_out = 0x62_100;
        memory.map_bytes(key_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                generate_key,
                &[
                    key_out as u32,
                    aes_provider as u32,
                    0,
                    0,
                    key_bytes as u32,
                    16,
                    0
                ],
            ),
            0
        );
        let aes_key = read_guest_pointer(&memory, key_out, GuestArch::X86).expect("aes key");
        assert_ne!(aes_key, 0);

        let encrypt = runtime.alloc_host_thunk(HostThunk::BCryptEncrypt);
        let decrypt = runtime.alloc_host_thunk(HostThunk::BCryptDecrypt);
        let plaintext = 0x62_200;
        memory.map_bytes(plaintext, b"block-aligned-16");
        let iv = 0x62_300;
        memory.map_bytes(iv, &[0xAA_u8; 16]);
        let ciphertext = 0x62_400;
        memory.map_bytes(ciphertext, &[0_u8; 64]);
        let cipher_len = 0x62_500;
        memory.map_bytes(cipher_len, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                encrypt,
                &[
                    aes_key as u32,
                    plaintext as u32,
                    16,
                    0,
                    iv as u32,
                    16,
                    ciphertext as u32,
                    64,
                    cipher_len as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(read_u32(&memory, cipher_len).expect("cipher len"), 16);
        let recovered = 0x62_600;
        memory.map_bytes(recovered, &[0_u8; 64]);
        let recovered_len = 0x62_700;
        memory.map_bytes(recovered_len, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                decrypt,
                &[
                    aes_key as u32,
                    ciphertext as u32,
                    16,
                    0,
                    iv as u32,
                    16,
                    recovered as u32,
                    64,
                    recovered_len as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(
            memory.read_bytes(recovered, 16).expect("plaintext"),
            b"block-aligned-16"
        );

        // BCryptGetProperty on the key reports the 256-bit key length.
        let key_length = runtime
            .alloc_utf16_string(&mut memory, "BCRYPT_KEY_LENGTH")
            .expect("key length prop");
        memory.map_bytes(prop_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_property,
                &[
                    aes_key as u32,
                    key_length as u32,
                    prop_out as u32,
                    4,
                    prop_len as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(read_u32(&memory, prop_out).expect("key length"), 32);

        let destroy_key = runtime.alloc_host_thunk(HostThunk::BCryptDestroyKey);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy_key, &[aes_key as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[aes_provider as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[provider as u32]),
            0
        );
    })
}

#[test]
fn bcrypt_thunk_keypair_import_and_derive() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "bcrypt-keypair",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let open = runtime.alloc_host_thunk(HostThunk::BCryptOpenAlgorithmProvider);
        let close = runtime.alloc_host_thunk(HostThunk::BCryptCloseAlgorithmProvider);
        let rsa_alg = runtime
            .alloc_utf16_string(&mut memory, "RSA")
            .expect("rsa alg");
        let provider_out = 0x61_000;
        memory.map_bytes(provider_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open,
                &[provider_out as u32, rsa_alg as u32, 0, 0],
            ),
            0
        );
        let provider = read_guest_pointer(&memory, provider_out, GuestArch::X86).expect("provider");
        assert_ne!(provider, 0);

        // BCryptGenerateKeyPair returns a key handle; BCryptFinalizeKeyPair
        // accepts it; an unknown handle is STATUS_INVALID_HANDLE.
        let generate_pair = runtime.alloc_host_thunk(HostThunk::BCryptGenerateKeyPair);
        let finalize_pair = runtime.alloc_host_thunk(HostThunk::BCryptFinalizeKeyPair);
        let destroy_key = runtime.alloc_host_thunk(HostThunk::BCryptDestroyKey);
        let rsa_key = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            generate_pair,
            &[provider as u32, 2048, 0],
        );
        assert_ne!(rsa_key, 0);
        assert_ne!(rsa_key, 0xC000_00BB, "key generation must not fail");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                finalize_pair,
                &[rsa_key as u32, 0],
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, finalize_pair, &[0xDEAD, 0]),
            0xC000_0008
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy_key, &[rsa_key as u32]),
            0
        );

        // BCryptImportKey materializes a symmetric key from a raw blob
        // and the imported key can encrypt data.
        let aes_alg = runtime
            .alloc_utf16_string(&mut memory, "AES")
            .expect("aes alg");
        let aes_provider_out = 0x61_008;
        memory.map_bytes(aes_provider_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open,
                &[aes_provider_out as u32, aes_alg as u32, 0, 0],
            ),
            0
        );
        let aes_provider =
            read_guest_pointer(&memory, aes_provider_out, GuestArch::X86).expect("aes provider");
        let import_key = runtime.alloc_host_thunk(HostThunk::BCryptImportKey);
        let blob = 0x62_000;
        memory.map_bytes(blob, &[0x22_u8; 16]);
        let imported_out = 0x62_100;
        memory.map_bytes(imported_out, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                import_key,
                &[
                    aes_provider as u32,
                    0,
                    0,
                    imported_out as u32,
                    0,
                    0,
                    blob as u32,
                    16,
                    0,
                ],
            ),
            0
        );
        let imported =
            read_guest_pointer(&memory, imported_out, GuestArch::X86).expect("imported key");
        assert_ne!(imported, 0);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy_key, &[imported as u32]),
            0
        );

        // BCryptDeriveKey without a secret agreement is
        // STATUS_INVALID_HANDLE; a zero-length output is
        // STATUS_INVALID_PARAMETER.
        let derive_key = runtime.alloc_host_thunk(HostThunk::BCryptDeriveKey);
        let out = 0x62_200;
        memory.map_bytes(out, &[0_u8; 32]);
        let out_len = 0x62_300;
        memory.map_bytes(out_len, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                derive_key,
                &[0x1234, 0, 0, out as u32, 16, out_len as u32, 0],
            ),
            0xC000_0008
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                derive_key,
                &[0, 0, 0, out as u32, 0, out_len as u32, 0],
            ),
            0xC000_000D
        );

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[aes_provider as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[provider as u32]),
            0
        );
    })
}

#[test]
fn crypt32_thunk_store_lifecycle_pfx_and_enumeration() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "crypt32-thunks",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        // PFXIsPFXBlob recognises the PKCS#12 SEQUENCE header.
        let pfx_blob = 0x60_000;
        memory.map_bytes(pfx_blob, &[0_u8; 32]);
        let pfx_bytes = 0x60_100;
        memory.map_bytes(pfx_bytes, &[0x30, 0x82, 0x00, 0x10, 0x01, 0x02]);
        write_u32(&mut memory, pfx_blob, 6);
        memory.map_bytes(pfx_blob + 8, &pfx_bytes.to_le_bytes());
        let bad_blob = 0x60_200;
        memory.map_bytes(bad_blob, &[0_u8; 32]);
        let bad_bytes = 0x60_300;
        memory.map_bytes(bad_bytes, &[0xDE, 0xAD, 0xBE, 0xEF]);
        write_u32(&mut memory, bad_blob, 4);
        memory.map_bytes(bad_blob + 8, &bad_bytes.to_le_bytes());
        let pfx_is_blob = runtime.alloc_host_thunk(HostThunk::PFXIsPFXBlob);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, pfx_is_blob, &[pfx_blob as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, pfx_is_blob, &[bad_blob as u32]),
            0
        );

        // PFXImportCertStore imports the blob as a certificate store.
        let pfx_import = runtime.alloc_host_thunk(HostThunk::PFXImportCertStore);
        let pfx_store = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            pfx_import,
            &[pfx_blob as u32, 0, 0],
        );
        assert_ne!(pfx_store, 0);
        // A garbage blob is rejected with CRYPT_E_ASN1_BADTAG.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                pfx_import,
                &[bad_blob as u32, 0, 0],
            ),
            0
        );

        // CertEnumCertificatesInStore walks the imported certificate.
        let enum_certs = runtime.alloc_host_thunk(HostThunk::CertEnumCertificatesInStore);
        let first = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            enum_certs,
            &[pfx_store as u32, 0],
        );
        assert_ne!(first, 0);
        assert_eq!(read_u32(&memory, first).expect("CERT magic"), 0x4345_5254);
        // The enumeration is exhausted after the single entry.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_certs,
                &[pfx_store as u32, first as u32],
            ),
            0
        );

        // CertFindCertificateInStore finds the entry by empty subject.
        let find_cert = runtime.alloc_host_thunk(HostThunk::CertFindCertificateInStore);
        let empty_subject = 0x60_400;
        memory.map_bytes(empty_subject, &[0_u8; 4]); // UTF-16 ""
        let found = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            find_cert,
            &[pfx_store as u32, 0, 0, 1, empty_subject as u32, 0],
        );
        assert_ne!(found, 0);

        // CertDuplicateCertificateContext returns the same handle.
        let duplicate = runtime.alloc_host_thunk(HostThunk::CertDuplicateCertificateContext);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, duplicate, &[found as u32]),
            found
        );

        // CertOpenStore opens a named memory store.
        let open_store = runtime.alloc_host_thunk(HostThunk::CertOpenStore);
        let memory_store =
            dispatch_x86_thunk(&mut runtime, &mut memory, open_store, &[0, 0, 0, 0, 0]);
        assert_ne!(memory_store, 0);

        // CertAddCertificateContextToStore copies the found context in.
        let add_cert = runtime.alloc_host_thunk(HostThunk::CertAddCertificateContextToStore);
        let stored_ctx = 0x60_500;
        memory.map_bytes(stored_ctx, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                add_cert,
                &[memory_store as u32, found as u32, 0, stored_ctx as u32],
            ),
            1
        );
        assert_eq!(
            read_u32(&memory, stored_ctx).expect("stored context"),
            found as u32
        );
        // The added certificate is now enumerable in the second store.
        let added = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            enum_certs,
            &[memory_store as u32, 0],
        );
        assert_ne!(added, 0);

        // CertGetNameStringW writes an empty name (1 character written).
        let get_name = runtime.alloc_host_thunk(HostThunk::CertGetNameStringW);
        let name_out = 0x60_600;
        memory.map_bytes(name_out, &[0_u8; 32]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_name,
                &[added as u32, 0, 0, 0, name_out as u32, 16],
            ),
            1
        );
        assert_eq!(read_u16(&memory, name_out).expect("empty name"), 0);

        // CertGetIntendedKeyUsage writes zero usage bits and succeeds.
        let get_usage = runtime.alloc_host_thunk(HostThunk::CertGetIntendedKeyUsage);
        let usage = 0x60_700;
        memory.map_bytes(usage, &[0xFF_u8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_usage,
                &[0, added as u32, usage as u32, 1],
            ),
            1
        );
        assert_eq!(memory.read_u8(usage).expect("usage"), 0);

        // CertOpenSystemStoreW returns a handle carrying the CRTS magic.
        let open_system = runtime.alloc_host_thunk(HostThunk::CertOpenSystemStoreW);
        let root_name = runtime
            .alloc_utf16_string(&mut memory, "ROOT")
            .expect("root");
        let system_store = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_system,
            &[0, root_name as u32],
        );
        assert_ne!(system_store, 0);
        assert_eq!(
            read_u32(&memory, system_store).expect("CRTS magic"),
            0x4352_5453
        );

        // CertFindExtension returns NULL (not found).
        let find_extension = runtime.alloc_host_thunk(HostThunk::CertFindExtension);
        let oid = runtime
            .alloc_utf16_string(&mut memory, "1.2.3.4")
            .expect("oid");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                find_extension,
                &[oid as u32, 0, 0],
            ),
            0
        );

        // CertFreeCertificateChain is a void no-op (no exit propagation).
        let free_chain = runtime.alloc_host_thunk(HostThunk::CertFreeCertificateChain);
        assert_eq!(
            dispatch_x86_thunk_result(&mut runtime, &mut memory, free_chain, &[0]),
            None
        );

        // CertVerifyCertificateChainPolicy always accepts the chain.
        let verify_policy = runtime.alloc_host_thunk(HostThunk::CertVerifyCertificateChainPolicy);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, verify_policy, &[0, 0, 0, 0, 0],),
            1
        );

        // CryptAcquireCertificatePrivateKey reports AT_SIGNATURE with no
        // private key available (FALSE + NTE_NO_KEY).
        let acquire_key = runtime.alloc_host_thunk(HostThunk::CryptAcquireCertificatePrivateKey);
        let key_spec = 0x60_800;
        memory.map_bytes(key_spec, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                acquire_key,
                &[added as u32, 0, 0, key_spec as u32, 0, 0],
            ),
            0
        );
        assert_eq!(read_u32(&memory, key_spec).expect("key spec"), 2);

        // CertDeleteCertificateFromStore / CertFreeCertificateContext
        // release the tracked contexts.
        let delete_cert = runtime.alloc_host_thunk(HostThunk::CertDeleteCertificateFromStore);
        let free_context = runtime.alloc_host_thunk(HostThunk::CertFreeCertificateContext);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delete_cert, &[added as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, free_context, &[found as u32]),
            1
        );

        // CertCloseStore closes both stores.
        let close_store = runtime.alloc_host_thunk(HostThunk::CertCloseStore);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                close_store,
                &[memory_store as u32]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close_store, &[pfx_store as u32]),
            1
        );
    })
}

#[test]
fn evidence_core_event_and_semaphore_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-sync");
        let mut memory = MemoryImage::default();
        let create_event_a = runtime.alloc_host_thunk(HostThunk::CreateEventA);
        let open_event_a = runtime.alloc_host_thunk(HostThunk::OpenEventA);
        let open_event_w = runtime.alloc_host_thunk(HostThunk::OpenEventW);
        let reset_event = runtime.alloc_host_thunk(HostThunk::ResetEvent);
        let open_mutex_w = runtime.alloc_host_thunk(HostThunk::OpenMutexW);
        let open_semaphore_w = runtime.alloc_host_thunk(HostThunk::OpenSemaphoreW);
        let release_semaphore = runtime.alloc_host_thunk(HostThunk::ReleaseSemaphore);
        let wait = runtime.alloc_host_thunk(HostThunk::WaitForSingleObject);

        // CreateEventA mints a named auto-reset event (ANSI name).
        let name_a = runtime
            .alloc_c_string(&mut memory, "evidence_event_a")
            .expect("ansi name");
        let event = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_event_a,
            &[0, 0, 0, name_a as u32],
        );
        assert_ne!(event, 0);
        assert_eq!(runtime.last_error, 0);

        // OpenEventA and OpenEventW resolve the same named object.
        let name_w = runtime
            .alloc_utf16_string(&mut memory, "evidence_event_a")
            .expect("wide name");
        let opened_a = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_event_a,
            &[0x1F0003, 0, name_a as u32],
        );
        assert_ne!(opened_a, 0);
        let opened_w = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_event_w,
            &[0x1F0003, 0, name_w as u32],
        );
        assert_ne!(opened_w, 0);

        // ResetEvent clears the signal: a zero-timeout wait reports
        // WAIT_TIMEOUT (0x102).
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, reset_event, &[opened_w as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wait, &[opened_w as u32, 0]),
            0x102
        );
        // Signaling through the subsystem makes the wait complete.
        runtime.win32.set_event(opened_w as u32).expect("set event");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wait, &[opened_w as u32, 0]),
            0
        );

        // OpenMutexW resolves a named mutex; missing names fail with
        // ERROR_FILE_NOT_FOUND.
        runtime
            .win32
            .create_named_mutex("evidence_mutex", false, false);
        let mutex_w = runtime
            .alloc_utf16_string(&mut memory, "evidence_mutex")
            .expect("wide name");
        assert_ne!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_mutex_w,
                &[0x1F0001, 0, mutex_w as u32]
            ),
            0
        );
        let missing_w = runtime
            .alloc_utf16_string(&mut memory, "evidence_missing_mutex")
            .expect("wide name");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_mutex_w,
                &[0x1F0001, 0, missing_w as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_FILE_NOT_FOUND);

        // OpenSemaphoreW + ReleaseSemaphore on a named semaphore: the
        // release reports the previous count.
        runtime
            .win32
            .create_named_semaphore("evidence_sem", 0, 5, false);
        let sem_w = runtime
            .alloc_utf16_string(&mut memory, "evidence_sem")
            .expect("wide name");
        let sem = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_semaphore_w,
            &[0x1F0003, 0, sem_w as u32],
        );
        assert_ne!(sem, 0);
        let prev_ptr = 0x41_000;
        memory.map_bytes(prev_ptr as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                release_semaphore,
                &[sem as u32, 2, prev_ptr as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(prev_ptr as u64).unwrap(), 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_semaphore_w,
                &[0x1F0003, 0, missing_w as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_FILE_NOT_FOUND);
    })
}

#[test]
fn evidence_core_init_once_thunks_round_trip() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-init-once");
        let mut memory = MemoryImage::default();
        let begin = runtime.alloc_host_thunk(HostThunk::InitOnceBeginInitialize);
        let complete = runtime.alloc_host_thunk(HostThunk::InitOnceComplete);
        let execute = runtime.alloc_host_thunk(HostThunk::InitOnceExecuteOnce);

        // First BeginInitialize reports pending.
        let pending_ptr = 0x41_000;
        let context_ptr_ptr = 0x41_004;
        memory.map_bytes(pending_ptr as u64, &[0; 8]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                begin,
                &[0x1000, 0, pending_ptr as u32, context_ptr_ptr as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(pending_ptr as u64).unwrap(), 1);
        assert_eq!(runtime.last_error, 0);

        // Complete records the context.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, complete, &[0x1000, 0, 42]),
            1
        );
        // A second BeginInitialize reports completed with the stored context.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                begin,
                &[0x1000, 0, pending_ptr as u32, context_ptr_ptr as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(pending_ptr as u64).unwrap(), 0);
        assert_eq!(
            memory.read_u32(context_ptr_ptr as u64).unwrap(),
            42,
            "the stored context is written back"
        );

        // InitOnceExecuteOnce on a completed init-once writes the context.
        let ctx_out = 0x41_008;
        memory.map_bytes(ctx_out as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                execute,
                &[0x1000, 0, 0, ctx_out as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(ctx_out as u64).unwrap(), 42);
        // InitOnceExecuteOnce with a NULL callback on a fresh init-once
        // fails with ERROR_INVALID_PARAMETER.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                execute,
                &[0x2000, 0, 0, ctx_out as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

#[test]
fn get_queued_completion_status_timeout_consumes_no_packet() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("gqcs-timeout");
        let mut memory = MemoryImage::default();
        let create_port = runtime.alloc_host_thunk(HostThunk::CreateIoCompletionPort);
        let get_status = runtime.alloc_host_thunk(HostThunk::GetQueuedCompletionStatus);
        let port = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_port,
            &[u32::MAX, 0, 0x99, 1],
        );
        assert_ne!(port, 0);

        let bytes_ptr = 0x41_000_u64;
        let key_ptr = 0x41_004_u64;
        let overlapped_ptr = 0x41_008_u64;
        // Pre-fill with garbage: the timeout resume must zero them.
        memory.map_bytes(bytes_ptr, &[0xAAu8; 12]);

        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_status,
            &[
                port as u32,
                bytes_ptr as u32,
                key_ptr as u32,
                overlapped_ptr as u32,
                50,
            ],
        );
        assert_eq!(runtime.pending_guest_threads.len(), 1, "GQCS parked");
        resume_parked_completion_port_waiter(&mut runtime, &mut memory);

        // Advance the guest clock past the 50 ms deadline.
        runtime.win32.record_sleep_observation(1_000, 1_000);
        runtime
            .pump_pending_guest_thread(&mut memory)
            .expect("pump timed-out GQCS");
        assert!(runtime.pending_guest_threads.is_empty());

        assert_eq!(runtime.last_error, crate::win32::WAIT_TIMEOUT);
        assert_eq!(
            memory.read_u32(GQCS_FLAG_PTR).unwrap(),
            0,
            "GQCS returned FALSE"
        );
        assert_eq!(memory.read_u32(bytes_ptr).unwrap(), 0);
        assert_eq!(memory.read_u32(key_ptr).unwrap(), 0);
        assert_eq!(memory.read_u32(overlapped_ptr).unwrap(), 0);

        // The timed-out wait consumed nothing: a later post stays queued.
        runtime
            .win32
            .post_queued_completion_status(port as u32, 3, 0x1111, 0x2222)
            .expect("post after timeout");
        let port_state = runtime
            .win32
            .io_completion_port_state(port as u32)
            .expect("port state");
        assert_eq!(port_state.queued_packet_count(), 1, "packet not consumed");
    })
}

#[test]
fn get_queued_completion_status_closed_port_is_abandoned() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("gqcs-closed");
        let mut memory = MemoryImage::default();
        let create_port = runtime.alloc_host_thunk(HostThunk::CreateIoCompletionPort);
        let get_status = runtime.alloc_host_thunk(HostThunk::GetQueuedCompletionStatus);
        let port = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_port,
            &[u32::MAX, 0, 0xAA, 1],
        );
        assert_ne!(port, 0);

        let bytes_ptr = 0x41_000_u64;
        let key_ptr = 0x41_004_u64;
        let overlapped_ptr = 0x41_008_u64;
        memory.map_bytes(bytes_ptr, &[0u8; 12]);

        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_status,
            &[
                port as u32,
                bytes_ptr as u32,
                key_ptr as u32,
                overlapped_ptr as u32,
                u32::MAX,
            ],
        );
        assert_eq!(runtime.pending_guest_threads.len(), 1, "GQCS parked");
        resume_parked_completion_port_waiter(&mut runtime, &mut memory);
        runtime.win32.close_handle(port as u32).expect("close port");

        runtime
            .pump_pending_guest_thread(&mut memory)
            .expect("pump closed-port GQCS");
        assert!(runtime.pending_guest_threads.is_empty());
        assert_eq!(runtime.last_error, crate::win32::ERROR_ABANDONED_WAIT_0);
        assert_eq!(
            memory.read_u32(GQCS_FLAG_PTR).unwrap(),
            0,
            "GQCS returned FALSE"
        );
    })
}

#[test]
fn evidence_core_misc_kernel32_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-misc");
        let mut memory = MemoryImage::default();
        let get_version = runtime.alloc_host_thunk(HostThunk::GetVersion);
        let set_error_mode = runtime.alloc_host_thunk(HostThunk::SetErrorMode);
        let feature_present = runtime.alloc_host_thunk(HostThunk::IsProcessorFeaturePresent);
        let session_id = runtime.alloc_host_thunk(HostThunk::ProcessIdToSessionId);
        let encode = runtime.alloc_host_thunk(HostThunk::EncodePointer);
        let decode = runtime.alloc_host_thunk(HostThunk::DecodePointer);
        let mul_div = runtime.alloc_host_thunk(HostThunk::MulDiv);
        let exit_code_process = runtime.alloc_host_thunk(HostThunk::GetExitCodeProcess);
        let set_filter = runtime.alloc_host_thunk(HostThunk::SetUnhandledExceptionFilter);
        let filter = runtime.alloc_host_thunk(HostThunk::UnhandledExceptionFilter);
        let beep = runtime.alloc_host_thunk(HostThunk::Beep);

        // GetVersion packs the GE winver profile (NT bit + major version).
        let version = dispatch_x86_thunk(&mut runtime, &mut memory, get_version, &[]);
        assert_ne!(version & 0x8000_0000, 0, "NT bit is set");
        assert_eq!((version >> 8) & 0xFF, 10, "major version 10");

        // SetErrorMode returns the previous mode.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_error_mode, &[0x8000]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_error_mode, &[0x0001]),
            0x8000
        );

        // IsProcessorFeaturePresent: known features present, unknown absent.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, feature_present, &[2]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, feature_present, &[0]),
            0
        );

        // ProcessIdToSessionId resolves a live guest process to session 1.
        let process = runtime
            .win32
            .create_process_w("app.exe", "app.exe", &BTreeMap::new(), "C:\\", false)
            .expect("create process");
        let session_ptr = 0x41_000;
        memory.map_bytes(session_ptr as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                session_id,
                &[process.process_id, session_ptr as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(session_ptr as u64).unwrap(), 1);

        // EncodePointer/DecodePointer round-trip the pointer value.
        let encoded = dispatch_x86_thunk(&mut runtime, &mut memory, encode, &[0x1234_5678]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, decode, &[encoded as u32]),
            0x1234_5678
        );

        // MulDiv rounds half away from zero; zero denominator → -1.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mul_div, &[7, 3, 2]),
            11
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, mul_div, &[7, 3, 0]),
            u64::from(-1_i32 as u32)
        );

        // GetExitCodeProcess reports STILL_ACTIVE, then the real exit code.
        let code_ptr = 0x41_004;
        memory.map_bytes(code_ptr as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                exit_code_process,
                &[process.process_handle, code_ptr as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(code_ptr as u64).unwrap(), 259);
        runtime
            .win32
            .terminate_process(process.process_handle, 7)
            .expect("terminate process");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                exit_code_process,
                &[process.process_handle, code_ptr as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(code_ptr as u64).unwrap(), 7);

        // SetUnhandledExceptionFilter returns the previous filter; with no
        // filter installed UnhandledExceptionFilter reports 0 (EXCEPTION_
        // CONTINUE_SEARCH path with no handler).
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_filter, &[0x1234]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_filter, &[0x5678]),
            0x1234
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_filter, &[0]),
            0x5678
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, filter, &[0x41_100]),
            0
        );

        // Beep reports success under DTM (no host audio is played).
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, beep, &[440, 10]),
            1
        );

        // DebugBreak raises STATUS_BREAKPOINT; with no SEH handler the
        // dispatch surfaces the breakpoint as the run error.
        let debug_break = runtime.alloc_host_thunk(HostThunk::DebugBreak);
        let mut state = evidence_x86_state(&mut memory, &[]);
        let result = runtime.dispatch_import(debug_break, &mut state, &mut memory);
        assert!(
            result.is_err(),
            "an unhandled DebugBreak must fail the dispatch"
        );

        // WriteConsoleW writes the guest text and reports the written count.
        let console_w = runtime.alloc_host_thunk(HostThunk::WriteConsoleW);
        let console_text = 0x41_200;
        memory.map_bytes(console_text as u64, &evidence_utf16("console"));
        let written_ptr = 0x41_210;
        memory.map_bytes(written_ptr as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                console_w,
                &[
                    STD_OUTPUT_HANDLE,
                    console_text as u32,
                    7,
                    written_ptr as u32,
                    0
                ]
            ),
            1
        );
        assert_eq!(memory.read_u32(written_ptr as u64).unwrap(), 7);
    })
}

#[test]
fn evidence_core_kernel32_interlocked_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-interlocked");
        let mut memory = MemoryImage::default();
        let exchange = runtime.alloc_host_thunk(HostThunk::InterlockedExchange);
        let exchange_add = runtime.alloc_host_thunk(HostThunk::InterlockedExchangeAdd);
        let compare_exchange = runtime.alloc_host_thunk(HostThunk::InterlockedCompareExchange);
        let increment = runtime.alloc_host_thunk(HostThunk::InterlockedIncrement);
        let decrement = runtime.alloc_host_thunk(HostThunk::InterlockedDecrement);

        // The value lives in guest memory; each op returns the documented
        // previous/new value and leaves the guest word updated.
        let cell = 0x42_000;
        memory.map_bytes(cell, &10_u32.to_le_bytes());

        // InterlockedIncrement returns the NEW value.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, increment, &[cell as u32]),
            11
        );
        assert_eq!(memory.read_u32(cell).unwrap(), 11);

        // InterlockedDecrement returns the NEW value.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, decrement, &[cell as u32]),
            10
        );
        assert_eq!(memory.read_u32(cell).unwrap(), 10);

        // InterlockedExchange stores and returns the PREVIOUS value.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                exchange,
                &[cell as u32, 0x1234_5678]
            ),
            10
        );
        assert_eq!(memory.read_u32(cell).unwrap(), 0x1234_5678);

        // InterlockedExchangeAdd adds and returns the PREVIOUS value.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, exchange_add, &[cell as u32, 5]),
            0x1234_5678
        );
        assert_eq!(memory.read_u32(cell).unwrap(), 0x1234_567D);

        // InterlockedCompareExchange stores when equal, returns previous.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                compare_exchange,
                &[cell as u32, 99, 0x1234_567D]
            ),
            0x1234_567D
        );
        assert_eq!(memory.read_u32(cell).unwrap(), 99);

        // A mismatched comparand leaves the guest word untouched.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                compare_exchange,
                &[cell as u32, 77, 0x1234_567D]
            ),
            99
        );
        assert_eq!(memory.read_u32(cell).unwrap(), 99);
    })
}

#[test]
fn evidence_core_kernel32_environment_expand_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-env-expand");
        let mut memory = MemoryImage::default();
        let expand = runtime.alloc_host_thunk(HostThunk::ExpandEnvironmentStringsW);

        // Seed the guest process environment (the same table
        // SetEnvironmentVariableW maintains).
        runtime
            .process_environment
            .insert("Casa1Dir".to_string(), r"C:\demo".to_string());
        runtime
            .process_environment
            .insert("PATH".to_string(), r"C:\Windows".to_string());

        let source = runtime
            .alloc_utf16_string(&mut memory, r"run from %Casa1Dir%\bin; %UNSET% stays")
            .expect("wide source");
        let buffer = 0x42_100;
        memory.map_bytes(buffer, &[0_u8; 0x100]);

        // Undefined variables pass through literally; defined ones expand.
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            expand,
            &[source as u32, buffer as u32, 0x100],
        );
        let expanded = read_guest_utf16_string(&memory, buffer, 128);
        assert_eq!(expanded, r"run from C:\demo\bin; %UNSET% stays");
        assert_eq!(written, expanded.encode_utf16().count() as u64);

        // Required-size semantics: a too-small buffer returns the size
        // INCLUDING the NUL with ERROR_INSUFFICIENT_BUFFER.
        memory.map_bytes(buffer, &[0_u8; 0x100]);
        let required = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            expand,
            &[source as u32, buffer as u32, 4],
        );
        assert_eq!(required, expanded.encode_utf16().count() as u64 + 1);
        assert_eq!(runtime.last_error, ERROR_INSUFFICIENT_BUFFER);

        // The (NULL, 0) query returns the required size without an error.
        let required =
            dispatch_x86_thunk(&mut runtime, &mut memory, expand, &[source as u32, 0, 0]);
        assert_eq!(required, expanded.encode_utf16().count() as u64 + 1);
        assert_eq!(runtime.last_error, 0);

        // An empty expansion still writes the NUL and returns 0.
        let empty = runtime
            .alloc_utf16_string(&mut memory, "plain text")
            .expect("wide empty");
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            expand,
            &[empty as u32, buffer as u32, 0x100],
        );
        assert_eq!(written, 10);
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn evidence_core_nt_rtl_and_io_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-nt-rtl");
        let mut memory = MemoryImage::default();
        let io_control = runtime.alloc_host_thunk(HostThunk::NtDeviceIoControlFile);
        let capture_context = runtime.alloc_host_thunk(HostThunk::RtlCaptureContext);
        let lookup_entry = runtime.alloc_host_thunk(HostThunk::RtlLookupFunctionEntry);
        let raise_exception = runtime.alloc_host_thunk(HostThunk::RtlRaiseException);
        let init_ansi = runtime.alloc_host_thunk(HostThunk::RtlInitAnsiString);
        let free_ansi = runtime.alloc_host_thunk(HostThunk::RtlFreeAnsiString);
        let free_unicode = runtime.alloc_host_thunk(HostThunk::RtlFreeUnicodeString);
        let alloc_heap = runtime.alloc_host_thunk(HostThunk::RtlAllocateHeap);
        let free_heap = runtime.alloc_host_thunk(HostThunk::RtlFreeHeap);
        let size_heap = runtime.alloc_host_thunk(HostThunk::RtlSizeHeap);

        // NtDeviceIoControlFile with an unknown code fails closed: the
        // IO_STATUS_BLOCK carries the mapped NTSTATUS and the call reports
        // the same status (ERROR_INVALID_FUNCTION → STATUS_UNSUCCESSFUL).
        let file = runtime
            .win32
            .create_file_w(
                "C:\\evidence-ioctl.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        let iosb = 0x41_000;
        memory.map_bytes(iosb as u64, &[0; 8]);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            io_control,
            &[file, 0, 0, 0, iosb as u32, 0xDEAD_0000, 0, 0, 0, 0],
        );
        assert_eq!(status, 0xC000_0001, "STATUS_UNSUCCESSFUL");
        assert_eq!(memory.read_u32(iosb as u64).unwrap(), 0xC000_0001);

        // RtlCaptureContext snapshots the current register state.
        let ctx = 0x41_100;
        let mut ctx_bytes = vec![0_u8; 0x300];
        ctx_bytes[0..4].copy_from_slice(&0x10007_u32.to_le_bytes());
        memory.map_bytes(ctx as u64, &ctx_bytes);
        let mut state = evidence_x86_state(&mut memory, &[ctx as u32]);
        state.gpr[0] = 0xAABB_CCDD;
        runtime
            .dispatch_import(capture_context, &mut state, &mut memory)
            .expect("rtl capture context");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            memory
                .read_u32(ctx as u64 + crate::ntdll::thread::X86_CONTEXT_EAX_OFFSET)
                .unwrap(),
            0xAABB_CCDD
        );

        // RtlLookupFunctionEntry is x64-only: on the x86 guest it reports
        // NULL.
        let image_base_ptr = 0x41_200;
        memory.map_bytes(image_base_ptr as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lookup_entry,
                &[0x40_000, image_base_ptr as u32, 0]
            ),
            0
        );

        // RtlRaiseException with an unhandled record ends the process with
        // the exception code (STATUS_ACCESS_VIOLATION).
        let record = 0x41_300;
        let mut record_bytes = vec![0_u8; 0x40];
        record_bytes[0..4].copy_from_slice(&0xC000_0005_u32.to_le_bytes());
        memory.map_bytes(record as u64, &record_bytes);
        let mut state = evidence_x86_state(&mut memory, &[record as u32]);
        let result = runtime
            .dispatch_import(raise_exception, &mut state, &mut memory)
            .expect("rtl raise exception");
        assert_eq!(result, Some(0xC000_0005_u32 as i32));
        assert_eq!(runtime.process_exit_requested, Some(0xC000_0005));

        // RtlInitAnsiString writes the x86 ANSI_STRING header (Length,
        // MaximumLength, Buffer).
        let ansi_src = 0x41_400;
        memory.map_bytes(ansi_src as u64, b"abc\0");
        let ansi_header = 0x41_500;
        memory.map_bytes(ansi_header as u64, &[0xFF; 8]);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            init_ansi,
            &[ansi_header as u32, ansi_src as u32],
        );
        assert_eq!(memory.read_u16(ansi_header as u64).unwrap(), 3);
        assert_eq!(memory.read_u16(ansi_header as u64 + 2).unwrap(), 4);
        assert_eq!(
            memory.read_u32(ansi_header as u64 + 4).unwrap(),
            ansi_src as u32
        );

        // RtlFreeAnsiString / RtlFreeUnicodeString zero the header.
        dispatch_x86_thunk(&mut runtime, &mut memory, free_ansi, &[ansi_header as u32]);
        assert_eq!(memory.read_u16(ansi_header as u64).unwrap(), 0);
        assert_eq!(memory.read_u16(ansi_header as u64 + 2).unwrap(), 0);
        let unicode_src = runtime
            .alloc_utf16_string(&mut memory, "xyz")
            .expect("wide src");
        let unicode_header = 0x41_600;
        memory.map_bytes(unicode_header as u64, &[0; 16]);
        let init_unicode = runtime.alloc_host_thunk(HostThunk::RtlInitUnicodeString);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            init_unicode,
            &[unicode_header as u32, unicode_src as u32],
        );
        assert_eq!(memory.read_u16(unicode_header as u64).unwrap(), 6);
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            free_unicode,
            &[unicode_header as u32],
        );
        assert_eq!(memory.read_u16(unicode_header as u64).unwrap(), 0);
        assert_eq!(memory.read_u16(unicode_header as u64 + 2).unwrap(), 0);

        // RtlAllocateHeap with HEAP_ZERO_MEMORY zeroes the block;
        // RtlSizeHeap reports the size; RtlFreeHeap invalidates it.
        let block = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            alloc_heap,
            &[PROCESS_HEAP_HANDLE as u32, HEAP_ZERO_MEMORY, 64],
        );
        assert_ne!(block, 0);
        assert_eq!(
            memory.read_bytes(block, 64).unwrap(),
            [0_u8; 64],
            "HEAP_ZERO_MEMORY zeroes the allocation"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                size_heap,
                &[PROCESS_HEAP_HANDLE as u32, 0, block as u32]
            ),
            64
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                free_heap,
                &[PROCESS_HEAP_HANDLE as u32, 0, block as u32]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                size_heap,
                &[PROCESS_HEAP_HANDLE as u32, 0, block as u32]
            ),
            u32::MAX as u64,
            "a freed block reports SIZE_MAX"
        );
        // A non-process heap handle is refused.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, alloc_heap, &[0x7777, 0, 64]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

// ── evidence-mid: advapi32 service control manager ────────────────────
#[test]
fn evidence_mid_advapi32_scm_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-scm");
        let mut memory = MemoryImage::default();

        // OpenSCManagerW returns a manager handle.
        let open_manager = runtime.alloc_host_thunk(HostThunk::OpenSCManagerW);
        let manager = dispatch_x86_thunk(&mut runtime, &mut memory, open_manager, &[0, 0, 0x10006]);
        assert_ne!(manager, 0);

        // CreateServiceW writes the service into the guest registry.
        let service_name = runtime
            .alloc_utf16_string(&mut memory, "DemoSvc")
            .expect("name");
        let display_name = runtime
            .alloc_utf16_string(&mut memory, "Demo Service")
            .expect("display");
        let image_path = runtime
            .alloc_utf16_string(&mut memory, "C:\\bin\\demo.exe")
            .expect("path");
        let create = runtime.alloc_host_thunk(HostThunk::CreateServiceW);
        let service_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create,
            &[
                manager as u32,
                service_name as u32,
                display_name as u32,
                0xF01FF,
                crate::advapi32::SERVICE_WIN32_OWN_PROCESS,
                crate::advapi32::SERVICE_AUTO_START,
                crate::advapi32::SERVICE_ERROR_NORMAL,
                image_path as u32,
                0,
                0,
                0,
                0,
                0,
            ],
        );
        assert_ne!(service_handle, 0);
        let ge = runtime.win32.ge();
        let image_path_stored = ge
            .registry_get_value(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\DemoSvc",
                "ImagePath",
                crate::ge::RegistryView::Native,
            )
            .expect("registry read")
            .expect("image path value");
        assert_eq!(image_path_stored.data.as_str(), Some("C:\\bin\\demo.exe"));

        // A duplicate CreateServiceW reports ERROR_SERVICE_EXISTS.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create,
                &[
                    manager as u32,
                    service_name as u32,
                    display_name as u32,
                    0xF01FF,
                    crate::advapi32::SERVICE_WIN32_OWN_PROCESS,
                    crate::advapi32::SERVICE_AUTO_START,
                    crate::advapi32::SERVICE_ERROR_NORMAL,
                    image_path as u32,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            ),
            0
        );
        assert_eq!(runtime.last_error, crate::advapi32::ERROR_SERVICE_EXISTS);

        // QueryServiceStatus: STOPPED before start.
        let status_ptr = 0x62_000;
        memory.map_bytes(status_ptr, &[0; 28]);
        let query_status = runtime.alloc_host_thunk(HostThunk::QueryServiceStatus);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query_status,
                &[service_handle as u32, status_ptr as u32]
            ),
            1
        );
        assert_eq!(
            read_u32(&memory, status_ptr + 4).expect("state"),
            crate::advapi32::SERVICE_STOPPED
        );
        assert_eq!(
            read_u32(&memory, status_ptr + 8).expect("controls"),
            crate::advapi32::SERVICE_ACCEPT_DEFAULT
        );

        // StartServiceW: the status flow START_PENDING → RUNNING.
        let start = runtime.alloc_host_thunk(HostThunk::StartServiceW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                start,
                &[service_handle as u32, 0, 0]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query_status,
                &[service_handle as u32, status_ptr as u32]
            ),
            1
        );
        assert_eq!(
            read_u32(&memory, status_ptr + 4).expect("state"),
            crate::advapi32::SERVICE_RUNNING
        );
        // Starting an already-running service reports ERROR_SERVICE_ALREADY_RUNNING.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                start,
                &[service_handle as u32, 0, 0]
            ),
            0
        );
        assert_eq!(
            runtime.last_error,
            crate::advapi32::ERROR_SERVICE_ALREADY_RUNNING
        );

        // ControlService(STOP): RUNNING → STOP_PENDING → STOPPED.
        let control = runtime.alloc_host_thunk(HostThunk::ControlService);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                control,
                &[
                    service_handle as u32,
                    crate::advapi32::SERVICE_CONTROL_STOP,
                    status_ptr as u32
                ]
            ),
            1
        );
        assert_eq!(
            read_u32(&memory, status_ptr + 4).expect("state"),
            crate::advapi32::SERVICE_STOPPED
        );
        // Stopping a stopped service reports ERROR_SERVICE_NOT_ACTIVE.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                control,
                &[
                    service_handle as u32,
                    crate::advapi32::SERVICE_CONTROL_STOP,
                    status_ptr as u32
                ]
            ),
            0
        );
        assert_eq!(
            runtime.last_error,
            crate::advapi32::ERROR_SERVICE_NOT_ACTIVE
        );

        // OpenServiceW: an unknown service reports
        // ERROR_SERVICE_DOES_NOT_EXIST.
        let open_service = runtime.alloc_host_thunk(HostThunk::OpenServiceW);
        let missing_name = runtime
            .alloc_utf16_string(&mut memory, "NoSuchSvc")
            .expect("name");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_service,
                &[manager as u32, missing_name as u32, 0x10001]
            ),
            0
        );
        assert_eq!(
            runtime.last_error,
            crate::advapi32::ERROR_SERVICE_DOES_NOT_EXIST
        );
        // The created service opens.
        let opened = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_service,
            &[manager as u32, service_name as u32, 0x10001],
        );
        assert_ne!(opened, 0);

        // DeleteService removes the registry database entry.
        let delete = runtime.alloc_host_thunk(HostThunk::DeleteService);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delete, &[service_handle as u32]),
            1
        );
        assert!(
            !crate::advapi32::service_exists(
                runtime.win32.ge(),
                "DemoSvc",
                crate::advapi32::scm_registry_view(),
            ),
            "the service database entry is gone after DeleteService"
        );

        // CloseServiceHandle closes both handle kinds.
        let close = runtime.alloc_host_thunk(HostThunk::CloseServiceHandle);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[opened as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[manager as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[manager as u32]),
            0,
            "closing a closed handle fails"
        );
    })
}

// ── evidence-mid: advapi32 CryptoAPI ───────────────────────────────────
#[test]
fn evidence_mid_advapi32_crypto_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-crypto");
        let mut memory = MemoryImage::default();

        // CryptAcquireContextW with a container name.
        let prov_out = 0x63_000;
        memory.map_bytes(prov_out, &[0; 4]);
        let container_ptr = runtime
            .alloc_utf16_string(&mut memory, "GameKeys")
            .expect("container");
        let acquire = runtime.alloc_host_thunk(HostThunk::CryptAcquireContextW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                acquire,
                &[prov_out as u32, container_ptr as u32, 0, 1, 0]
            ),
            1
        );
        let prov = read_u32(&memory, prov_out).expect("prov handle");
        assert_eq!(
            runtime
                .crypt_providers
                .get(&u64::from(prov))
                .map(|p| p.container.as_str()),
            Some("GameKeys")
        );

        // CryptCreateHash(CALG_MD5) + CryptHashData + CryptGetHashParam:
        // the RFC 1321 "abc" digest proves the shared hash machinery.
        let hash_out = 0x63_100;
        memory.map_bytes(hash_out, &[0; 4]);
        let create_hash = runtime.alloc_host_thunk(HostThunk::CryptCreateHash);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_hash,
                &[prov, crate::advapi32::CALG_MD5, 0, 0, hash_out as u32]
            ),
            1
        );
        let hash = read_u32(&memory, hash_out).expect("hash handle");
        let data_ptr = runtime.alloc_heap(&mut memory, 3, true).expect("data heap");
        memory.map_bytes(data_ptr, b"abc");
        let hash_data = runtime.alloc_host_thunk(HostThunk::CryptHashData);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                hash_data,
                &[hash, data_ptr as u32, 3, 0]
            ),
            1
        );
        let digest_out = 0x63_200;
        memory.map_bytes(digest_out, &[0; 32]);
        let digest_len = 0x63_300;
        memory.map_bytes(digest_len, &32_u32.to_le_bytes());
        let get_param = runtime.alloc_host_thunk(HostThunk::CryptGetHashParam);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_param,
                &[hash, 2, digest_out as u32, digest_len as u32, 0]
            ),
            1
        );
        assert_eq!(
            memory.read_bytes(digest_out, 16).expect("md5 digest"),
            crate::crypto::md5(b"abc").to_vec()
        );
        // HP_HASHSIZE reports the digest size; a small buffer reports
        // ERROR_MORE_DATA with the required size.
        let size_out = 0x63_400;
        memory.map_bytes(size_out, &[0; 4]);
        memory.map_bytes(digest_len, &4_u32.to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_param,
                &[hash, 4, size_out as u32, digest_len as u32, 0]
            ),
            1
        );
        assert_eq!(read_u32(&memory, size_out).expect("hash size"), 16);
        memory.map_bytes(digest_len, &4_u32.to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_param,
                &[hash, 2, digest_out as u32, digest_len as u32, 0]
            ),
            0
        );
        assert_eq!(runtime.last_error, crate::advapi32::ERROR_MORE_DATA);
        assert_eq!(read_u32(&memory, digest_len).expect("required"), 16);

        // CryptDeriveKey(CALG_RC4) from the hash + CryptEncrypt/
        // CryptDecrypt round trip in the guest buffer.
        let key_out = 0x63_500;
        memory.map_bytes(key_out, &[0; 4]);
        let derive_key = runtime.alloc_host_thunk(HostThunk::CryptDeriveKey);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                derive_key,
                &[prov, crate::advapi32::CALG_RC4, hash, 0, key_out as u32]
            ),
            1
        );
        let key = read_u32(&memory, key_out).expect("key handle");
        let plain = b"secret message";
        let buffer = runtime
            .alloc_heap(&mut memory, 64, true)
            .expect("crypto heap");
        memory.map_bytes(buffer, plain);
        let data_len = 0x63_600;
        memory.map_bytes(data_len, &(plain.len() as u32).to_le_bytes());
        let encrypt = runtime.alloc_host_thunk(HostThunk::CryptEncrypt);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                encrypt,
                &[key, 0, 1, 0, buffer as u32, data_len as u32, 64]
            ),
            1
        );
        let cipher_len = read_u32(&memory, data_len).expect("cipher len");
        assert_eq!(cipher_len as usize, plain.len());
        let ciphertext = memory
            .read_bytes(buffer, cipher_len as usize)
            .expect("cipher");
        assert_ne!(ciphertext, plain.to_vec());
        let decrypt = runtime.alloc_host_thunk(HostThunk::CryptDecrypt);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                decrypt,
                &[key, 0, 1, 0, buffer as u32, data_len as u32]
            ),
            1
        );
        let round_trip = memory
            .read_bytes(buffer, cipher_len as usize)
            .expect("plain");
        assert_eq!(round_trip, plain.to_vec());

        // CALG_RC2: block cipher with PKCS#7 padding (9 bytes → 16).
        // The key object owns the CBC chaining state, so decryption
        // runs on a freshly derived key (the documented usage pattern).
        let rc2_key_out = 0x63_700;
        memory.map_bytes(rc2_key_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                derive_key,
                &[prov, crate::advapi32::CALG_RC2, hash, 0, rc2_key_out as u32]
            ),
            1
        );
        let rc2_key = read_u32(&memory, rc2_key_out).expect("rc2 key handle");
        let rc2_plain = b"rc2 secret"; // 9 bytes
        memory.map_bytes(buffer, rc2_plain);
        memory.map_bytes(data_len, &(rc2_plain.len() as u32).to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                encrypt,
                &[rc2_key, 0, 1, 0, buffer as u32, data_len as u32, 64]
            ),
            1
        );
        let padded_len = read_u32(&memory, data_len).expect("padded len");
        assert_eq!(padded_len, 16, "RC2 pads to the 8-byte block size");
        let ciphertext = memory
            .read_bytes(buffer, padded_len as usize)
            .expect("rc2 cipher");
        let rc2_dec_key_out = 0x63_708;
        memory.map_bytes(rc2_dec_key_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                derive_key,
                &[
                    prov,
                    crate::advapi32::CALG_RC2,
                    hash,
                    0,
                    rc2_dec_key_out as u32
                ]
            ),
            1
        );
        let rc2_dec_key = read_u32(&memory, rc2_dec_key_out).expect("rc2 dec key handle");
        memory.map_bytes(buffer, &ciphertext);
        memory.map_bytes(data_len, &(ciphertext.len() as u32).to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                decrypt,
                &[rc2_dec_key, 0, 1, 0, buffer as u32, data_len as u32]
            ),
            1
        );
        assert_eq!(
            memory
                .read_bytes(buffer, rc2_plain.len())
                .expect("rc2 plain"),
            rc2_plain.to_vec()
        );

        // CALG_3DES round trip through the FIPS EDE machinery.
        let tdes_key_out = 0x63_710;
        memory.map_bytes(tdes_key_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                derive_key,
                &[
                    prov,
                    crate::advapi32::CALG_3DES,
                    hash,
                    0,
                    tdes_key_out as u32
                ]
            ),
            1
        );
        let tdes_key = read_u32(&memory, tdes_key_out).expect("tdes key handle");
        memory.map_bytes(buffer, rc2_plain);
        memory.map_bytes(data_len, &(rc2_plain.len() as u32).to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                encrypt,
                &[tdes_key, 0, 1, 0, buffer as u32, data_len as u32, 64]
            ),
            1
        );
        let tdes_len = read_u32(&memory, data_len).expect("tdes len");
        assert_eq!(tdes_len, 16);
        let tdes_cipher = memory
            .read_bytes(buffer, tdes_len as usize)
            .expect("tdes cipher");
        let tdes_dec_key_out = 0x63_718;
        memory.map_bytes(tdes_dec_key_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                derive_key,
                &[
                    prov,
                    crate::advapi32::CALG_3DES,
                    hash,
                    0,
                    tdes_dec_key_out as u32
                ]
            ),
            1
        );
        let tdes_dec_key = read_u32(&memory, tdes_dec_key_out).expect("tdes dec key handle");
        memory.map_bytes(buffer, &tdes_cipher);
        memory.map_bytes(data_len, &(tdes_cipher.len() as u32).to_le_bytes());
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                decrypt,
                &[tdes_dec_key, 0, 1, 0, buffer as u32, data_len as u32]
            ),
            1
        );
        assert_eq!(
            memory
                .read_bytes(buffer, rc2_plain.len())
                .expect("tdes plain"),
            rc2_plain.to_vec()
        );

        // CryptGenRandom: two draws of the same length differ.
        let rng_a = 0x63_800;
        let rng_b = 0x63_900;
        memory.map_bytes(rng_a, &[0; 32]);
        memory.map_bytes(rng_b, &[0; 32]);
        let gen_random = runtime.alloc_host_thunk(HostThunk::CryptGenRandom);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                gen_random,
                &[prov, 32, rng_a as u32]
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                gen_random,
                &[prov, 32, rng_b as u32]
            ),
            1
        );
        assert_ne!(
            memory.read_bytes(rng_a, 32).expect("random a"),
            memory.read_bytes(rng_b, 32).expect("random b")
        );

        // An unsupported algorithm reports NTE_BAD_ALGID.
        let bad_hash_out = 0x63_A00;
        memory.map_bytes(bad_hash_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_hash,
                &[prov, 0x1111, 0, 0, bad_hash_out as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, crate::advapi32::NTE_BAD_ALGID);

        // Destroy hash/key and release the provider.
        let destroy_hash = runtime.alloc_host_thunk(HostThunk::CryptDestroyHash);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy_hash, &[hash]),
            1
        );
        let destroy_key = runtime.alloc_host_thunk(HostThunk::CryptDestroyKey);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, destroy_key, &[key]),
            1
        );
        let release = runtime.alloc_host_thunk(HostThunk::CryptReleaseContext);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release, &[prov, 0]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release, &[prov, 0]),
            0,
            "releasing an unknown provider fails"
        );
    })
}

#[test]
fn duplicate_handle_aliases_tagged_usb_handles_until_last_close() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("duplicate-usb");
        let duplicate = runtime.alloc_host_thunk(HostThunk::DuplicateHandle);
        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        let source = crate::real_hid::dispatch::register_usb(
            crate::real_hid::StableDeviceId::from_raw(0xCA5A_0003),
            "usb-dup".to_string(),
        ) as u32;
        let out = 0x40_000_u64;
        let mut memory = MemoryImage::default();
        memory.map_bytes(out, &[0_u8; 8]);
        let process = runtime.win32.current_process_handle();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                duplicate,
                &[process, source, process, out as u32, 0, 0, 0],
            ),
            1
        );
        let alias =
            read_guest_pointer(&memory, out, GuestArch::X86).expect("duplicate handle") as u32;
        assert_ne!(alias, source);
        assert!(crate::real_hid::dispatch::is_usb(u64::from(alias)));
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[alias]),
            1
        );
        assert!(
            crate::real_hid::dispatch::is_usb(u64::from(source)),
            "closing the alias keeps the original device"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[source]),
            1
        );
        assert!(!crate::real_hid::dispatch::is_usb(u64::from(source)));
    });
}

#[test]
fn nt_usb_ioctls_route_to_the_host_bridge_with_exact_statuses() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("nt-usb-ioctl");
        let thunk = runtime.alloc_host_thunk(HostThunk::NtDeviceIoControlFile);
        let handle = crate::real_hid::dispatch::register_usb(
            crate::real_hid::StableDeviceId::from_raw(0xCA5A_0001),
            "test-usb".to_string(),
        ) as u32;
        let mut memory = MemoryImage::default();
        let iosb = 0x40_000_u64;
        let out = 0x41_000_u64;
        memory.map_bytes(iosb, &[0_u8; 24]);
        memory.map_bytes(out, &[0_u8; 32]);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    handle,
                    0,
                    0,
                    0,
                    iosb as u32,
                    IOCTL_USB_ENUMERATE_DEVICES,
                    0,
                    0,
                    out as u32,
                    32,
                ],
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(memory.read_u32(iosb + 4).expect("information"), 0);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    handle,
                    0,
                    0,
                    0,
                    iosb as u32,
                    0x00FF_FFFF,
                    0,
                    0,
                    out as u32,
                    32
                ],
            ),
            u64::from(crate::ntdll::STATUS_NOT_SUPPORTED.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    handle,
                    0,
                    0,
                    0,
                    iosb as u32,
                    IOCTL_USB_VALIDATE_TRANSFER,
                    0,
                    0,
                    out as u32,
                    32,
                ],
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
    });
}

#[test]
fn tbs_tpm_dispatch_rejects_bad_contracts_and_runs_startup_exactly() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("tbs-tpm");
        let context_create = runtime.alloc_host_thunk(HostThunk::TbsiContextCreate);
        let submit = runtime.alloc_host_thunk(HostThunk::TbsipSubmitCommand);
        let close = runtime.alloc_host_thunk(HostThunk::TbsipContextClose);
        let mut memory = MemoryImage::default();
        let params = 0x40_000_u64;
        let out = 0x40_100_u64;
        let response = 0x41_000_u64;
        let response_len = 0x42_000_u64;
        memory.map_bytes(params, &[0_u8; 8]);
        memory.map_bytes(out, &[0_u8; 8]);
        memory.map_bytes(response, &[0_u8; 64]);
        memory.map_bytes(response_len, &[0_u8; 4]);
        memory.write_u32(params, 1);

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, context_create, &[0, out as u32]),
            u64::from(crate::tpm::tbs::TBS_E_BAD_PARAMETER)
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, context_create, &[0, 0]),
            u64::from(crate::tpm::tbs::TBS_E_INVALID_OUTPUT_POINTER)
        );
        memory.write_u32(params, 9);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                context_create,
                &[params as u32, out as u32]
            ),
            u64::from(crate::tpm::tbs::TBS_E_INVALID_CONTEXT_PARAM)
        );
        memory.write_u32(params, 1);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                context_create,
                &[params as u32, out as u32]
            ),
            0
        );
        let context = read_guest_pointer(&memory, out, GuestArch::X86).expect("context");

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[0xDEAD]),
            u64::from(crate::tpm::tbs::TBS_E_INVALID_CONTEXT)
        );

        // TPM2_Startup(CLEAR): tag 0x8001, size 12, command 0x144.
        let command = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let command_ptr = 0x43_000_u64;
        memory.map_bytes(command_ptr, &command);
        memory.write_u32(response_len, 64);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                submit,
                &[
                    context as u32,
                    0,
                    100,
                    command_ptr as u32,
                    command.len() as u32,
                    response as u32,
                    response_len as u32,
                ]
            ),
            0
        );
        assert_eq!(memory.read_u32(response_len).expect("length"), 10);
        let tag = u16::from_be_bytes(
            memory
                .read_bytes(response, 2)
                .expect("tag")
                .try_into()
                .expect("tag bytes"),
        );
        let size = u32::from_be_bytes(
            memory
                .read_bytes(response + 2, 4)
                .expect("size")
                .try_into()
                .expect("size bytes"),
        );
        let rc = u32::from_be_bytes(
            memory
                .read_bytes(response + 6, 4)
                .expect("rc")
                .try_into()
                .expect("rc bytes"),
        );
        assert_eq!(tag, 0x8001);
        assert_eq!(size, 10);
        assert_eq!(rc, 0);

        // A smaller caller buffer reports the required size and no bytes.
        memory.write_u32(response_len, 4);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                submit,
                &[
                    context as u32,
                    0,
                    100,
                    command_ptr as u32,
                    command.len() as u32,
                    response as u32,
                    response_len as u32,
                ]
            ),
            u64::from(crate::tpm::tbs::TBS_E_INSUFFICIENT_BUFFER)
        );
        assert_eq!(memory.read_u32(response_len).expect("required"), 10);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                submit,
                &[
                    context as u32,
                    0,
                    999,
                    command_ptr as u32,
                    12,
                    response as u32,
                    response_len as u32
                ]
            ),
            u64::from(crate::tpm::tbs::TBS_E_BAD_PARAMETER)
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                submit,
                &[
                    context as u32,
                    0,
                    100,
                    command_ptr as u32,
                    70_000,
                    response as u32,
                    response_len as u32
                ]
            ),
            u64::from(crate::tpm::tbs::TBS_E_BUFFER_TOO_LARGE)
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                submit,
                &[
                    context as u32,
                    0,
                    100,
                    0,
                    4,
                    response as u32,
                    response_len as u32
                ]
            ),
            u64::from(crate::tpm::tbs::TBS_E_BAD_PARAMETER)
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                submit,
                &[
                    context as u32,
                    0,
                    100,
                    command_ptr as u32,
                    12,
                    response as u32,
                    0
                ]
            ),
            u64::from(crate::tpm::tbs::TBS_E_INVALID_OUTPUT_POINTER)
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[context as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[context as u32]),
            u64::from(crate::tpm::tbs::TBS_E_INVALID_CONTEXT)
        );
    });
}

#[test]
fn evidence_cng_rpc_propsys_imm_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-crypto-sys");
        let mut memory = MemoryImage::default();

        // ── ncrypt: the full key lifecycle ──
        let open_provider: u64 = runtime.alloc_host_thunk(HostThunk::NCryptOpenStorageProvider);
        let create_key: u64 = runtime.alloc_host_thunk(HostThunk::NCryptCreatePersistedKey);
        let set_property: u64 = runtime.alloc_host_thunk(HostThunk::NCryptSetProperty);
        let finalize: u64 = runtime.alloc_host_thunk(HostThunk::NCryptFinalizeKey);
        let sign: u64 = runtime.alloc_host_thunk(HostThunk::NCryptSignHash);
        let verify: u64 = runtime.alloc_host_thunk(HostThunk::NCryptVerifySignature);
        let get_property: u64 = runtime.alloc_host_thunk(HostThunk::NCryptGetProperty);
        let is_alg: u64 = runtime.alloc_host_thunk(HostThunk::NCryptIsAlgSupported);
        let provider_out = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                open_provider,
                &[0, 0, provider_out as u32]
            ),
            0
        );
        let provider = read_guest_pointer(&memory, provider_out, GuestArch::X86).unwrap();
        assert_ne!(provider, 0);
        // The RSA algorithm name.
        let alg_ptr = 0x41_010_u64;
        let alg_wide: Vec<u16> = "RSA".encode_utf16().chain([0]).collect();
        for (i, unit) in alg_wide.iter().enumerate() {
            write_guest_u16(&mut memory, alg_ptr + (i as u64 * 2), *unit).ok();
        }
        let key_out = 0x41_100_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_key,
                &[provider as u32, key_out as u32, alg_ptr as u32, 0, 0, 0]
            ),
            0
        );
        let key = read_guest_pointer(&memory, key_out, GuestArch::X86).unwrap();
        assert_ne!(key, 0);
        // The key length property (1024 for speed).
        let length_ptr = 0x41_110_u64;
        let length_wide: Vec<u16> = "Length".encode_utf16().chain([0]).collect();
        for (i, unit) in length_wide.iter().enumerate() {
            write_guest_u16(&mut memory, length_ptr + (i as u64 * 2), *unit).ok();
        }
        let length_value = 0x41_120_u64;
        write_guest_u32(&mut memory, length_value, 1024).ok();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_property,
                &[key as u32, length_ptr as u32, length_value as u32, 4, 0]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, finalize, &[key as u32, 0]),
            0
        );
        assert!(runtime.ncrypt_keys.get(&key).unwrap().finalized);

        // The property round trip.
        let alg_name_out = 0x41_200_u64;
        let name_size_out = 0x41_210_u64;
        let alg_prop = 0x41_220_u64;
        let prop_wide: Vec<u16> = "Algorithm Name".encode_utf16().chain([0]).collect();
        for (i, unit) in prop_wide.iter().enumerate() {
            write_guest_u16(&mut memory, alg_prop + (i as u64 * 2), *unit).ok();
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_property,
                &[
                    key as u32,
                    alg_prop as u32,
                    alg_name_out as u32,
                    64,
                    name_size_out as u32,
                    0
                ]
            ),
            0
        );
        let alg = memory.read_bytes(alg_name_out, 8).unwrap();
        assert_eq!(&alg[..4], &[0x52, 0x00, 0x53, 0x00], "RSA");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, is_alg, &[alg_ptr as u32, 0]),
            0
        );

        // Sign + verify a digest.
        let digest_ptr = 0x41_300_u64;
        let digest: Vec<u8> = (0..32).map(|i| i as u8).collect();
        memory.map_bytes(digest_ptr, &digest);
        let signature_out = 0x41_400_u64;
        let signature_size_out = 0x41_500_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sign,
                &[
                    key as u32,
                    0,
                    digest_ptr as u32,
                    32,
                    signature_out as u32,
                    256,
                    signature_size_out as u32,
                    0
                ]
            ),
            0
        );
        let sig_len = read_guest_u32(&memory, signature_size_out).unwrap();
        assert_eq!(sig_len, 128, "1024-bit RSA signature");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify,
                &[
                    key as u32,
                    0,
                    digest_ptr as u32,
                    32,
                    signature_out as u32,
                    sig_len,
                    0
                ]
            ),
            0
        );

        // ── rpcrt4: the UUID surface ──
        let uuid_create: u64 = runtime.alloc_host_thunk(HostThunk::UuidCreate);
        let uuid_to_string: u64 = runtime.alloc_host_thunk(HostThunk::UuidToStringW);
        let uuid_from_string: u64 = runtime.alloc_host_thunk(HostThunk::UuidFromStringW);
        let uuid_out = 0x41_500_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, uuid_create, &[uuid_out as u32]),
            0
        );
        let uuid_bytes = memory.read_bytes(uuid_out, 16).unwrap();
        assert!(uuid_bytes.iter().any(|b| *b != 0), "non-nil UUID");
        let string_out = 0x41_510_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                uuid_to_string,
                &[uuid_out as u32, string_out as u32]
            ),
            0
        );
        let string_ptr = read_guest_pointer(&memory, string_out, GuestArch::X86).unwrap();
        let text = read_utf16_string(&memory, string_ptr).unwrap();
        assert_eq!(text.len(), 36, "canonical UUID string");
        let roundtrip_out = 0x41_520_u64;
        let text_ptr = 0x41_530_u64;
        let wide: Vec<u16> = text.encode_utf16().chain([0]).collect();
        for (i, unit) in wide.iter().enumerate() {
            write_guest_u16(&mut memory, text_ptr + (i as u64 * 2), *unit).ok();
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                uuid_from_string,
                &[text_ptr as u32, roundtrip_out as u32]
            ),
            0
        );
        assert_eq!(
            memory.read_bytes(roundtrip_out, 16).unwrap(),
            uuid_bytes,
            "UUID round trip"
        );

        // ── propsys: the property-key registry ──
        let key_from_name: u64 = runtime.alloc_host_thunk(HostThunk::PSGetPropertyKeyFromName);
        let name_from_key: u64 = runtime.alloc_host_thunk(HostThunk::PSGetNameFromPropertyKey);
        let name_ptr = 0x41_600_u64;
        let name_wide: Vec<u16> = "System.Title".encode_utf16().chain([0]).collect();
        for (i, unit) in name_wide.iter().enumerate() {
            write_guest_u16(&mut memory, name_ptr + (i as u64 * 2), *unit).ok();
        }
        let key_out = 0x41_610_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                key_from_name,
                &[name_ptr as u32, key_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, key_out + 16).unwrap(),
            2,
            "PKEY System.Title pid"
        );
        let reverse_out = 0x41_620_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                name_from_key,
                &[key_out as u32, reverse_out as u32]
            ),
            0
        );
        let reverse_ptr = read_guest_pointer(&memory, reverse_out, GuestArch::X86).unwrap();
        assert_eq!(
            read_utf16_string(&memory, reverse_ptr).unwrap(),
            "System.Title"
        );

        // ── imm32: the no-IME surface ──
        let imm_context: u64 = runtime.alloc_host_thunk(HostThunk::ImmGetContext);
        let imm_release: u64 = runtime.alloc_host_thunk(HostThunk::ImmReleaseContext);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, imm_context, &[0x1000]),
            0,
            "no IME context"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, imm_release, &[0x1000, 0]),
            1
        );
    })
}

#[test]
fn evidence_security_crypto_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-security");
        let mut memory = MemoryImage::default();

        // ── rsaenh: the CSP context + key ──
        let acquire: u64 = runtime.alloc_host_thunk(HostThunk::CpAcquireContext);
        let gen_key: u64 = runtime.alloc_host_thunk(HostThunk::CpGenKey);
        let release: u64 = runtime.alloc_host_thunk(HostThunk::CpReleaseContext);
        let ctx_out = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                acquire,
                &[0, 0, 1, 0, ctx_out as u32]
            ),
            0
        );
        let ctx = read_guest_pointer(&memory, ctx_out, GuestArch::X86).unwrap();
        assert_ne!(ctx, 0);
        let key_out = 0x41_100_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                gen_key,
                &[ctx as u32, 1, 0, key_out as u32]
            ),
            0
        );
        let key = read_guest_pointer(&memory, key_out, GuestArch::X86).unwrap();
        assert_ne!(key, 0);
        assert!(runtime.csp_keys.get(&key).unwrap().private_key.is_some());
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release, &[ctx as u32, 0]),
            0
        );

        // ── cryptng: the legacy BCrypt surface (the existing suite) ──
        let bcrypt_open: u64 = runtime.alloc_host_thunk(HostThunk::BCryptOpenAlgorithmProvider);
        let bcrypt_hash: u64 = runtime.alloc_host_thunk(HostThunk::BCryptHash);
        let alg_ptr = 0x41_200_u64;
        let alg_wide: Vec<u16> = "SHA256".encode_utf16().chain([0]).collect();
        for (i, unit) in alg_wide.iter().enumerate() {
            write_guest_u16(&mut memory, alg_ptr + (i as u64 * 2), *unit).ok();
        }
        let provider_out = 0x41_210_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                bcrypt_open,
                &[provider_out as u32, alg_ptr as u32, 0, 0]
            ),
            0
        );
        let provider = read_guest_pointer(&memory, provider_out, GuestArch::X86).unwrap();
        assert_ne!(provider, 0);
        let input = 0x41_220_u64;
        memory.map_bytes(input, b"abc");
        let digest_out = 0x41_230_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                bcrypt_hash,
                &[
                    provider as u32,
                    0,
                    0,
                    input as u32,
                    3,
                    digest_out as u32,
                    32
                ]
            ),
            0
        );
        let digest = memory.read_bytes(digest_out, 32).unwrap();
        assert_eq!(
            digest,
            vec![
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ],
            "SHA-256 of abc"
        );

        // ── dpapi: the protect/unprotect round trip ──
        let protect: u64 = runtime.alloc_host_thunk(HostThunk::CryptProtectData);
        let unprotect: u64 = runtime.alloc_host_thunk(HostThunk::CryptUnprotectData);
        let data_in = 0x41_300_u64;
        let secret = 0x41_310_u64;
        memory.map_bytes(secret, b"hello world");
        write_guest_u32(&mut memory, data_in, 11).ok();
        write_guest_pointer(&mut memory, data_in + 8, secret, GuestArch::X86).ok();
        assert_eq!(
            read_guest_u32(&memory, data_in).unwrap(),
            11,
            "cbData written"
        );
        let blob_out = 0x41_320_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                protect,
                &[data_in as u32, 0, 0, 0, 0, 0, blob_out as u32]
            ),
            1
        );
        let blob_size = read_guest_u32(&memory, blob_out).unwrap();
        assert!(blob_size > 32, "blob size {blob_size}");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                unprotect,
                &[blob_out as u32, 0, 0, 0, 0, 0, data_in as u32]
            ),
            1
        );
        let restored = read_guest_u32(&memory, data_in).unwrap();
        assert_eq!(restored, 11, "the round trip restores the length");
        let restored_ptr = read_guest_pointer(&memory, data_in + 8, GuestArch::X86).unwrap();
        assert_eq!(
            memory.read_bytes(restored_ptr, 11).unwrap(),
            b"hello world",
            "the round trip restores the data"
        );

        // ── sspicli: the NTLM package info ──
        let query_package: u64 = runtime.alloc_host_thunk(HostThunk::QuerySecurityPackageInfoW);
        let package_ptr = 0x41_400_u64;
        let package_wide: Vec<u16> = "NTLM".encode_utf16().chain([0]).collect();
        for (i, unit) in package_wide.iter().enumerate() {
            write_guest_u16(&mut memory, package_ptr + (i as u64 * 2), *unit).ok();
        }
        let info_out = 0x41_410_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query_package,
                &[package_ptr as u32, info_out as u32]
            ),
            0
        );
        let info = read_guest_pointer(&memory, info_out, GuestArch::X86).unwrap();
        assert_ne!(info, 0);
        let name_ptr = read_guest_pointer(&memory, info + 12, GuestArch::X86).unwrap();
        assert_eq!(read_utf16_string(&memory, name_ptr).unwrap(), "NTLM");
    })
}

#[test]
fn cert_digest_digest_dispatch_writes_known_digests() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("cert-digest");
        let mut memory = MemoryImage::default();
        let digest = runtime.alloc_host_thunk(HostThunk::CertDigestDigest);
        let request = 0x41_000_u64;
        let data = 0x41_100_u64;
        let out = 0x41_200_u64;
        let cap = 0x41_300_u64;
        memory.map_bytes(data, b"abc");
        write_u32(&mut memory, request, data as u32); // pbData
        write_u32(&mut memory, request + 4, 3); // cbData
        write_u32(&mut memory, request + 8, 0x8003); // CALG_MD5
        write_u32(&mut memory, request + 12, out as u32); // pbDigest
        write_u32(&mut memory, request + 16, cap as u32); // pcbDigest
        write_u32(&mut memory, cap, 16); // capacity

        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, digest, &[request as u32]);
        assert_eq!(ret, 1, "the digest helper returns TRUE");
        assert_eq!(runtime.last_error, 0);
        // RFC 1321: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72.
        assert_eq!(
            memory.read_bytes(out, 16).expect("digest bytes"),
            vec![
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
        assert_eq!(read_u32(&memory, cap).expect("capacity"), 16);

        // FIPS 180-2: SHA-256("abc") =
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
        write_u32(&mut memory, request + 8, 0x800c); // CALG_SHA_256
        write_u32(&mut memory, cap, 32); // grow the output capacity
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, digest, &[request as u32]);
        assert_eq!(ret, 1);
        assert_eq!(
            memory.read_bytes(out, 32).expect("digest bytes"),
            vec![
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        assert_eq!(read_u32(&memory, cap).expect("capacity"), 32);

        // An unknown algorithm fails honestly: FALSE +
        // ERROR_NOT_SUPPORTED, nothing written.
        write_u32(&mut memory, request + 8, 0x9999);
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, digest, &[request as u32]);
        assert_eq!(ret, 0);
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);
    })
}

#[test]
fn cng_audit_log_appends_real_records() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("cng-audit");
        let mut memory = MemoryImage::default();
        let audit = runtime.alloc_host_thunk(HostThunk::CngAuditLog);
        let record = 0x41_000_u64;
        assert!(runtime.cng_audit_records().is_empty());

        // A genuine append: provider/action/result + host timestamp.
        write_u32(&mut memory, record, 0x0001_2345); // provider
        write_u32(&mut memory, record + 4, 0x1); // action
        write_u32(&mut memory, record + 8, 0); // result (success)
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, audit, &[record as u32]);
        assert_eq!(ret, u64::from(ERROR_SUCCESS));
        assert_eq!(runtime.last_error, 0);
        let records = runtime.cng_audit_records();
        assert_eq!(records.len(), 1, "one genuine record appended");
        assert_eq!(records[0].provider, 0x0001_2345);
        assert_eq!(records[0].action, 0x1);
        assert_eq!(records[0].result, 0);
        assert!(records[0].timestamp_ms > 0);

        // A second call appends a second record (the op count grows).
        write_u32(&mut memory, record, 0x0000_beef);
        write_u32(&mut memory, record + 4, 0x2);
        write_u32(&mut memory, record + 8, 0xC000_000D); // audited failure status
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, audit, &[record as u32]);
        assert_eq!(ret, u64::from(ERROR_SUCCESS));
        let records = runtime.cng_audit_records();
        assert_eq!(records.len(), 2, "the op count increases per call");
        assert_eq!(records[1].provider, 0x0000_beef);
        assert_eq!(records[1].action, 0x2);
        assert_eq!(records[1].result, 0xC000_000D);
        assert!(records[1].timestamp_ms >= records[0].timestamp_ms);

        // A NULL record is a parameter failure and appends nothing.
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, audit, &[0]);
        assert_eq!(ret, u64::from(ERROR_INVALID_PARAMETER));
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        assert_eq!(runtime.cng_audit_records().len(), 2);
    })
}

#[test]
fn cert_select_certificate_selects_the_single_eligible_certificate() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("cert-select");
        let mut memory = MemoryImage::default();
        let select = runtime.alloc_host_thunk(HostThunk::CertSelectCertificate);

        // Two certificates: one valid for ten years from now, one that
        // expired ten days ago.  Only the first is selectable.
        let valid_der = build_test_cert_der(1, "Valid Game Cert", -60, 86400 * 3650);
        let expired_der = build_test_cert_der(2, "Expired Game Cert", -86400 * 400, -86400 * 10);
        let store_handle = runtime.cert_store_manager.open_store("SELECT_TEST_A");
        runtime
            .cert_store_manager
            .add_certificate(store_handle, &valid_der)
            .expect("add valid cert");
        runtime
            .cert_store_manager
            .add_certificate(store_handle, &expired_der)
            .expect("add expired cert");

        let request = 0x60_000_u64;
        let selected_out = 0x60_100_u64;
        write_x86_select_request(&mut memory, request, &[store_handle], &[]);
        memory.map_bytes(selected_out, &[0; 4]);

        // Real selection: TRUE + a real certificate context.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select,
            &[request as u32, selected_out as u32],
        );
        assert_eq!(ret, 1, "exactly one best candidate is selected");
        assert_eq!(runtime.last_error, 0);
        let context = read_u32(&memory, selected_out).expect("selected ctx") as u64;
        assert_ne!(context, 0);
        assert_eq!(read_u32(&memory, context).expect("magic"), 0x4345_5254);
        assert_eq!(
            read_u32(&memory, context + 4).expect("der len") as usize,
            valid_der.len()
        );
        assert_eq!(
            memory
                .read_bytes(context + 64, valid_der.len())
                .expect("der"),
            valid_der,
            "the selected context carries the winning DER"
        );
        assert_eq!(
            runtime
                .cert_contexts
                .get(&context)
                .expect("registered context"),
            &valid_der
        );
        assert_eq!(
            read_guest_pointer(&memory, request + SEL_X86_HSELECTED, GuestArch::X86).unwrap(),
            store_handle,
            "hSelectedCertStore names the winning store"
        );

        // The selection is deterministic: an identical second request
        // selects the same certificate again.
        let second_out = 0x60_200_u64;
        memory.map_bytes(second_out, &[0; 4]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select,
            &[request as u32, second_out as u32],
        );
        assert_eq!(ret, 1);
        assert_eq!(
            runtime
                .cert_contexts
                .get(&(read_u32(&memory, second_out).expect("ctx") as u64))
                .expect("second context"),
            &valid_der
        );
    })
}

#[test]
fn cert_select_certificate_user_cancel_and_real_failure_modes() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("cert-select-cancel");
        let mut memory = MemoryImage::default();
        let select = runtime.alloc_host_thunk(HostThunk::CertSelectCertificate);

        // Null request and null out pointer: parameter failures.
        let request = 0x60_000_u64;
        let selected_out = 0x60_100_u64;
        memory.map_bytes(selected_out, &[0; 4]);
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, select, &[0, selected_out as u32]);
        assert_eq!(ret, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, select, &[request as u32, 0]);
        assert_eq!(ret, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // No stores requested: nothing is offered, so the pick is
        // cancelled (FALSE, no error).
        write_x86_select_request(&mut memory, request, &[], &[]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select,
            &[request as u32, selected_out as u32],
        );
        assert_eq!(ret, 0, "an empty picker cancels");
        assert_eq!(runtime.last_error, 0);
        assert_eq!(read_u32(&memory, selected_out).unwrap(), 0);

        // A store handle that does not exist is a real failure.
        write_x86_select_request(&mut memory, request, &[0xdead_beef], &[]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select,
            &[request as u32, selected_out as u32],
        );
        assert_eq!(ret, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);

        // Two simultaneously eligible certificates: the best-match
        // ordering (algorithm strength, then notAfter, then store order)
        // claims a selection instead of cancelling.
        let first = build_test_cert_der(3, "First Eligible", -60, 86400 * 3650);
        let second = build_test_cert_der(4, "Second Eligible", -60, 86400 * 3650);
        let store_handle = runtime.cert_store_manager.open_store("SELECT_TEST_B");
        runtime
            .cert_store_manager
            .add_certificate(store_handle, &first)
            .expect("add first");
        runtime
            .cert_store_manager
            .add_certificate(store_handle, &second)
            .expect("add second");
        write_x86_select_request(&mut memory, request, &[store_handle], &[]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select,
            &[request as u32, selected_out as u32],
        );
        assert_eq!(ret, 1, "the best-match selection claims a certificate");
        assert_eq!(runtime.last_error, 0);
        let context = read_u32(&memory, selected_out).unwrap() as u64;
        assert_ne!(context, 0);
        let selected = runtime
            .cert_contexts
            .get(&context)
            .expect("selected context");
        assert!(
            selected == &first || selected == &second,
            "the selection is one of the eligible certificates"
        );

        // Only expired certificates: none is selectable (cancel).
        let only_expired = build_test_cert_der(5, "Only Expired", -86400 * 400, -86400 * 10);
        let expired_store = runtime.cert_store_manager.open_store("SELECT_TEST_C");
        runtime
            .cert_store_manager
            .add_certificate(expired_store, &only_expired)
            .expect("add expired");
        write_x86_select_request(&mut memory, request, &[expired_store], &[]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select,
            &[request as u32, selected_out as u32],
        );
        assert_eq!(ret, 0, "expired-only stores cancel");
        assert_eq!(runtime.last_error, 0);

        // The certificates of the display-store list participate in
        // the selection exactly like the rghStores list.
        let valid_der = build_test_cert_der(6, "Display Store Cert", -60, 86400 * 3650);
        let display_store = runtime.cert_store_manager.open_store("SELECT_TEST_D");
        runtime
            .cert_store_manager
            .add_certificate(display_store, &valid_der)
            .expect("add display cert");
        write_x86_select_request(&mut memory, request, &[], &[display_store]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            select,
            &[request as u32, selected_out as u32],
        );
        assert_eq!(ret, 1, "display-store certificates are candidates");
        let context = read_u32(&memory, selected_out).expect("ctx") as u64;
        assert_eq!(read_u32(&memory, context).expect("magic"), 0x4345_5254);
        assert_eq!(
            memory
                .read_bytes(context + 64, valid_der.len())
                .expect("der"),
            valid_der
        );
    })
}

#[test]
fn evidence_core_srw_lock_thunks_round_trip() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-srw");
        let mut memory = MemoryImage::default();
        let init = runtime.alloc_host_thunk(HostThunk::InitializeSRWLock);
        let acquire_ex = runtime.alloc_host_thunk(HostThunk::AcquireSRWLockExclusive);
        let release_ex = runtime.alloc_host_thunk(HostThunk::ReleaseSRWLockExclusive);
        let try_ex = runtime.alloc_host_thunk(HostThunk::TryAcquireSRWLockExclusive);
        let acquire_sh = runtime.alloc_host_thunk(HostThunk::AcquireSRWLockShared);
        let release_sh = runtime.alloc_host_thunk(HostThunk::ReleaseSRWLockShared);
        let try_sh = runtime.alloc_host_thunk(HostThunk::TryAcquireSRWLockShared);
        let init_cs_spin =
            runtime.alloc_host_thunk(HostThunk::InitializeCriticalSectionAndSpinCount);
        let init_cs_ex = runtime.alloc_host_thunk(HostThunk::InitializeCriticalSectionEx);

        let lock = 0x41_000_u32;
        memory.map_bytes(lock as u64, &[0xFF; 16]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init, &[lock]),
            0
        );
        assert_eq!(memory.read_bytes(lock as u64, 4).unwrap(), [0_u8; 4]);

        // Exclusive ownership is exclusive: a second TryAcquire fails until
        // the release.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_ex, &[lock]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_ex, &[lock]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release_ex, &[lock]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_ex, &[lock]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release_ex, &[lock]),
            0
        );
        // The blocking acquire also round-trips.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, acquire_ex, &[lock]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release_ex, &[lock]),
            0
        );

        // Shared ownership admits multiple readers; an exclusive acquire is
        // refused while readers hold the lock.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_sh, &[lock]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_sh, &[lock]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_ex, &[lock]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release_sh, &[lock]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release_sh, &[lock]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, try_ex, &[lock]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release_ex, &[lock]),
            0
        );
        // The shared blocking acquire round-trips too.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, acquire_sh, &[lock]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, release_sh, &[lock]),
            0
        );

        // The spin-count initializers register a fresh critical section and
        // zero the guest structure (spin count at offset 20 on x86).
        let cs = 0x42_000_u32;
        memory.map_bytes(cs as u64, &[0xFF; 24]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init_cs_spin, &[cs, 0x1000]),
            1
        );
        assert_eq!(
            runtime.critical_sections.get(&(cs as u64)).copied(),
            Some(0)
        );
        assert_eq!(memory.read_u32(cs as u64 + 20).unwrap(), 0x1000);
        let cs2 = 0x42_100_u32;
        memory.map_bytes(cs2 as u64, &[0xFF; 24]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, init_cs_ex, &[cs2, 0x400, 0]),
            1
        );
        assert_eq!(
            runtime.critical_sections.get(&(cs2 as u64)).copied(),
            Some(0)
        );
        assert_eq!(memory.read_u32(cs2 as u64 + 20).unwrap(), 0x400);
    })
}

#[test]
fn evidence_core_iocp_thunks_round_trip() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-iocp");
        let mut memory = MemoryImage::default();
        let create_port = runtime.alloc_host_thunk(HostThunk::CreateIoCompletionPort);
        let post_status = runtime.alloc_host_thunk(HostThunk::PostQueuedCompletionStatus);
        let get_status = runtime.alloc_host_thunk(HostThunk::GetQueuedCompletionStatus);
        let get_status_ex = runtime.alloc_host_thunk(HostThunk::GetQueuedCompletionStatusEx);

        // CreateIoCompletionPort mints a port.
        let port = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_port,
            &[u32::MAX, 0, 0x1234, 2],
        );
        assert_ne!(port, 0);
        assert_eq!(runtime.last_error, 0);

        // PostQueuedCompletionStatus enqueues one packet.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                post_status,
                &[port as u32, 7, 0x1234, 0x5678]
            ),
            1
        );
        // GetQueuedCompletionStatus dequeues it into the output pointers.
        let bytes_ptr = 0x41_000;
        let key_ptr = 0x41_004;
        let overlapped_ptr = 0x41_008;
        memory.map_bytes(bytes_ptr as u64, &[0; 12]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_status,
                &[
                    port as u32,
                    bytes_ptr as u32,
                    key_ptr as u32,
                    overlapped_ptr as u32,
                    0
                ]
            ),
            1
        );
        assert_eq!(memory.read_u32(bytes_ptr as u64).unwrap(), 7);
        assert_eq!(memory.read_u32(key_ptr as u64).unwrap(), 0x1234);
        assert_eq!(memory.read_u32(overlapped_ptr as u64).unwrap(), 0x5678);

        // A second packet dequeues through GetQueuedCompletionStatusEx with
        // the OVERLAPPED_ENTRY layout (x86 stride 16).
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                post_status,
                &[port as u32, 9, 0xCAFE, 0xBEEF]
            ),
            1
        );
        let entries_ptr = 0x41_100;
        let removed_ptr = 0x41_200;
        memory.map_bytes(entries_ptr as u64, &[0; 64]);
        memory.map_bytes(removed_ptr as u64, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_status_ex,
                &[port as u32, entries_ptr as u32, 4, removed_ptr as u32, 0, 0]
            ),
            1
        );
        assert_eq!(memory.read_u32(removed_ptr as u64).unwrap(), 1);
        assert_eq!(memory.read_u32(entries_ptr as u64).unwrap(), 0xCAFE);
        assert_eq!(memory.read_u32(entries_ptr as u64 + 4).unwrap(), 0xBEEF);
        assert_eq!(memory.read_u32(entries_ptr as u64 + 12).unwrap(), 9);
    })
}

#[test]
fn evidence_core_string_and_codepage_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-strings");
        let mut memory = MemoryImage::default();
        let lstrlen_a = runtime.alloc_host_thunk(HostThunk::Strlen);
        let lstrcpy_a = runtime.alloc_host_thunk(HostThunk::LstrcpyA);
        let lstrcat_w = runtime.alloc_host_thunk(HostThunk::LstrcatW);
        let lstrcpyn_w = runtime.alloc_host_thunk(HostThunk::LstrcpynW);
        let mb2wc = runtime.alloc_host_thunk(HostThunk::MultiByteToWideChar);
        let wc2mb = runtime.alloc_host_thunk(HostThunk::WideCharToMultiByte);
        let get_string_type = runtime.alloc_host_thunk(HostThunk::GetStringTypeW);
        let lcmap = runtime.alloc_host_thunk(HostThunk::LCMapStringW);
        let ods_a = runtime.alloc_host_thunk(HostThunk::OutputDebugStringA);
        let ods_w = runtime.alloc_host_thunk(HostThunk::OutputDebugStringW);

        // lstrlenA counts ANSI bytes before the NUL.
        let ascii = 0x41_000;
        memory.map_bytes(ascii, b"hello\0");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, lstrlen_a, &[ascii as u32]),
            5
        );

        // lstrcpyA copies the NUL-terminated ANSI string and returns dst.
        let dst = 0x41_100;
        memory.map_bytes(dst, &[0xFF; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lstrcpy_a,
                &[dst as u32, ascii as u32]
            ),
            dst
        );
        assert_eq!(read_c_string(&memory, dst).unwrap(), "hello");

        // lstrcatW appends the source to the destination.
        let wide_ab = 0x41_200;
        let wide_cd = 0x41_300;
        memory.map_bytes(wide_ab, &evidence_utf16("ab"));
        memory.map_bytes(wide_cd, &evidence_utf16("cd"));
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lstrcat_w,
                &[wide_ab as u32, wide_cd as u32]
            ),
            wide_ab
        );
        assert_eq!(read_utf16_string(&memory, wide_ab).unwrap(), "abcd");

        // lstrcpynW copies at most max_count-1 code units + NUL.
        let wide_abcdef = 0x41_400;
        memory.map_bytes(wide_abcdef, &evidence_utf16("abcdef"));
        let cpy_dst = 0x41_500;
        memory.map_bytes(cpy_dst, &[0xFF; 32]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lstrcpyn_w,
                &[cpy_dst as u32, wide_abcdef as u32, 4]
            ),
            cpy_dst
        );
        assert_eq!(read_utf16_string(&memory, cpy_dst).unwrap(), "abc");

        // MultiByteToWideChar size query then fill (CP_ACP → UTF-16).  The
        // required size counts UTF-16 code units (5 for "hello").
        let wc_query = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            mb2wc,
            &[CP_ACP, 0, ascii as u32, 5, 0, 0],
        );
        assert_eq!(wc_query, 5);
        let wc_dst = 0x41_600;
        memory.map_bytes(wc_dst, &[0; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                mb2wc,
                &[CP_ACP, 0, ascii as u32, 5, wc_dst as u32, 5]
            ),
            5
        );
        assert_eq!(
            memory.read_bytes(wc_dst, 10).unwrap(),
            evidence_utf16("hello")
        );

        // WideCharToMultiByte size query then fill.
        let mb_query = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wc2mb,
            &[CP_ACP, 0, wc_dst as u32, 5, 0, 0, 0, 0],
        );
        assert_eq!(mb_query, 5);
        let mb_dst = 0x41_700;
        memory.map_bytes(mb_dst, &[0; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wc2mb,
                &[CP_ACP, 0, wc_dst as u32, 5, mb_dst as u32, 5, 0, 0]
            ),
            5
        );
        assert_eq!(read_c_string(&memory, mb_dst).unwrap(), "hello");

        // GetStringTypeW classifies each code unit (C1_* for 'h' non-zero).
        let st_out = 0x41_800;
        memory.map_bytes(st_out, &[0; 32]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_string_type,
                &[CT_CTYPE1, wc_dst as u32, u32::MAX, st_out as u32]
            ),
            1
        );
        assert_ne!(memory.read_u16(st_out).unwrap(), 0);

        // LCMapStringW folds case: "ABC" → "abc" (LCMAP_LOWERCASE).
        let wide_abc = 0x41_900;
        memory.map_bytes(wide_abc, &evidence_utf16("ABC"));
        let lc_dst = 0x41_A00;
        memory.map_bytes(lc_dst, &[0; 16]);
        let lc_required = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            lcmap,
            &[0, LCMAP_LOWERCASE, wide_abc as u32, u32::MAX, 0, 0],
        );
        assert_eq!(lc_required, 4, "lowercased 'abc' + NUL");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lcmap,
                &[
                    0,
                    LCMAP_LOWERCASE,
                    wide_abc as u32,
                    u32::MAX,
                    lc_dst as u32,
                    4
                ]
            ),
            4
        );
        assert_eq!(read_utf16_string(&memory, lc_dst).unwrap(), "abc");

        // OutputDebugStringA/W are observable no-fault calls.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, ods_a, &[ascii as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, ods_w, &[wc_dst as u32]),
            0
        );
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn anticheat_identity_exports_reject_invalid_arguments_and_report_real_facts() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("anticheat-identity-exports");
        let mut memory = MemoryImage::default();

        // CheckRemoteDebuggerPresent reads the live attach state.
        let check = runtime.alloc_host_thunk(HostThunk::CheckRemoteDebuggerPresent);
        let out = 0x42_000u64;
        memory.map_bytes(out, &[0u8; 4]);
        let process = runtime.win32.current_process_handle();
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, check, &[process, out as u32]),
            1
        );
        assert_eq!(memory.read_u32(out).expect("present"), 0);
        runtime
            .anticheat
            .debug
            .attach(runtime.guest_pid)
            .expect("attach debugger");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, check, &[process, out as u32]),
            1
        );
        assert_eq!(memory.read_u32(out).expect("present"), 1);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, check, &[process, 0]),
            0
        );
        assert_eq!(runtime.last_error, 87, "null out pointer is invalid");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, check, &[0, out as u32]),
            0
        );
        assert_eq!(runtime.last_error, 6, "zero handle is invalid");

        // GetSystemFirmwareTable serves the real SMBIOS table.
        let firmware = runtime.alloc_host_thunk(HostThunk::GetSystemFirmwareTable);
        const RSMB: u32 = 0x5253_4D42;
        const ACPI: u32 = 0x4143_5049;
        let required = dispatch_x86_thunk(&mut runtime, &mut memory, firmware, &[RSMB, RSMB, 0, 0]);
        assert!(required > 0, "SMBIOS table must have a real size");
        assert_eq!(runtime.last_error, 122, "required size reported");
        let table = 0x42_100u64;
        memory.map_bytes(table, &vec![0u8; required as usize]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                firmware,
                &[RSMB, RSMB, table as u32, required as u32]
            ),
            required
        );
        assert_eq!(runtime.last_error, 0);
        assert_eq!(memory.read_u8(table).expect("smbios"), 0, "type 0 BIOS");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                firmware,
                &[RSMB, RSMB, table as u32, required.saturating_sub(1) as u32]
            ),
            required
        );
        assert_eq!(
            runtime.last_error, 122,
            "short buffer reports required size"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, firmware, &[ACPI, 0, 0, 0]),
            0
        );
        assert_eq!(runtime.last_error, 50, "ACPI tables are genuinely absent");

        // GetVolumeInformationW reports the real volume identity.
        let probe = crate::hardware_identity::host_identity();
        eprintln!(
            "[identity] disks={} absent={:?}",
            probe.disks.len(),
            probe.absent
        );
        let volume = runtime.alloc_host_thunk(HostThunk::GetVolumeInformationW);
        let root = runtime
            .alloc_utf16_string(&mut memory, "C:\\")
            .expect("root");
        let name = 0x42_200u64;
        let serial = 0x42_300u64;
        let max_component = 0x42_304u64;
        let flags = 0x42_308u64;
        let fs = 0x42_320u64;
        memory.map_bytes(name, &[0u8; 64]);
        memory.map_bytes(serial, &[0u8; 16]);
        memory.map_bytes(fs, &[0u8; 64]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                volume,
                &[
                    root as u32,
                    name as u32,
                    32,
                    serial as u32,
                    max_component as u32,
                    flags as u32,
                    fs as u32,
                    32,
                ]
            ),
            1,
            "last_error={}",
            runtime.last_error
        );
        assert_eq!(runtime.last_error, 0);
        let identity = crate::hardware_identity::host_identity();
        let disk = identity.disks.first().expect("mounted volume");
        assert_eq!(memory.read_u32(serial).expect("serial"), disk.volume_serial);
        assert_eq!(memory.read_u32(max_component).expect("max"), 255);
        assert_eq!(memory.read_u32(flags).expect("flags"), 0);
        assert_eq!(
            read_utf16_string(&memory, fs).expect("filesystem"),
            disk.filesystem
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                volume,
                &[0, name as u32, 32, serial as u32, 0, 0, fs as u32, 32]
            ),
            0
        );
        assert_eq!(runtime.last_error, 87, "null root is invalid");
    })
}

#[test]
fn firmware_identity_surface_matches_the_smbios_source_and_rejects_short_buffers() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("firmware-cross-surface");
        let mut memory = MemoryImage::default();
        let query = runtime.alloc_host_thunk(HostThunk::NtQuerySystemInformation);
        let get_table = runtime.alloc_host_thunk(HostThunk::GetSystemFirmwareTable);
        let identity = crate::hardware_identity::host_identity();
        let table = crate::hardware_identity::build_smbios_table(identity);
        const RSMB: u32 = 0x5253_4D42;

        let required = 12 + table.len() as u32;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_table, &[RSMB, RSMB, 0, 0]),
            u64::from(table.len() as u32),
            "Win32 and introspection report the same table length"
        );

        let buffer = 0x4C_000u64;
        let length_ptr = 0x4D_000u64;
        memory.map_bytes(buffer, &[0u8; 0x4000]);
        memory.map_bytes(length_ptr, &[0u8; 4]);
        write_u32(&mut memory, buffer, RSMB);
        write_u32(&mut memory, buffer + 4, RSMB);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[76, buffer as u32, required + 16, length_ptr as u32]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(memory.read_u32(buffer).expect("provider"), RSMB);
        assert_eq!(
            memory.read_u32(buffer + 8).expect("table length"),
            table.len() as u32
        );
        assert_eq!(
            memory.read_bytes(buffer + 12, table.len()).expect("table"),
            table,
            "the introspection table is the SAME SMBIOS bytes"
        );

        write_u32(&mut memory, buffer, RSMB);
        write_u32(&mut memory, buffer + 4, RSMB);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                query,
                &[76, buffer as u32, required - 1, length_ptr as u32]
            ),
            u64::from(crate::ntdll::STATUS_INFO_LENGTH_MISMATCH.raw())
        );
        assert_eq!(memory.read_u32(length_ptr).expect("required"), required);
    })
}

#[test]
fn attestation_guest_thunks_reject_forgery_replay_and_no_provider() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("attestation-thunks");
        let mut memory = MemoryImage::default();
        let challenge_thunk = runtime.alloc_host_thunk(HostThunk::NtAttestationChallenge);
        let quote_thunk = runtime.alloc_host_thunk(HostThunk::NtAttestationQuote);
        let verify_thunk = runtime.alloc_host_thunk(HostThunk::NtAttestationVerify);
        let verifier = runtime
            .alloc_c_string(&mut memory, "casa1-guest")
            .expect("verifier");
        let provider = runtime
            .alloc_c_string(&mut memory, "casa1")
            .expect("provider");
        let challenge_out = 0x62_000u64;
        let challenge_required = 0x62_100u64;
        let quote_out = 0x63_000u64;
        let quote_required = 0x65_000u64;
        memory.map_bytes(challenge_out, &[0u8; 64]);
        memory.map_bytes(challenge_required, &[0u8; 4]);
        memory.map_bytes(quote_out, &[0u8; 0x2000]);
        memory.map_bytes(quote_required, &[0u8; 4]);

        // A short challenge buffer reports the exact wire size.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                challenge_thunk,
                &[
                    verifier as u32,
                    600_000,
                    challenge_out as u32,
                    0,
                    challenge_required as u32
                ]
            ),
            u64::from(crate::ntdll::STATUS_INFO_LENGTH_MISMATCH.raw())
        );
        assert_eq!(memory.read_u32(challenge_required).expect("required"), 48);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                challenge_thunk,
                &[verifier as u32, 600_000, 0, 48, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw()),
            "a null challenge output is invalid"
        );
        // A null verifier and a zero TTL are invalid parameters.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                challenge_thunk,
                &[0, 600_000, challenge_out as u32, 48, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                challenge_thunk,
                &[verifier as u32, 0, challenge_out as u32, 48, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );

        let issue_challenge =
            |runtime: &mut PeHostRuntime, memory: &mut MemoryImage, nonce_out: u64| -> Vec<u8> {
                assert_eq!(
                    dispatch_x86_thunk(
                        runtime,
                        memory,
                        challenge_thunk,
                        &[
                            verifier as u32,
                            600_000,
                            nonce_out as u32,
                            48,
                            challenge_required as u32
                        ]
                    ),
                    u64::from(crate::ntdll::STATUS_SUCCESS.raw())
                );
                let mut bytes = vec![0_u8; 48];
                memory.read_into(nonce_out, &mut bytes).expect("challenge");
                bytes
            };
        let issue_quote = |runtime: &mut PeHostRuntime,
                           memory: &mut MemoryImage,
                           challenge: u64,
                           out: u64|
         -> Vec<u8> {
            // A zero-length quote buffer reports the required size.
            assert_eq!(
                dispatch_x86_thunk(
                    runtime,
                    memory,
                    quote_thunk,
                    &[
                        challenge as u32,
                        48,
                        provider as u32,
                        out as u32,
                        0,
                        quote_required as u32
                    ]
                ),
                u64::from(crate::ntdll::STATUS_INFO_LENGTH_MISMATCH.raw())
            );
            let required = memory.read_u32(quote_required).expect("quote size") as usize;
            assert!(required > 0);
            assert_eq!(
                dispatch_x86_thunk(
                    runtime,
                    memory,
                    quote_thunk,
                    &[
                        challenge as u32,
                        48,
                        provider as u32,
                        out as u32,
                        required as u32,
                        quote_required as u32
                    ]
                ),
                u64::from(crate::ntdll::STATUS_SUCCESS.raw())
            );
            let mut bytes = vec![0_u8; required];
            memory.read_into(out, &mut bytes).expect("quote bytes");
            bytes
        };

        memory.map_bytes(challenge_out, &[0u8; 48]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                quote_thunk,
                &[
                    challenge_out as u32,
                    48,
                    provider as u32,
                    quote_out as u32,
                    0x2000,
                    quote_required as u32
                ]
            ),
            0xC000_000D,
            "an all-zero challenge is malformed"
        );

        let challenge_one = issue_challenge(&mut runtime, &mut memory, challenge_out);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                quote_thunk,
                &[0, 48, provider as u32, quote_out as u32, 0x2000, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                quote_thunk,
                &[
                    challenge_out as u32,
                    47,
                    provider as u32,
                    quote_out as u32,
                    0x2000,
                    0
                ]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        let empty_provider = runtime
            .alloc_c_string(&mut memory, "")
            .expect("empty provider");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                quote_thunk,
                &[
                    challenge_out as u32,
                    48,
                    empty_provider as u32,
                    quote_out as u32,
                    0x2000,
                    0
                ]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                quote_thunk,
                &[challenge_out as u32, 48, provider as u32, 0, 0x2000, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        let quote_one = issue_quote(&mut runtime, &mut memory, challenge_out, quote_out);
        assert!(
            serde_json::from_slice::<crate::anticheat::Quote>(&quote_one).is_ok(),
            "the signed quote must be well-formed JSON"
        );

        // A fresh runtime has no provider registered: verification is the
        // documented "cannot attest" failure, never a fabricated verdict.
        let (mut no_provider, _temp_two) = test_runtime("attestation-no-provider");
        let mut no_provider_memory = MemoryImage::default();
        let no_provider_verify = no_provider.alloc_host_thunk(HostThunk::NtAttestationVerify);
        let no_provider_challenge_out = 0x66_000u64;
        let no_provider_required = 0x66_100u64;
        no_provider_memory.map_bytes(no_provider_challenge_out, &[0u8; 48]);
        no_provider_memory.map_bytes(no_provider_required, &[0u8; 4]);
        let no_provider_challenge_thunk =
            no_provider.alloc_host_thunk(HostThunk::NtAttestationChallenge);
        let no_provider_verifier = no_provider
            .alloc_c_string(&mut no_provider_memory, "casa1-guest")
            .expect("verifier");
        assert_eq!(
            dispatch_x86_thunk(
                &mut no_provider,
                &mut no_provider_memory,
                no_provider_challenge_thunk,
                &[
                    no_provider_verifier as u32,
                    600_000,
                    no_provider_challenge_out as u32,
                    48,
                    no_provider_required as u32
                ]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let no_provider_quote = 0x67_000u64;
        no_provider_memory.map_bytes(no_provider_quote, &quote_one);
        assert_eq!(
            dispatch_x86_thunk(
                &mut no_provider,
                &mut no_provider_memory,
                no_provider_verify,
                &[
                    no_provider_challenge_out as u32,
                    48,
                    no_provider_quote as u32,
                    quote_one.len() as u32
                ]
            ),
            0xC000_00BB,
            "no provider is STATUS_NOT_SUPPORTED"
        );

        // Genuine quote verifies, then the same challenge replays denied.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[
                    challenge_out as u32,
                    48,
                    quote_out as u32,
                    quote_one.len() as u32
                ]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[
                    challenge_out as u32,
                    48,
                    quote_out as u32,
                    quote_one.len() as u32
                ]
            ),
            0xC000_0022,
            "a replayed challenge is STATUS_ACCESS_DENIED"
        );
        let _ = challenge_one;

        // A quote whose DER signature was tampered with never verifies.
        let challenge_two = issue_challenge(&mut runtime, &mut memory, challenge_out);
        let genuine_two = issue_quote(&mut runtime, &mut memory, challenge_out, quote_out);
        let mut forged: crate::anticheat::Quote =
            serde_json::from_slice(&genuine_two).expect("quote json");
        let signature_len = forged.signature_der.len();
        forged.signature_der[signature_len - 1] ^= 0x01;
        let forged = serde_json::to_vec(&forged).expect("forged quote");
        memory.map_bytes(0x68_000, &forged);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[challenge_out as u32, 48, 0x68_000u32, forged.len() as u32]
            ),
            0xC000_0022,
            "a forged signature is STATUS_ACCESS_DENIED"
        );
        let mut impostor: crate::anticheat::Quote =
            serde_json::from_slice(&genuine_two).expect("quote json");
        impostor.provider_id = "not-casa1".to_string();
        let impostor = serde_json::to_vec(&impostor).expect("impostor quote");
        memory.map_bytes(0x6C_000, &impostor);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[challenge_out as u32, 48, 0x6C_000u32, impostor.len() as u32]
            ),
            0xC000_0034,
            "an unregistered provider is STATUS_OBJECT_NAME_NOT_FOUND"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[
                    challenge_out as u32,
                    48,
                    quote_out as u32,
                    genuine_two.len() as u32
                ]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let _ = challenge_two;

        // A quote bound to a different nonce is a parameter mismatch.
        let challenge_three = issue_challenge(&mut runtime, &mut memory, challenge_out);
        let mut other_nonce_challenge = challenge_three.clone();
        other_nonce_challenge[0] ^= 0xFF;
        memory.map_bytes(challenge_out, &other_nonce_challenge);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[
                    challenge_out as u32,
                    48,
                    quote_out as u32,
                    genuine_two.len() as u32
                ]
            ),
            0xC000_000D,
            "a quote bound to another nonce is STATUS_INVALID_PARAMETER"
        );

        // Null/truncated buffers and a malformed quote are invalid
        // parameters, never a trust verdict.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[0, 48, quote_out as u32, genuine_two.len() as u32]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[challenge_out as u32, 48, 0, genuine_two.len() as u32]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[challenge_out as u32, 48, quote_out as u32, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        memory.map_bytes(0x69_000, &[0u8; 47]);
        memory.map_bytes(0x6A_000, b"not a quote");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[0x69_000u32, 47, quote_out as u32, genuine_two.len() as u32]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify_thunk,
                &[challenge_out as u32, 48, 0x6A_000u32, 11]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
    })
}

#[test]
fn attestation_provider_enrollment_is_persisted_revocable_and_exact() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("attestation-enrollment");
        let mut memory = MemoryImage::default();
        let enroll = runtime.alloc_host_thunk(HostThunk::NtAttestationEnrollProvider);
        let revoke = runtime.alloc_host_thunk(HostThunk::NtAttestationRevokeProvider);
        let verify = runtime.alloc_host_thunk(HostThunk::NtAttestationVerify);

        let key = crate::anticheat::AttestationKeyPair::generate();
        let spki = key.public_key_spki();
        let provider = runtime
            .alloc_c_string(&mut memory, "acme")
            .expect("provider");
        let key_ptr = 0x80_000u64;
        memory.map_bytes(key_ptr, &spki);

        // Malformed ids/keys are exact parameter failures.
        let empty_id = runtime.alloc_c_string(&mut memory, "").expect("empty id");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[empty_id as u32, key_ptr as u32, spki.len() as u32, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        let traversal = runtime
            .alloc_c_string(&mut memory, "bad/id")
            .expect("traversal id");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[traversal as u32, key_ptr as u32, spki.len() as u32, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[provider as u32, key_ptr as u32, 0, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );
        let bad_key = 0x81_000u64;
        memory.map_bytes(bad_key, &[0x00, 0x01, 0x02]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[provider as u32, bad_key as u32, 3, 0]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw())
        );

        // Real enrollment persists the supplied SPKI and is trusted.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[provider as u32, key_ptr as u32, spki.len() as u32, 0]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let stored = crate::anticheat::InstallIdentityStore::open(
            runtime.win32.ge().root.join("attestation"),
        )
        .load_provider("acme")
        .expect("load provider")
        .expect("persisted provider");
        assert_eq!(stored.public_key_spki, spki);
        assert_eq!(stored.valid_until_ms, None);

        // A duplicate id is never an overwrite.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[provider as u32, key_ptr as u32, spki.len() as u32, 0]
            ),
            u64::from(crate::ntdll::STATUS_OBJECT_NAME_COLLISION.raw())
        );

        // A runtime that has not yet registered the provider in memory
        // loads the persisted enrollment before verifying.
        runtime.anticheat.attestation = crate::anticheat::AttestationRegistry::new();

        let challenge_at = 0x82_000u64;
        let quote_at = 0x83_000u64;
        memory.map_bytes(challenge_at, &[0u8; 48]);
        memory.map_bytes(quote_at, &[0u8; 0x2000]);
        let write_quote = |runtime: &mut PeHostRuntime,
                           memory: &mut MemoryImage,
                           provider_id: &str|
         -> (u64, usize) {
            let challenge = crate::anticheat::Challenge::new(
                crate::anticheat::ATTESTATION_VERIFIER,
                60_000,
                runtime.anticheat.clock.tick_count64(),
            );
            memory.map_bytes(
                challenge_at,
                &crate::anticheat::challenge_to_wire(&challenge),
            );
            let quote = key.sign_quote(
                provider_id,
                &crate::anticheat::measure_casa1_build(),
                &challenge.nonce,
            );
            let bytes = serde_json::to_vec(&quote).expect("quote json");
            memory.map_bytes(quote_at, &bytes);
            (challenge_at, bytes.len())
        };
        let (challenge, quote_len) = write_quote(&mut runtime, &mut memory, "acme");
        // An unknown provider is an exact object-name miss.
        let ghost = runtime.alloc_c_string(&mut memory, "ghost").expect("ghost");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, revoke, &[ghost as u32]),
            u64::from(crate::ntdll::STATUS_OBJECT_NAME_NOT_FOUND.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify,
                &[challenge as u32, 48, quote_at as u32, quote_len as u32]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );

        // Revocation is persisted and affects the next verification.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, revoke, &[provider as u32]),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert!(
            crate::anticheat::InstallIdentityStore::open(
                runtime.win32.ge().root.join("attestation"),
            )
            .is_revoked("acme")
        );
        // Drop the in-memory trust again: the persisted revocation alone
        // must deny the next verification, never fall back to NoProvider.
        runtime.anticheat.attestation = crate::anticheat::AttestationRegistry::new();
        let (challenge, quote_len) = write_quote(&mut runtime, &mut memory, "acme");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify,
                &[challenge as u32, 48, quote_at as u32, quote_len as u32]
            ),
            0xC000_0022,
            "a revoked provider is STATUS_ACCESS_DENIED"
        );
        // Revocation is idempotent and re-enrollment stays refused.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, revoke, &[provider as u32]),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[provider as u32, key_ptr as u32, spki.len() as u32, 0]
            ),
            0xC000_0022,
            "a revoked provider cannot be re-enrolled"
        );

        // A finite TTL expires the provider key: verification is
        // STATUS_TIMEOUT, never a trust verdict.
        let short = runtime
            .alloc_c_string(&mut memory, "short-lived")
            .expect("short id");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[short as u32, key_ptr as u32, spki.len() as u32, 1]
            ),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let short_key =
            crate::anticheat::AttestationKeyPair::from_secret_bytes(&key.secret_bytes())
                .expect("same key");
        let challenge = crate::anticheat::Challenge::new(
            crate::anticheat::ATTESTATION_VERIFIER,
            60_000,
            runtime.anticheat.clock.tick_count64(),
        );
        memory.map_bytes(
            challenge_at,
            &crate::anticheat::challenge_to_wire(&challenge),
        );
        let quote = short_key.sign_quote(
            "short-lived",
            &crate::anticheat::measure_casa1_build(),
            &challenge.nonce,
        );
        let bytes = serde_json::to_vec(&quote).expect("quote json");
        memory.map_bytes(quote_at, &bytes);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                verify,
                &[challenge_at as u32, 48, quote_at as u32, bytes.len() as u32]
            ),
            0xC000_0102,
            "an expired provider key is the documented attestation timeout"
        );

        // A store that cannot be written is an exact I/O failure, never a
        // fabricated success or a zeroed trust decision.
        let attestation_root = runtime.win32.ge().root.join("attestation");
        std::fs::remove_dir_all(&attestation_root).expect("remove store");
        std::fs::write(&attestation_root, b"not a directory").expect("block store root");
        let io_provider = runtime
            .alloc_c_string(&mut memory, "io-failure")
            .expect("io provider");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enroll,
                &[io_provider as u32, key_ptr as u32, spki.len() as u32, 0]
            ),
            0xC000_0001
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, revoke, &[short as u32]),
            0xC000_0001
        );
    })
}

#[test]
fn iat_patch_repatch_unpatch_and_unload_are_exact() {
    let (mut runtime, _temp) = test_runtime("iat-patch-exact");
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
    let mut memory = MemoryImage::default();
    let base = 0x40_0000u64;
    let rva = 0x1000u32;
    let slot = base + u64::from(rva);
    memory.map_bytes(base, &[0u8; 0x2000]);

    let thunk = runtime.alloc_host_thunk(HostThunk::GetLastError);
    write_guest_pointer(&mut memory, slot, thunk, GuestArch::X64).expect("seed IAT");
    let handle = runtime.get_or_create_module_handle("kernel32.dll");
    let import = ResolvedImport {
        requested_module: "kernel32.dll".to_string(),
        resolved_module: "kernel32.dll".to_string(),
        symbol: crate::pe::ImportSymbol::ByName {
            hint: 0,
            name: "GetLastError".to_string(),
        },
        iat_rva: rva,
        export: ExportSymbol {
            ordinal: 0,
            name: Some("GetLastError".to_string()),
            target: ExportTarget::Rva(0),
        },
    };
    runtime.record_iat_bindings(base, &mut memory, &[import]);
    assert_eq!(runtime.iat_metrics().patched, 1);
    assert_eq!(runtime.iat_metrics().iat_patched, 1);
    assert_eq!(
        runtime
            .iat_patches
            .entry(slot)
            .map(|entry| entry.patched_value),
        Some(thunk)
    );
    assert_eq!(
        read_guest_pointer(&memory, slot, GuestArch::X64).expect("read IAT"),
        thunk
    );

    let replacement = runtime.alloc_host_thunk(HostThunk::SetLastError);
    assert_eq!(
        runtime
            .re_resolve_iat_thunk(thunk, replacement, &mut memory)
            .expect("repatch"),
        1
    );
    assert_eq!(
        read_guest_pointer(&memory, slot, GuestArch::X64).expect("read IAT"),
        replacement
    );
    assert_eq!(runtime.iat_metrics().repatched, 1);

    // Guest writes win: a slot the guest changed is not clobbered by a
    // later thunk replacement.
    write_guest_pointer(&mut memory, slot, 0xDEAD_BEEF, GuestArch::X64).expect("guest write");
    assert_eq!(
        runtime
            .re_resolve_iat_thunk(replacement, thunk, &mut memory)
            .expect("repatch"),
        0
    );
    assert_eq!(
        read_guest_pointer(&memory, slot, GuestArch::X64).expect("read IAT"),
        0xDEAD_BEEF
    );
    // Restore the tracked value for the unload path.
    write_guest_pointer(&mut memory, slot, replacement, GuestArch::X64).expect("restore IAT");

    assert_eq!(
        runtime
            .invalidate_module_iat(handle, &mut memory)
            .expect("invalidate"),
        1
    );
    let rearmed = read_guest_pointer(&memory, slot, GuestArch::X64).expect("read rearmed IAT");
    assert_ne!(rearmed, replacement);
    assert_eq!(runtime.iat_patches.entry(slot).is_none(), true);
    assert_eq!(runtime.iat_metrics().invalidated, 1);
}

#[test]
fn iat_dispatch_bypass_counter_is_exact_and_reset_by_unpatch() {
    let mut table = IatPatchTable::default();
    let entry = IatPatchEntry {
        slot_va: 0x4000,
        selected_base: 0x4000,
        iat_rva: 0,
        module: "kernel32.dll".to_string(),
        symbol: crate::pe::ImportSymbol::ByName {
            hint: 0,
            name: "GetTickCount64".to_string(),
        },
        bound_value: 0xABC,
        patched_value: 0xABC,
        module_handle: 7,
    };
    assert_eq!(table.patch(entry.clone()), true);
    assert_eq!(table.patch(entry), false, "idempotent re-record");
    assert_eq!(table.record_dispatch(0xABC), true);
    assert_eq!(table.record_dispatch(0xABC), true);
    assert_eq!(table.record_dispatch(0x999), false);
    assert_eq!(table.metrics().dispatch_bypasses, 2);
    assert_eq!(table.metrics().iat_dispatch_bypasses, 2);
    let removed = table.unpatch(0x4000).expect("unpatch");
    assert_eq!(removed.patched_value, 0xABC);
    assert_eq!(table.record_dispatch(0xABC), false);
    assert_eq!(table.metrics().dispatch_bypasses, 2);
    assert_eq!(table.len(), 0);
}

#[test]
fn iat_patch_table_concurrent_patch_and_unpatch_has_no_race() {
    use std::sync::{Arc, Mutex};
    let table = Arc::new(Mutex::new(IatPatchTable::default()));
    let mut threads = Vec::new();
    for index in 0..8u64 {
        let table = Arc::clone(&table);
        threads.push(std::thread::spawn(move || {
            table.lock().expect("lock").patch(IatPatchEntry {
                slot_va: 0x4000 + index,
                selected_base: 0x4000,
                iat_rva: index as u32,
                module: "kernel32.dll".to_string(),
                symbol: crate::pe::ImportSymbol::ByName {
                    hint: 0,
                    name: format!("fn{index}"),
                },
                bound_value: index + 1,
                patched_value: index + 1,
                module_handle: 1,
            });
        }));
    }
    for thread in threads {
        thread.join().expect("patch thread");
    }
    assert_eq!(table.lock().expect("lock").len(), 8);
    assert_eq!(table.lock().expect("lock").metrics().patched, 8);

    let mut threads = Vec::new();
    for index in 0..8u64 {
        let table = Arc::clone(&table);
        threads.push(std::thread::spawn(move || {
            table
                .lock()
                .expect("lock")
                .unpatch(0x4000 + index)
                .expect("entry");
        }));
    }
    for thread in threads {
        thread.join().expect("unpatch thread");
    }
    assert_eq!(table.lock().expect("lock").len(), 0);
    assert_eq!(table.lock().expect("lock").metrics().patched, 8);
}

#[test]
fn inlined_api_semantics_match_dispatch_no_mismatch() {
    let (mut runtime, _temp) = test_runtime("inline-api");
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x5000, &[0u8; 0x100]);
    memory.map_bytes(0x6000, &[0u8; 0x100]);
    let mut state = CpuState::new(GuestArch::X64);
    crate::jit::reset_inline_api_metrics();

    let call_inline = |runtime: &mut PeHostRuntime,
                       state: &mut CpuState,
                       memory: &mut MemoryImage,
                       api: crate::jit::InlineApi| {
        unsafe {
            crate::jit::jit_helper_inline_api(
                runtime as *mut PeHostRuntime as *mut libc::c_void,
                state as *mut CpuState,
                memory as *mut MemoryImage,
                api.index() as u64,
                0,
            )
        }
    };

    // SetLastError / GetLastError.
    state.set(Register::Rcx, 0x2222);
    assert_eq!(
        call_inline(
            &mut runtime,
            &mut state,
            &mut memory,
            crate::jit::InlineApi::SetLastError
        ),
        0
    );
    assert_eq!(runtime.last_error, 0x2222);
    state.set(Register::Rcx, 0);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::GetLastError,
    );
    assert_eq!(state.get(Register::Rax), 0x2222);

    // TID / PID.
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::GetCurrentThreadId,
    );
    assert_eq!(
        state.get(Register::Rax),
        u64::from(runtime.win32.current_thread_id())
    );
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::GetCurrentProcessId,
    );
    assert_eq!(
        state.get(Register::Rax),
        u64::from(runtime.win32.current_process_id())
    );

    // QPC monotonicity and tick coherence against the shared monotonic
    // clock.
    state.set(Register::Rcx, 0x5000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::QueryPerformanceCounter,
    );
    assert_eq!(state.get(Register::Rax), 1);
    let first = memory.read_u64(0x5000).expect("first qpc");
    state.set(Register::Rcx, 0x5000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::QueryPerformanceCounter,
    );
    let second = memory.read_u64(0x5000).expect("second qpc");
    assert!(first > 0);
    assert!(second >= first);
    let tick = runtime.anticheat.clock.tick_count64();
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::GetTickCount64,
    );
    assert_eq!(state.get(Register::Rax), tick);

    // Interlocked fast paths, pinned to the exact atomic semantics.
    memory.write_u32(0x6000, 5);
    state.set(Register::Rcx, 0x6000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::InterlockedIncrement,
    );
    assert_eq!(state.get(Register::Rax), 6);
    assert_eq!(memory.read_u32(0x6000).expect("counter"), 6);
    state.set(Register::Rcx, 0x6000);
    state.set(Register::Rdx, 9);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::InterlockedExchange,
    );
    assert_eq!(state.get(Register::Rax), 6);
    assert_eq!(memory.read_u32(0x6000).expect("counter"), 9);

    // SRW fast paths.
    state.set(Register::Rcx, 0x7000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::InitializeSRWLock,
    );
    state.set(Register::Rcx, 0x7000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::AcquireSRWLockExclusive,
    );
    state.set(Register::Rcx, 0x7000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::ReleaseSRWLockExclusive,
    );
    state.set(Register::Rcx, 0x7000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::TryAcquireSRWLockShared,
    );
    assert_eq!(state.get(Register::Rax), 1);
    state.set(Register::Rcx, 0x7000);
    let _ = call_inline(
        &mut runtime,
        &mut state,
        &mut memory,
        crate::jit::InlineApi::ReleaseSRWLockShared,
    );

    let metrics = crate::jit::inline_api_metrics();
    assert_eq!(
        metrics.per_api[crate::jit::InlineApi::SetLastError.index()],
        1
    );
    assert_eq!(
        metrics.per_api[crate::jit::InlineApi::GetLastError.index()],
        1
    );
    assert_eq!(
        metrics.per_api[crate::jit::InlineApi::QueryPerformanceCounter.index()],
        2
    );
    assert_eq!(
        metrics.per_api[crate::jit::InlineApi::GetTickCount64.index()],
        1
    );
}

#[test]
fn whole_module_precompile_compiles_reachable_blocks_and_skips_without_jit() {
    let (mut runtime, _temp) = test_runtime("aot-precompile");
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1000, &[0x90, 0x90, 0xC3]);
    runtime.mapped_image_base = 0x1000;
    runtime.mapped_image_size = 3;
    assert_eq!(
        runtime
            .precompile_code_range(&memory, 0x1000, 0x1003, 8)
            .expect("precompile without JIT"),
        None,
        "a disabled JIT has nothing to precompile"
    );
    assert_eq!(
        runtime
            .precompile_image(&memory, 0x1000)
            .expect("image precompile without JIT"),
        None
    );

    let cache_dir = std::env::temp_dir().join(format!(
        "casa1-precompile-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0)
    ));
    let mut jit = crate::jit::JitRuntime::new(GuestArch::X64);
    jit.set_aot_cache_dir(Some(cache_dir.clone()));
    runtime.jit_runtime = Some(jit);
    let report = runtime
        .precompile_code_range(&memory, 0x1000, 0x1003, 8)
        .expect("precompile with JIT")
        .expect("JIT is installed");
    assert_eq!(report.blocks, 1);
    assert_eq!(report.compiled, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(
        runtime
            .precompile_image(&memory, 0x1000)
            .expect("image precompile")
            .expect("JIT is installed")
            .compiled,
        1
    );
    runtime.aot_precompile = false;
    assert_eq!(
        runtime.precompile_image(&memory, 0x1000).expect("disabled"),
        None,
        "the precompile switch is honored"
    );
    runtime.aot_precompile = true;

    // A fresh runtime for the same image must reuse the persisted record.
    let (mut second, _second_temp) = test_runtime("aot-precompile-second");
    configure_runtime_for_test_arch(&mut second, GuestArch::X64);
    let mut second_jit = crate::jit::JitRuntime::new(GuestArch::X64);
    second_jit.set_aot_cache_dir(Some(cache_dir.clone()));
    second.jit_runtime = Some(second_jit);
    let report = second
        .precompile_code_range(&memory, 0x1000, 0x1003, 8)
        .expect("second precompile")
        .expect("JIT is installed");
    assert_eq!(report.compiled, 1);
    let hits = second.jit_runtime.as_ref().expect("JIT").aot_metrics().0;
    assert_ne!(hits, 0, "the second runtime loaded the AOT record");
    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[test]
fn jit_inlined_api_call_site_matches_dispatch_no_mismatch() {
    let (mut runtime, _temp) = test_runtime("jit-inline-site");
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
    let mut jit = crate::jit::JitRuntime::new(GuestArch::X64);
    crate::jit::register_inline_api_target(0x8000, crate::jit::InlineApi::GetCurrentThreadId);
    let ir = vec![
        crate::cpu::IrInstruction::Call {
            target: 0x8000,
            return_address: 0x1006,
        },
        crate::cpu::IrInstruction::Jump { target: 0x9999 },
    ];
    let block = jit
        .get_or_compile_at_tier(
            &ir,
            0x1000,
            GuestArch::X64,
            crate::jit::CompilationTier::Tier0,
            None,
        )
        .expect("compile inline call site")
        .clone();
    let mut state = CpuState::new(GuestArch::X64);
    state.rip = 0x1000;
    let mut memory = MemoryImage::default();
    let api = crate::jit::InlineApi::GetCurrentThreadId.index();
    let before = crate::jit::inline_api_metrics().per_api[api];
    crate::jit::set_pe_runtime_pointer(&mut runtime as *mut PeHostRuntime as *mut libc::c_void);
    let _ = unsafe { jit.execute_block(&block, &mut state, &mut memory) };
    crate::jit::set_pe_runtime_pointer(std::ptr::null_mut());
    let after = crate::jit::inline_api_metrics().per_api[api];
    assert_eq!(after, before + 1);
    assert_eq!(
        state.get(Register::Rax),
        u64::from(runtime.win32.current_thread_id())
    );
}

#[test]
fn inlined_api_x86_stack_args_preserve_rsp_no_mismatch() {
    let (mut runtime, _temp) = test_runtime("inline-api-x86");
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x1_0000, &[0u8; 0x100]);
    memory.write_u32(0x1_0000, 0x1234);
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rsp, 0x1_0000);
    let sp_before = state.get(Register::Rsp);
    unsafe {
        crate::jit::jit_helper_inline_api(
            &mut runtime as *mut PeHostRuntime as *mut libc::c_void,
            &mut state as *mut CpuState,
            &mut memory as *mut MemoryImage,
            crate::jit::InlineApi::SetLastError.index() as u64,
            0,
        );
    }
    assert_eq!(runtime.last_error, 0x1234);
    assert_eq!(state.get(Register::Rsp), sp_before);
}

#[test]
fn serial_com_dispatch_rejects_invalid_busy_and_stale_handles() {
    let _guard = serial_dispatch_test_lock();
    crate::real_hid::dispatch::reset_for_tests();
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "serial-dispatch-errors",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        install_serial_dispatch_fixture(&mut runtime, 0x401, "/dev/cu.casa1-test");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, "\\\\.\\COM1")
            .expect("COM1 path");
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_ne!(handle, INVALID_HANDLE_VALUE as u32);
        assert_eq!(runtime.last_error, 0);
        assert_eq!(crate::real_hid::dispatch::serial_handle_count(), 1);

        let second = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_eq!(second, INVALID_HANDLE_VALUE as u32);
        assert_eq!(runtime.last_error, ERROR_SHARING_VIOLATION);

        let invalid_path = runtime
            .alloc_utf16_string(&mut memory, "\\\\.\\COM9")
            .expect("COM9 path");
        let invalid = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[invalid_path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_eq!(invalid, INVALID_HANDLE_VALUE as u32);
        assert_eq!(runtime.last_error, ERROR_FILE_NOT_FOUND);

        let device_path = runtime
            .alloc_utf16_string(&mut memory, "/dev/cu.casa1-test")
            .expect("device path");
        let by_path = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[device_path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_eq!(
            by_path, INVALID_HANDLE_VALUE as u32,
            "the first COM1 handle is still open"
        );

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle]),
            1
        );
        assert_eq!(runtime.last_error, 0);
        let purge_stale = runtime.alloc_host_thunk(HostThunk::PurgeComm);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, purge_stale, &[handle, 0]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);

        let read = runtime.alloc_host_thunk(HostThunk::ReadFile);
        let buffer = 0x70_000_u64;
        memory.map_bytes(buffer, &[0u8; 8]);
        let bytes_read = 0x70_100_u64;
        write_u32(&mut memory, bytes_read, 0xdead_beef);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                read,
                &[handle, buffer as u32, 1, bytes_read as u32, 0],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        assert_eq!(read_u32(&memory, bytes_read).unwrap_or(0), 0);

        let events = runtime
            .user32
            .refresh_physical_devices()
            .expect("refresh empty host");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].device().id,
            crate::real_hid::StableDeviceId::from_raw(0x401)
        );
        assert!(runtime.user32.serial_ports().is_empty());
        let create_after = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let after_removal = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_after,
            &[path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_eq!(after_removal, INVALID_HANDLE_VALUE as u32);
        assert_eq!(runtime.last_error, ERROR_FILE_NOT_FOUND);
    });
}

#[test]
fn serial_comm_ioctls_roundtrip_and_config_boundaries() {
    let _guard = serial_dispatch_test_lock();
    crate::real_hid::dispatch::reset_for_tests();
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "serial-comm-dispatch",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        install_serial_dispatch_fixture(&mut runtime, 0x402, "/dev/cu.casa1-comm");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, "\\\\.\\COM1")
            .expect("COM1 path");
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_ne!(handle, INVALID_HANDLE_VALUE as u32);

        let dcb = 0x71_000_u64;
        memory.map_bytes(dcb, &[0u8; 64]);
        let get_state = runtime.alloc_host_thunk(HostThunk::GetCommState);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_state, &[handle, dcb as u32],),
            1
        );
        assert_eq!(read_u32(&memory, dcb).unwrap_or(0), 28);
        assert_eq!(read_u32(&memory, dcb + 4).unwrap_or(0), 115_200);
        assert_eq!(memory.read_u8(dcb + 18).unwrap_or(0), 8);
        assert_eq!(memory.read_u8(dcb + 19).unwrap_or(0), 0);
        assert_eq!(memory.read_u8(dcb + 20).unwrap_or(0), 0);

        write_u32(&mut memory, dcb, 28);
        write_u32(&mut memory, dcb + 4, 9_600);
        memory.write_u8(dcb + 18, 8);
        memory.write_u8(dcb + 19, 2);
        memory.write_u8(dcb + 20, 2);
        let set_state = runtime.alloc_host_thunk(HostThunk::SetCommState);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_state, &[handle, dcb as u32],),
            1
        );
        assert_eq!(runtime.last_error, 0);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_state, &[handle, dcb as u32],),
            1
        );
        assert_eq!(read_u32(&memory, dcb + 4).unwrap_or(0), 9_600);
        assert_eq!(memory.read_u8(dcb + 19).unwrap_or(0), 2);
        assert_eq!(memory.read_u8(dcb + 20).unwrap_or(0), 2);

        write_u32(&mut memory, dcb + 4, 12_345);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_state, &[handle, dcb as u32],),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_state, &[handle, 0]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        let timeouts = 0x72_000_u64;
        memory.map_bytes(timeouts, &[0u8; 32]);
        for (index, value) in [10u32, 2, 30, 4, 50].iter().enumerate() {
            write_u32(&mut memory, timeouts + (index as u64 * 4), *value);
        }
        let set_timeouts = runtime.alloc_host_thunk(HostThunk::SetCommTimeouts);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_timeouts,
                &[handle, timeouts as u32],
            ),
            1
        );
        let get_timeouts = runtime.alloc_host_thunk(HostThunk::GetCommTimeouts);
        for offset in [0u64, 4, 8, 12, 16] {
            write_u32(&mut memory, timeouts + offset, 0);
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_timeouts,
                &[handle, timeouts as u32],
            ),
            1
        );
        assert_eq!(read_u32(&memory, timeouts).unwrap_or(0), 10);
        assert_eq!(read_u32(&memory, timeouts + 8).unwrap_or(0), 30);
        assert_eq!(read_u32(&memory, timeouts + 16).unwrap_or(0), 50);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_timeouts, &[handle, 0],),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_timeouts, &[handle, 0],),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        let purge = runtime.alloc_host_thunk(HostThunk::PurgeComm);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, purge, &[handle, 5]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, purge, &[handle, 0x10]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        let errors = 0x73_000_u64;
        let stat = 0x73_010_u64;
        memory.map_bytes(errors, &[0xff; 16]);
        let clear = runtime.alloc_host_thunk(HostThunk::ClearCommError);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                clear,
                &[handle, errors as u32, stat as u32],
            ),
            1
        );
        assert_eq!(read_u32(&memory, errors).unwrap_or(0xff), 0);
        assert_eq!(read_u32(&memory, stat).unwrap_or(0xff), 0);

        let escape = runtime.alloc_host_thunk(HostThunk::EscapeCommFunction);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, escape, &[handle, 0]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, escape, &[handle, 5]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, escape, &[handle, 9]),
            0
        );

        let flush = runtime.alloc_host_thunk(HostThunk::FlushFileBuffers);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, flush, &[handle]),
            1
        );

        let read = runtime.alloc_host_thunk(HostThunk::ReadFile);
        let write = runtime.alloc_host_thunk(HostThunk::WriteFile);
        let buffer = 0x74_000_u64;
        memory.map_bytes(buffer, &[1u8; 16]);
        let count = 0x74_100_u64;
        for (thunk, length, buffer_ptr, expected_error) in [
            (read, 0, 0, 0),
            (write, 0, 0, 0),
            (read, 1, 0, ERROR_INVALID_PARAMETER),
            (write, 1, 0, ERROR_INVALID_PARAMETER),
            (
                read,
                crate::real_hid::dispatch::MAX_SERIAL_TRANSFER + 1,
                buffer as u32,
                ERROR_INVALID_PARAMETER,
            ),
            (
                write,
                crate::real_hid::dispatch::MAX_SERIAL_TRANSFER + 1,
                buffer as u32,
                ERROR_INVALID_PARAMETER,
            ),
            (read, 4, buffer as u32, ERROR_NOT_SUPPORTED),
            (write, 4, buffer as u32, ERROR_NOT_SUPPORTED),
        ] {
            let result = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[handle, buffer_ptr, length as u32, count as u32, 0],
            );
            if expected_error == 0 {
                assert_eq!(result, 1);
                assert_eq!(runtime.last_error, 0);
            } else {
                assert_eq!(result, 0);
                assert_eq!(runtime.last_error, expected_error);
            }
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                read,
                &[handle, buffer as u32, 4, count as u32, 0x74_200],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                write,
                &[handle, buffer as u32, 4, count as u32, 0x74_200],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_state, &[handle, dcb as u32]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    });
}

#[test]
fn usb_dispatch_ioctls_enumerate_validate_and_reject_stale() {
    let _guard = serial_dispatch_test_lock();
    crate::real_hid::dispatch::reset_for_tests();
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "usb-dispatch-ioctls",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        install_usb_dispatch_fixture(&mut runtime);
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, "\\\\.\\Casa1Usb#0000000000000202")
            .expect("usb path");
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_ne!(handle, INVALID_HANDLE_VALUE as u32);
        assert_eq!(runtime.last_error, 0);
        assert_eq!(crate::real_hid::dispatch::usb_handle_count(), 1);
        assert_eq!(
            crate::real_hid::dispatch::usb_path(u64::from(handle)),
            Ok("IOUSBHostDevice:0000000000000202".to_string())
        );

        let ioctl = runtime.alloc_host_thunk(HostThunk::DeviceIoControl);
        let out = 0x75_000_u64;
        let bytes_ret = 0x75_200_u64;
        memory.map_bytes(out, &[0u8; 64]);
        write_u32(&mut memory, bytes_ret, 0xdead_beef);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[
                    handle,
                    IOCTL_USB_ENUMERATE_DEVICES,
                    0,
                    0,
                    out as u32,
                    32,
                    bytes_ret as u32,
                    0,
                ],
            ),
            1
        );
        assert_eq!(runtime.last_error, 0);
        assert_eq!(read_u32(&memory, bytes_ret).unwrap_or(0), 32);
        assert_eq!(
            read_u64(&memory, out).unwrap_or(0),
            0x202,
            "stable device id is published"
        );
        assert_eq!(read_u32(&memory, out + 8).unwrap_or(0), 0x1234);
        assert_eq!(read_u32(&memory, out + 12).unwrap_or(0), 0x5678);
        assert_eq!(read_u32(&memory, out + 16).unwrap_or(0), 1);
        assert_eq!(read_u32(&memory, out + 20).unwrap_or(0), 1);
        assert_eq!(read_u32(&memory, out + 24).unwrap_or(0), 1);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[
                    handle,
                    IOCTL_USB_ENUMERATE_DEVICES,
                    0,
                    0,
                    out as u32,
                    0,
                    bytes_ret as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INSUFFICIENT_BUFFER);
        assert_eq!(read_u32(&memory, bytes_ret).unwrap_or(0), 32);

        let input = 0x76_000_u64;
        memory.map_bytes(input, &[0u8; 32]);
        for (index, value) in [0u32, 0x81, 3, 1, 0, 8].iter().enumerate() {
            write_u32(&mut memory, input + (index as u64 * 4), *value);
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[
                    handle,
                    IOCTL_USB_VALIDATE_TRANSFER,
                    input as u32,
                    24,
                    out as u32,
                    0,
                    bytes_ret as u32,
                    0,
                ],
            ),
            1
        );
        assert_eq!(runtime.last_error, 0);

        write_u32(&mut memory, input + 8, 1);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[
                    handle,
                    IOCTL_USB_VALIDATE_TRANSFER,
                    input as u32,
                    24,
                    out as u32,
                    0,
                    bytes_ret as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);

        write_u32(&mut memory, input + 8, 3);
        write_u32(&mut memory, input + 16, 0x8000_0000);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[
                    handle,
                    IOCTL_USB_VALIDATE_TRANSFER,
                    input as u32,
                    24,
                    out as u32,
                    0,
                    bytes_ret as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);

        write_u32(&mut memory, input + 16, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[
                    handle,
                    IOCTL_USB_SUBMIT_TRANSFER,
                    input as u32,
                    24,
                    out as u32,
                    0,
                    bytes_ret as u32,
                    0,
                ],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[handle, 0x1234, 0, 0, out as u32, 0, bytes_ret as u32, 0],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_NOT_SUPPORTED);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle]),
            1
        );
        assert_eq!(crate::real_hid::dispatch::usb_handle_count(), 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                ioctl,
                &[
                    handle,
                    IOCTL_USB_ENUMERATE_DEVICES,
                    0,
                    0,
                    out as u32,
                    32,
                    bytes_ret as u32,
                    0
                ],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        let reopened = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, 0x8000_0000, 0, 0, 3, 0, 0],
        ) as u32;
        assert_ne!(reopened, INVALID_HANDLE_VALUE as u32);
        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, close, &[reopened]),
            1
        );

        let malformed = runtime
            .alloc_utf16_string(&mut memory, "\\\\.\\Casa1Usb#xyz")
            .expect("malformed usb path");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_file,
                &[malformed as u32, 0x8000_0000, 0, 0, 3, 0, 0],
            ) as u32,
            INVALID_HANDLE_VALUE as u32
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        let missing = runtime
            .alloc_utf16_string(&mut memory, "\\\\.\\Casa1Usb#0000000000000999")
            .expect("missing usb path");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_file,
                &[missing as u32, 0x8000_0000, 0, 0, 3, 0, 0],
            ) as u32,
            INVALID_HANDLE_VALUE as u32
        );
        assert_eq!(runtime.last_error, ERROR_FILE_NOT_FOUND);
    });
}
