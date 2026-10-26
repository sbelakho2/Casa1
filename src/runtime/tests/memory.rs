use super::support::*;
use super::*;

#[test]
fn read_utf16z_max_chars_limit_exceeded_is_error() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x10_000, &utf16_bytes("abcdef"));
        let error = read_utf16z(&memory, 0x10_000, 4).expect_err("must exceed limit");
        assert_eq!(error.code, ReasonCode::RcGuestPointerOutOfRange);
        // A string exactly at the limit (plus its NUL) still succeeds.
        assert_eq!(
            read_utf16z(&memory, 0x10_000, 6).expect("exact limit"),
            "abcdef"
        );
    })
}

#[test]
fn read_utf16z_string_ending_exactly_at_page_boundary() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        // Four code units = 8 bytes; the NUL unit straddles the page edge and
        // map_bytes maps it into the following page.
        let content = "abcd";
        let base = 0x10_000 + 4096 - 8;
        memory.map_bytes(base, &utf16_bytes(content));
        assert_eq!(read_utf16z(&memory, base, 1024).expect("read"), content);
    })
}

#[test]
fn read_utf16z_string_crossing_page_boundary() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        let content = "x".repeat(3000);
        let base = 0x10_000 + 4000;
        memory.map_bytes(base, &utf16_bytes(&content));
        assert_eq!(read_utf16z(&memory, base, 8192).expect("read"), content);
    })
}

#[test]
fn read_utf16z_unmapped_page_mid_string_is_error() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        // Map only the content (no NUL): the "c" unit straddles the page
        // edge and its high byte lies in the unmapped following page. An
        // unmapped range mid-string must error, not truncate.
        let base = 0x10_000 + 4096 - 5;
        memory.map_bytes(base, &utf16_bytes("abc")[..5]);
        let error = read_utf16z(&memory, base, 1024).expect_err("unmapped mid-string");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    })
}

#[test]
fn read_utf16z_nul_at_unmapped_page_edge_is_error() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        // Map only the content (no NUL): "ab" occupies the page's last four
        // bytes, so the NUL unit straddles the edge — its first byte at
        // page_end-1 is readable and its second byte is unmapped. The NUL
        // itself must be read (attempted) through the page-aware path before
        // failing — it is not a silent truncation point.
        let base = 0x10_000 + 4096 - 5;
        memory.map_bytes(base, &utf16_bytes("ab")[..4]);
        let error = read_utf16z(&memory, base, 1024).expect_err("NUL read must error");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    })
}

#[test]
fn tls_alloc_exhaustion_reports_not_enough_memory() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "tls-exhaustion",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        let tls_vector = 0x70_000;
        memory.map_bytes(tls_vector, &[0_u8; 4096 * 4]);
        runtime.tls_vector_ptr = tls_vector;

        let alloc_thunk = runtime.alloc_host_thunk(HostThunk::TlsAlloc);
        for expected in 0_u32..4096 {
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, alloc_thunk, &[]),
                u64::from(expected)
            );
            assert_eq!(runtime.last_error, 0);
        }
        // Exhausted: TlsAlloc returns TLS_OUT_OF_INDEXES (0xFFFFFFFF) with
        // ERROR_NOT_ENOUGH_MEMORY (8).
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, alloc_thunk, &[]),
            u32::MAX as u64
        );
        assert_eq!(runtime.last_error, ERROR_NOT_ENOUGH_MEMORY);
    })
}

#[test]
fn local_free_releases_local_alloc_handle_in_x86_runtime() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "local-free", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let local_alloc = runtime.alloc_host_thunk(HostThunk::LocalAlloc);
        let local_free = runtime.alloc_host_thunk(HostThunk::LocalFree);
        let handle = dispatch_x86_thunk(&mut runtime, &mut memory, local_alloc, &[0, 64]);
        assert_ne!(handle, 0);

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, local_free, &[handle as u32]),
            0
        );
        assert!(!runtime.heap_allocations.contains_key(&handle));
    })
}

#[test]
fn global_memory_status_ex_reports_host_memory_invariants() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("memory-status");
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::GlobalMemoryStatusEx);
        let status_ptr = 0x41_000_u32;
        memory.map_bytes(status_ptr as u64, &[0; 64]);

        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[status_ptr]);
        assert_eq!(result, 1);
        assert_eq!(memory.read_u32(status_ptr as u64).expect("dwLength"), 64);
        let memory_load = memory
            .read_u32((status_ptr + 4) as u64)
            .expect("dwMemoryLoad");
        assert!(
            memory_load <= 100,
            "memory load must be 0..=100, got {memory_load}"
        );
        let total_phys = memory
            .read_u64((status_ptr + 8) as u64)
            .expect("total phys");
        let avail_phys = memory
            .read_u64((status_ptr + 16) as u64)
            .expect("avail phys");
        assert!(total_phys > 0, "total physical memory must be non-zero");
        assert!(avail_phys <= total_phys, "available must not exceed total");
        let total_page = memory
            .read_u64((status_ptr + 24) as u64)
            .expect("total page");
        let avail_page = memory
            .read_u64((status_ptr + 32) as u64)
            .expect("avail page");
        assert!(
            total_page >= total_phys,
            "page-file total must include physical"
        );
        assert!(
            avail_page <= total_page,
            "available page must not exceed total"
        );
        // The virtual figures stay the guest VA-space bounds (2 GB x86).
        let total_virt = memory
            .read_u64((status_ptr + 40) as u64)
            .expect("total virt");
        assert_eq!(total_virt, 2 * 1024 * 1024 * 1024);
        // NULL buffer fails with ERROR_INVALID_PARAMETER.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
    })
}

// ── Guest pointer validation tests ──────────────────────────────────────
#[test]
fn test_validate_guest_pointer_rejects_null() {
    with_big_stack(|| {
        let memory = MemoryImage::default();
        let result = validate_guest_pointer(&memory, 0, 4);
        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    })
}

#[test]
fn test_validate_guest_pointer_rejects_unmapped_range() {
    with_big_stack(|| {
        let memory = MemoryImage::default();
        // Address 0x1000 is not mapped in a default MemoryImage
        let result = validate_guest_pointer(&memory, 0x1000, 16);
        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    })
}

#[test]
fn test_validate_guest_pointer_rejects_overflow() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        let base: u64 = 0xFFFF_FFFF_FFFF_FF00;
        memory.map_bytes(base, &vec![0u8; 256]);
        // base + 0x200 would overflow u64
        let result = validate_guest_pointer(&memory, base, 0x200);
        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert_eq!(err.code, ReasonCode::RcGuestPointerOutOfRange);
    })
}

#[test]
fn test_read_guest_bytes_checked_rejects_null() {
    with_big_stack(|| {
        let memory = MemoryImage::default();
        let result = read_guest_bytes_checked(&memory, 0, 4);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    })
}

#[test]
fn test_write_guest_bytes_checked_rejects_null() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        let result = write_guest_bytes_checked(&mut memory, 0, &[1, 2, 3]);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    })
}

// ── UTF-16 string tests ─────────────────────────────────────────────────
#[test]
fn test_read_utf16_string_checked_null_pointer() {
    with_big_stack(|| {
        let memory = MemoryImage::default();
        let result = read_utf16_string_checked(&memory, 0, 256);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    })
}

#[test]
fn test_read_utf16_string_checked_non_null_terminated_truncated() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        let base: u64 = 0x42000;
        // Write "AB" without null terminator — max_units=2 should stop after 2 units
        let units: Vec<u16> = vec![b'A' as u16, b'B' as u16];
        memory.map_bytes(base, &u16_bytes(&units));
        let result = read_utf16_string_checked(&memory, base, 2);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        // Should return "AB" even without null terminator (truncated at max_units)
        assert_eq!(result.unwrap(), "AB");
    })
}

#[test]
fn test_read_utf16_string_checked_lone_high_surrogate() {
    with_big_stack(|| {
        let mut memory = MemoryImage::default();
        let base: u64 = 0x44000;
        // Write a lone high surrogate (0xD800) followed by null terminator
        let units: Vec<u16> = vec![0xD800, 0];
        memory.map_bytes(base, &u16_bytes(&units));
        let result = read_utf16_string_checked(&memory, base, 256);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        // String::from_utf16_lossy replaces invalid surrogates with replacement char
        let s = result.unwrap();
        assert!(
            !s.is_empty(),
            "lone surrogate should produce replacement character"
        );
    })
}

#[test]
fn test_invalid_guest_pointer_null_read_u32() {
    with_big_stack(|| {
        let mem = MemoryImage::default();
        let result = read_guest_u32(&mem, 0);
        assert!(result.is_err(), "null pointer read should fail");
    })
}

#[test]
fn test_invalid_guest_pointer_unmapped_read_u32() {
    with_big_stack(|| {
        let mem = MemoryImage::default();
        let result = read_guest_u32(&mem, 0xDEAD_BEEF);
        assert!(result.is_err(), "unmapped pointer read should fail");
    })
}

#[test]
fn test_invalid_guest_pointer_null_read_bytes_checked() {
    with_big_stack(|| {
        let mem = MemoryImage::default();
        let result = read_guest_bytes_checked(&mem, 0, 16);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    })
}

#[test]
fn test_invalid_guest_pointer_overflow_read_checked() {
    with_big_stack(|| {
        let mem = MemoryImage::default();
        let result = read_guest_bytes_checked(&mem, u64::MAX, 4);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().message.contains("overflow"));
    })
}

#[test]
fn test_invalid_guest_pointer_write_checked_null() {
    with_big_stack(|| {
        let mut mem = MemoryImage::default();
        let result = write_guest_bytes_checked(&mut mem, 0, &[1, 2, 3, 4]);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(
            result.unwrap_err().code,
            ReasonCode::RcGuestPointerOutOfRange
        );
    })
}

#[test]
fn test_invalid_guest_pointer_write_checked_unmapped() {
    with_big_stack(|| {
        let mut mem = MemoryImage::default();
        let result = write_guest_bytes_checked(&mut mem, 0xFFFF_0000, &[1, 2, 3]);
        assert!(result.is_err(), "expected Err, got {result:?}");
    })
}

// -----------------------------------------------------------------------
// Item 110: Tests for truncated UTF-16 strings, non-terminated, invalid surrogates
// (Tests the module-level read_guest_utf16_string which takes length: i32)
// -----------------------------------------------------------------------
#[test]
fn test_read_guest_utf16_truncated_surrogate_pair() {
    with_big_stack(|| {
        let mut mem = MemoryImage::default();
        // U+D800 high surrogate followed by null terminator (truncated pair)
        let data: Vec<u8> = [0x00, 0xD8, 0x00, 0x00].to_vec();
        mem.map_bytes(0x1000, &data);
        let s = super::super::read_guest_utf16_string(&mem, 0x1000, -1);
        // from_utf16_lossy replaces unpaired surrogates with U+FFFD
        let replacement = '\u{FFFD}';
        assert!(
            s.contains(replacement),
            "expected replacement char for unpaired surrogate, got: {s:?}"
        );
    })
}

#[test]
fn test_read_guest_utf16_invalid_double_high_surrogate() {
    with_big_stack(|| {
        let mut mem = MemoryImage::default();
        // Two consecutive high surrogates (invalid)
        let data: Vec<u8> = [0x00, 0xD8, 0x01, 0xD8, 0x00, 0x00].to_vec();
        mem.map_bytes(0x1000, &data);
        let s = super::super::read_guest_utf16_string(&mem, 0x1000, -1);
        // Should handle gracefully (replacement chars)
        assert!(
            !s.is_empty(),
            "should produce some output even for invalid surrogates"
        );
    })
}

#[test]
fn crt_dupenv_s_allocates_and_handles_missing() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        runtime
            .process_environment
            .insert("MY_VAR".to_string(), "value123".to_string());
        let dupenv_s = runtime.alloc_host_thunk(HostThunk::DupenvS);
        let name = runtime.alloc_c_string(&mut memory, "MY_VAR").expect("name");
        let buffer_ptr = 0x61_000;
        let size_ptr = 0x61_008;
        memory.map_bytes(buffer_ptr, &[0_u8; 8]);
        memory.map_bytes(size_ptr, &[0_u8; 8]);

        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            dupenv_s,
            &[buffer_ptr as u32, size_ptr as u32, name as u32],
        );
        assert_eq!(ret, 0);
        let allocated = read_guest_pointer(&memory, buffer_ptr, GuestArch::X86).expect("buffer");
        assert_ne!(allocated, 0);
        assert_eq!(
            read_guest_pointer(&memory, size_ptr, GuestArch::X86).expect("size"),
            9
        );
        assert_eq!(
            read_c_string(&memory, allocated).expect("value"),
            "value123"
        );

        // Missing variable → NULL buffer, zero size, success.
        let missing = runtime
            .alloc_c_string(&mut memory, "NO_SUCH_VAR")
            .expect("missing");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            dupenv_s,
            &[buffer_ptr as u32, size_ptr as u32, missing as u32],
        );
        assert_eq!(ret, 0);
        assert_eq!(
            read_guest_pointer(&memory, buffer_ptr, GuestArch::X86).expect("buffer"),
            0
        );
        assert_eq!(
            read_guest_pointer(&memory, size_ptr, GuestArch::X86).expect("size"),
            0
        );
    })
}

#[test]
fn crt_alloc_fail_hook_yields_null_and_enomem() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let malloc = runtime.alloc_host_thunk(HostThunk::Malloc);
        runtime.crt_alloc_fail_next = true;
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, malloc, &[64]);
        assert_eq!(ret, 0, "injected allocation failure returns NULL");
        assert_eq!(runtime.crt_errno_get(&mut memory), ENOMEM);
        // The hook is one-shot: the next malloc succeeds.
        let set_errno = runtime.alloc_host_thunk(HostThunk::SetErrno);
        dispatch_x86_thunk(&mut runtime, &mut memory, set_errno, &[0]);
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, malloc, &[64]);
        assert_ne!(ret, 0);
        assert_eq!(runtime.crt_errno_get(&mut memory), 0);
    })
}

// ═══════════════════════════════════════════════════════════════════════
// evidence-crt-net: guest-thunk semantic tests for the CRT + network +
// crypto families (msvcrt/ucrtbase/ws2_32/winhttp/advapi32/bcrypt/
// crypt32).  Each test drives the guest API surface (HostThunk dispatch)
// and asserts observable behavior; the evidence registry names these
// tests as casa1-conformance:runtime-unit-tests.
// ═══════════════════════════════════════════════════════════════════════
#[test]
fn crt_memory_ops_copy_move_set_alloc_free() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();

        // memcpy copies bytes and returns the destination.
        let memcpy = runtime.alloc_host_thunk(HostThunk::Memcpy);
        let src = 0x64_000;
        memory.map_bytes(src, b"hello world");
        let dst = 0x64_100;
        memory.map_bytes(dst, &[0xAA_u8; 32]);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            memcpy,
            &[dst as u32, src as u32, 11],
        );
        assert_eq!(ret, dst);
        assert_eq!(memory.read_bytes(dst, 11).expect("copied"), b"hello world");

        // memmove is safe on overlapping ranges (the source is snapshotted
        // before the copy, so a forward overlap preserves the original bytes).
        let memmove = runtime.alloc_host_thunk(HostThunk::Memmove);
        let overlap = 0x64_200;
        memory.map_bytes(overlap, b"0123456789abcdef");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            memmove,
            &[(overlap + 2) as u32, overlap as u32, 10],
        );
        assert_eq!(ret, overlap + 2);
        assert_eq!(
            memory.read_bytes(overlap, 16).expect("overlap"),
            b"010123456789cdef"
        );

        // memset fills count bytes and returns the destination.
        let memset = runtime.alloc_host_thunk(HostThunk::Memset);
        let fill = 0x64_300;
        memory.map_bytes(fill, &[0x00_u8; 16]);
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, memset, &[fill as u32, 0xAB, 8]);
        assert_eq!(ret, fill);
        assert_eq!(
            memory.read_bytes(fill, 16).expect("fill"),
            [
                0xAB_u8, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        // calloc zeroes count*size bytes.
        let calloc = runtime.alloc_host_thunk(HostThunk::Calloc);
        let block = dispatch_x86_thunk(&mut runtime, &mut memory, calloc, &[4, 8]);
        assert_ne!(block, 0);
        assert_eq!(memory.read_bytes(block, 32).expect("calloc"), [0_u8; 32]);

        // realloc preserves the old contents and free releases the block.
        let malloc = runtime.alloc_host_thunk(HostThunk::Malloc);
        let realloc = runtime.alloc_host_thunk(HostThunk::Realloc);
        let free = runtime.alloc_host_thunk(HostThunk::Free);
        let first = dispatch_x86_thunk(&mut runtime, &mut memory, malloc, &[16]);
        assert_ne!(first, 0);
        memory.map_bytes(first, b"0123456789abcdef");
        let grown = dispatch_x86_thunk(&mut runtime, &mut memory, realloc, &[first as u32, 64]);
        assert_ne!(grown, 0);
        assert_eq!(
            memory.read_bytes(grown, 16).expect("preserved"),
            b"0123456789abcdef"
        );
        assert!(!runtime.heap_allocations.contains_key(&first));
        assert!(runtime.heap_allocations.contains_key(&grown));
        dispatch_x86_thunk(&mut runtime, &mut memory, free, &[grown as u32]);
        assert!(!runtime.heap_allocations.contains_key(&grown));
        // free(NULL) is a safe no-op.
        dispatch_x86_thunk(&mut runtime, &mut memory, free, &[0]);
    })
}

#[test]
fn evidence_core_global_heap_thunks_round_trip() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-heap");
        let mut memory = MemoryImage::default();
        let process_heap = runtime.alloc_host_thunk(HostThunk::GetProcessHeap);
        let process_heaps = runtime.alloc_host_thunk(HostThunk::GetProcessHeaps);
        let global_alloc = runtime.alloc_host_thunk(HostThunk::GlobalAlloc);
        let global_lock = runtime.alloc_host_thunk(HostThunk::GlobalLock);
        let global_unlock = runtime.alloc_host_thunk(HostThunk::GlobalUnlock);
        let global_free = runtime.alloc_host_thunk(HostThunk::GlobalFree);
        let heap_realloc = runtime.alloc_host_thunk(HostThunk::HeapReAlloc);
        let slist = runtime.alloc_host_thunk(HostThunk::InitializeSListHead);

        // GetProcessHeap reports the canonical process heap handle.
        let heap = dispatch_x86_thunk(&mut runtime, &mut memory, process_heap, &[]);
        assert_eq!(heap, PROCESS_HEAP_HANDLE);

        // GetProcessHeaps writes the one process heap and reports the count.
        let heaps_ptr = 0x41_000;
        memory.map_bytes(heaps_ptr as u64, &[0; 8]);
        let count = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            process_heaps,
            &[1, heaps_ptr as u32],
        );
        assert_eq!(count, 1);
        assert_eq!(
            memory.read_u32(heaps_ptr as u64).unwrap() as u64,
            PROCESS_HEAP_HANDLE
        );

        // GlobalAlloc mints a block; GlobalLock returns the locked address;
        // GlobalUnlock succeeds; HeapReAlloc moves the block (data copied).
        let block = dispatch_x86_thunk(&mut runtime, &mut memory, global_alloc, &[0, 64]);
        assert_ne!(block, 0);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, global_lock, &[block as u32]),
            block
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, global_unlock, &[block as u32]),
            0
        );
        assert_eq!(runtime.last_error, 0);
        let reallocated = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            heap_realloc,
            &[PROCESS_HEAP_HANDLE as u32, 0, block as u32, 256],
        );
        assert_ne!(reallocated, 0);
        assert_ne!(reallocated, block);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                global_free,
                &[reallocated as u32]
            ),
            0
        );
        // The freed block is gone: GlobalLock fails with ERROR_INVALID_HANDLE
        // and HeapReAlloc on an unknown address fails with
        // ERROR_INVALID_PARAMETER.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                global_lock,
                &[reallocated as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                heap_realloc,
                &[PROCESS_HEAP_HANDLE as u32, 0, 0x7777, 16]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // InitializeSListHead zeroes the x86 8-byte header.
        let slist_ptr = 0x42_000;
        memory.map_bytes(slist_ptr as u64, &[0xFF; 8]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, slist, &[slist_ptr as u32]),
            0
        );
        assert_eq!(memory.read_bytes(slist_ptr as u64, 8).unwrap(), [0_u8; 8]);
    })
}

#[test]
fn evidence_core_nt_memory_and_wait_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-nt-mem");
        let mut memory = MemoryImage::default();
        let read_mem = runtime.alloc_host_thunk(HostThunk::NtReadVirtualMemory);
        let write_mem = runtime.alloc_host_thunk(HostThunk::NtWriteVirtualMemory);
        let delay = runtime.alloc_host_thunk(HostThunk::NtDelayExecution);
        let wait_multi = runtime.alloc_host_thunk(HostThunk::NtWaitForMultipleObjects);
        let qpc = runtime.alloc_host_thunk(HostThunk::NtQueryPerformanceCounter);

        // NtReadVirtualMemory copies mapped guest bytes and reports the
        // count; unmapped reads never create pages (access violation).
        let source = 0x42_000;
        memory.map_bytes(source, b"ABCDEFGH");
        let buffer = 0x42_100;
        memory.map_bytes(buffer, &[0; 8]);
        let bytes_read_ptr = 0x42_200;
        memory.map_bytes(bytes_read_ptr, &[0; 4]);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_mem,
            &[
                0xFFFF_FFFF,
                source as u32,
                buffer as u32,
                8,
                bytes_read_ptr as u32,
            ],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        assert_eq!(memory.read_bytes(buffer, 8).unwrap(), b"ABCDEFGH");
        assert_eq!(memory.read_u32(bytes_read_ptr).unwrap(), 8);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_mem,
            &[
                0xFFFF_FFFF,
                0xDEAD_0000,
                buffer as u32,
                8,
                bytes_read_ptr as u32,
            ],
        );
        assert_eq!(status, 0xC000_0005, "STATUS_ACCESS_VIOLATION");

        // NtWriteVirtualMemory writes into the target and reports the count.
        let target = 0x42_300;
        memory.map_bytes(target, &[0; 8]);
        let bytes_written_ptr = 0x42_400;
        memory.map_bytes(bytes_written_ptr, &[0; 4]);
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            write_mem,
            &[
                0xFFFF_FFFF,
                target as u32,
                source as u32,
                8,
                bytes_written_ptr as u32,
            ],
        );
        assert_eq!(status, 0, "STATUS_SUCCESS");
        assert_eq!(memory.read_bytes(target, 8).unwrap(), b"ABCDEFGH");
        assert_eq!(memory.read_u32(bytes_written_ptr).unwrap(), 8);

        // NtDelayExecution(0) completes immediately with STATUS_SUCCESS;
        // a non-zero delay parks the thread on the scheduler.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delay, &[0, 0]),
            0
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, delay, &[0, 10_000]);
        assert!(
            runtime.main_thread_parked,
            "a non-zero delay parks the guest thread"
        );

        // NtWaitForMultipleObjects: one signaled event satisfies
        // wait-any immediately; unsignaled with zero timeout reports
        // STATUS_TIMEOUT.
        let (event_a, _) = runtime.win32.create_event(true, true, false, None);
        let (event_b, _) = runtime.win32.create_event(true, false, false, None);
        let handles_ptr = 0x42_500;
        memory.map_bytes(handles_ptr, &[0; 8]);
        memory.write_u32(handles_ptr, event_a);
        memory.write_u32(handles_ptr + 4, event_b);
        let rax = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wait_multi,
            &[2, handles_ptr as u32, 0, 0, 0],
        );
        assert_eq!(rax, 0, "WAIT_OBJECT_0 for the signaled event");
        // Both unsignaled, zero timeout → STATUS_TIMEOUT.
        runtime.win32.reset_event(event_a).expect("reset");
        let rax = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wait_multi,
            &[2, handles_ptr as u32, 0, 0, 0],
        );
        assert_eq!(rax, 0x102, "STATUS_TIMEOUT");
        // wait_all with both signaled → WAIT_OBJECT_0.
        runtime.win32.set_event(event_a).expect("set a");
        runtime.win32.set_event(event_b).expect("set b");
        let rax = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            wait_multi,
            &[2, handles_ptr as u32, 1, 0, 0],
        );
        assert_eq!(rax, 0, "wait-all satisfied");
        // Zero handles is STATUS_INVALID_PARAMETER.
        let rax = dispatch_x86_thunk(&mut runtime, &mut memory, wait_multi, &[0, 0, 0, 0, 0]);
        assert_eq!(rax, 0xC000_000D, "STATUS_INVALID_PARAMETER");

        // NtQueryPerformanceCounter writes counter + frequency.
        let counter_ptr = 0x42_600;
        let freq_ptr = 0x42_608;
        memory.map_bytes(counter_ptr, &[0; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                qpc,
                &[counter_ptr as u32, freq_ptr as u32]
            ),
            0,
            "STATUS_SUCCESS"
        );
        assert_eq!(memory.read_u64(freq_ptr).unwrap(), 10_000_000);
        assert_eq!(memory.read_u64(counter_ptr).unwrap(), 0);
    })
}
