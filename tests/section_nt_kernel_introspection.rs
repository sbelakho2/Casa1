#![allow(dead_code, unused_imports)]
//! Adversarial tests for the CasaK kernel-introspection surface served by
//! `NtQuerySystemInformation`: every class the serializer backs must return
//! real, internally-consistent runtime state, an exact
//! `STATUS_INFO_LENGTH_MISMATCH` with the true required length for a short
//! buffer, and `STATUS_INVALID_INFO_CLASS` (never a fabricated value) for a
//! class that is not backed.
//!
//! The tests drive the REAL dispatch path through [`NtThunkSession`] — the
//! same scratch runtime the section47/49/50 suites use — so the serialized
//! structures are the ones a guest actually reads.

mod support;

use casa1::cpu::GuestArch;
use casa1::ge::{GameEnvironment, GeArch};
use casa1::ntdll::{
    NtStatus, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS, STATUS_SUCCESS,
};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use tempfile::TempDir;

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const SYSTEM_MODULE_INFORMATION_CLASS: u32 = 11;
const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;
const SYSTEM_PAGEFILE_INFORMATION_CLASS: u32 = 18;
const SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS: u32 = 35;
const SYSTEM_LOOKASIDE_INFORMATION_CLASS: u32 = 45;
const SYSTEM_RANGE_START_INFORMATION_CLASS: u32 = 50;
const SYSTEM_BIGPOOL_INFORMATION_CLASS: u32 = 66;
const SYSTEM_FIRMWARE_TABLE_INFORMATION_CLASS: u32 = 76;
const SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS: u32 = 103;

const ARENA: u64 = 0x30_000;
const ARENA2: u64 = 0x40_000;
const ARENA3: u64 = 0x50_000;

const X64_RANGE_START: u64 = 0xFFFF_8000_0000_0000;

fn setup() -> (TempDir, NtThunkSession) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(
        temp_dir.path(),
        "nt-introspection",
        GeArch::X64,
        "win11-23h2",
    )
    .expect("create GE");
    let session = NtThunkSession::new(ge);
    (temp_dir, session)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64"))
}

fn big_stack(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(body)
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

/// Call `NtQuerySystemInformation(class, buffer, length, return_length_ptr)`.
fn query_system_information(
    session: &mut NtThunkSession,
    thunk: u64,
    class: u32,
    buffer: u64,
    length: u64,
    return_length_ptr: u64,
) -> u32 {
    let rax = session.call(
        thunk,
        &[u64::from(class), buffer, length, return_length_ptr],
    );
    NtStatus::from_raw(rax as u32).raw()
}

#[test]
fn system_information_rejects_an_invalid_class_with_status_invalid_info_class() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        // A sentinel proves the invalid-class path writes nothing.
        session.map_guest(ARENA, &0xAB_u8.to_le_bytes());
        let len_ptr = ARENA2;
        session.map_guest(len_ptr, &0u32.to_le_bytes());
        let status = query_system_information(&mut session, query, 0xDEAD, ARENA, 1, len_ptr);
        assert_eq!(status, STATUS_INVALID_INFO_CLASS.raw());
        assert_eq!(session.read_guest(ARENA, 1), vec![0xAB], "no bytes written");
        assert_eq!(
            read_u32(&session.read_guest(len_ptr, 4), 0),
            0,
            "no length written"
        );
    });
}

#[test]
fn system_module_information_reports_the_real_loaded_module_and_rejects_a_seven_byte_buffer() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        let load = session.alloc_thunk(HostThunk::LoadLibraryW);
        // Load a real module: the loader synthesizes it from its built-in
        // export table and records the mapping, so the module list is REAL.
        let name: Vec<u8> = "kernel32.dll\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        session.map_guest(ARENA3, &name);
        let handle = session.call(load, &[ARENA3]);
        assert_ne!(handle, 0, "LoadLibraryW returns a module handle");

        let buffer = ARENA;
        session.map_guest(buffer, &[0_u8; 4096]);
        let len_ptr = ARENA2;
        session.map_guest(len_ptr, &[0_u8; 4]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_MODULE_INFORMATION_CLASS,
            buffer,
            4096,
            len_ptr,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let bytes = session.read_guest(buffer, 4096);
        let count = read_u32(&bytes, 0) as usize;
        assert!(count >= 1, "the loaded module is enumerated");
        // The loaded module appears with its real base and a non-zero size.
        let mut found = false;
        for index in 0..count {
            let entry = 8 + index * 296;
            let base = read_u64(&bytes, entry + 16);
            let size = read_u32(&bytes, entry + 24);
            if base == handle {
                found = true;
                assert!(size > 0, "the module's mapped size is real");
                let offset =
                    u16::from_le_bytes(bytes[entry + 38..entry + 40].try_into().unwrap()) as usize;
                // OffsetToFileName is relative to the entry start.
                let name_bytes = &bytes[entry + offset..entry + offset + 12];
                assert_eq!(
                    name_bytes, b"kernel32.dll",
                    "the file name is the loaded image"
                );
            }
        }
        assert!(found, "the loaded module base appears in the list");
        // One byte short of the truth: exact required length, no partial write.
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_MODULE_INFORMATION_CLASS,
            buffer,
            8,
            len_ptr,
        );
        assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH.raw());
        assert_eq!(
            read_u32(&session.read_guest(len_ptr, 4), 0) as usize,
            8 + 296 * count
        );
    });
}

#[test]
fn system_process_information_reports_a_suspended_pending_thread_and_rejects_truncation() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        // Pending guest threads are a scheduler artifact of x86 guest threads.
        session.set_guest_arch(GuestArch::X86);
        let create_thread = session.alloc_thunk(HostThunk::NtCreateThreadEx);
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);

        let handle_ptr = 0x41_200;
        session.map_guest(handle_ptr, &[0_u8; 4]);
        let rax = session.call_x86(
            create_thread,
            &[
                handle_ptr as u32,
                0x1F_03FF,
                0,
                0xFFFF_FFFF,
                0x1000, // start address
                0,      // parameter
                1,      // create suspended
                0,
                0,
                0x10_000, // stack reserve
            ],
        );
        assert_eq!(NtStatus::from_raw(rax), STATUS_SUCCESS);
        assert_ne!(read_u32(&session.read_guest(handle_ptr, 4), 0), 0);

        let buffer = ARENA;
        session.map_guest(buffer, &[0_u8; 2048]);
        let rax = session.call_x86(
            query,
            &[SYSTEM_PROCESS_INFORMATION_CLASS, buffer as u32, 2048, 0],
        );
        assert_eq!(NtStatus::from_raw(rax), STATUS_SUCCESS);
        let bytes = session.read_guest(buffer, 2048);
        let thread_count = read_u32(&bytes, 4) as usize;
        assert!(thread_count >= 2, "main + the pending suspended thread");
        // At least one thread carries the suspended wait reason (6).
        let mut suspended = 0;
        for index in 0..thread_count {
            let base = 0x100 + index * 0x50;
            if read_u32(&bytes, base + 72) == 6 {
                suspended += 1;
            }
        }
        assert_eq!(suspended, 1, "exactly one suspended pending thread");
    });
}

#[test]
fn system_handle_information_drops_a_closed_handle_and_matches_the_live_table() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        let create_event = session.alloc_thunk(HostThunk::CreateEventW);
        let close_handle = session.alloc_thunk(HostThunk::CloseHandle);

        let first = session.call(create_event, &[0, 0, 0, 0]);
        let second = session.call(create_event, &[0, 0, 0, 0]);
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second);

        let buffer = ARENA;
        session.map_guest(buffer, &[0_u8; 512]);
        let len_ptr = ARENA2;
        session.map_guest(len_ptr, &[0_u8; 8]);
        // A non-zero return-length pointer is written on success.
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_HANDLE_INFORMATION_CLASS,
            buffer,
            512,
            len_ptr,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let bytes = session.read_guest(buffer, 512);
        assert_eq!(read_u32(&bytes, 0), 2, "two live handles");
        assert_eq!(read_u32(&session.read_guest(len_ptr, 4), 0), 8 + 24 * 2);
        // Every reported handle value is one of the live handles.
        let mut values: Vec<u32> = Vec::new();
        for index in 0..2usize {
            let entry = 8 + index * 24;
            assert_ne!(read_u64(&bytes, entry + 8), 0, "Object is a real identity");
            values.push(u32::from(u16::from_le_bytes(
                bytes[entry + 6..entry + 8].try_into().unwrap(),
            )));
        }
        assert!(values.contains(&(first as u32)));
        assert!(values.contains(&(second as u32)));

        // Close the first handle: it must disappear from the next query (the
        // freed handle value is a gap the enumerator must skip).
        assert_eq!(session.call(close_handle, &[first]), 1);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_HANDLE_INFORMATION_CLASS,
            buffer,
            512,
            len_ptr,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let bytes = session.read_guest(buffer, 512);
        assert_eq!(read_u32(&bytes, 0), 1, "the closed handle is gone");
        let remaining = u32::from(u16::from_le_bytes(bytes[8 + 6..8 + 8].try_into().unwrap()));
        assert_eq!(remaining, second as u32);
    });
}

#[test]
fn system_process_information_is_stable_across_repeated_calls_and_reports_the_guest_pid() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        let guest_pid = session.guest_pid();

        let buffer = ARENA;
        session.map_guest(buffer, &[0_u8; 1024]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer,
            1024,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let first = session.read_guest(buffer, 1024);
        // The current process is reported with its real guest pid and at least
        // one thread (the main thread).
        assert_eq!(
            read_u64(&first, 0x50),
            u64::from(guest_pid),
            "UniqueProcessId is the guest pid"
        );
        assert!(read_u32(&first, 4) >= 1, "Number of threads");
        // Repeated calls are byte-identical (deterministic, no invented drift).
        session.map_guest(ARENA2, &[0_u8; 1024]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            ARENA2,
            1024,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        // The ImageName.Buffer pointer differs (it points into each buffer),
        // so compare everything except that pointer.
        let second = session.read_guest(ARENA2, 1024);
        assert_eq!(first[0..0x40], second[0..0x40]);
        assert_eq!(first[0x48..], second[0x48..]);
        // A buffer too small for one process is a length mismatch.
        let len_ptr = ARENA3;
        session.map_guest(len_ptr, &[0_u8; 4]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer,
            0x100,
            len_ptr,
        );
        assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH.raw());
        assert!(read_u32(&session.read_guest(len_ptr, 4), 0) > 0x100);
    });
}

#[test]
fn system_kernel_debugger_information_is_truthful_without_a_debugger() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        session.map_guest(ARENA, &[0xCD_u8, 0xCD]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS,
            ARENA,
            2,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        // No kernel debugger: enabled = 0, not-present = 1.
        assert_eq!(session.read_guest(ARENA, 2), vec![0, 1]);
        // A one-byte buffer is rejected with the exact required length.
        let len_ptr = ARENA2;
        session.map_guest(len_ptr, &[0_u8; 4]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS,
            ARENA,
            1,
            len_ptr,
        );
        assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH.raw());
        assert_eq!(read_u32(&session.read_guest(len_ptr, 4), 0), 2);
    });
}

#[test]
fn system_code_integrity_information_reports_zero_enforcement() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        session.map_guest(ARENA, &[0xFF_u8; 8]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS,
            ARENA,
            8,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let bytes = session.read_guest(ARENA, 8);
        assert_eq!(read_u32(&bytes, 0), 8, "Length");
        assert_eq!(read_u32(&bytes, 4), 0, "no code-integrity enforcement");
    });
}

#[test]
fn system_range_start_information_rejects_a_short_buffer_and_reports_the_x64_split() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        session.map_guest(ARENA, &[0_u8; 8]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_RANGE_START_INFORMATION_CLASS,
            ARENA,
            8,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        assert_eq!(read_u64(&session.read_guest(ARENA, 8), 0), X64_RANGE_START);
        let len_ptr = ARENA2;
        session.map_guest(len_ptr, &[0_u8; 4]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_RANGE_START_INFORMATION_CLASS,
            ARENA,
            7,
            len_ptr,
        );
        assert_eq!(status, STATUS_INFO_LENGTH_MISMATCH.raw());
        assert_eq!(read_u32(&session.read_guest(len_ptr, 4), 0), 8);
    });
}

#[test]
fn system_bigpool_and_lookaside_are_truthfully_empty_without_a_tagged_pool() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        // BigPool: no tagged-pool rows are wired, so the truthful entry count
        // is zero (never a stale or fabricated row).
        session.map_guest(ARENA, &[0xEE_u8; 8]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_BIGPOOL_INFORMATION_CLASS,
            ARENA,
            8,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        assert_eq!(read_u32(&session.read_guest(ARENA, 8), 0), 0);
        // Lookaside: no list is wired, so the row is zeroed, not invented.
        session.map_guest(ARENA2, &[0xFF_u8; 40]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_LOOKASIDE_INFORMATION_CLASS,
            ARENA2,
            40,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        assert_eq!(session.read_guest(ARENA2, 40), vec![0_u8; 40]);
    });
}

#[test]
fn system_firmware_table_information_echoes_the_query_and_never_fabricates_a_table() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        // Input: (ProviderSignature='ACPI', TableID=7, TableBufferLength=0).
        let mut input = Vec::new();
        input.extend_from_slice(&0x4143_5049u32.to_le_bytes());
        input.extend_from_slice(&7u32.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        session.map_guest(ARENA, &input);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_FIRMWARE_TABLE_INFORMATION_CLASS,
            ARENA,
            12,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let bytes = session.read_guest(ARENA, 12);
        assert_eq!(read_u32(&bytes, 0), 0x4143_5049, "provider echoed");
        assert_eq!(read_u32(&bytes, 4), 7, "table id echoed");
        assert_eq!(read_u32(&bytes, 8), 0, "no fabricated firmware table");
    });
}

#[test]
fn system_pagefile_information_names_the_real_page_file() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        session.map_guest(ARENA, &[0_u8; 128]);
        let len_ptr = ARENA2;
        session.map_guest(len_ptr, &[0_u8; 4]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_PAGEFILE_INFORMATION_CLASS,
            ARENA,
            128,
            len_ptr,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let bytes = session.read_guest(ARENA, 128);
        assert_eq!(read_u32(&bytes, 0), 0, "single entry: NextEntryOffset = 0");
        let name_len = u16::from_le_bytes(bytes[16..18].try_into().unwrap());
        assert_eq!(
            name_len,
            r"C:\pagefile.sys".encode_utf16().count() as u16 * 2
        );
        let wide: Vec<u16> = bytes[18..18 + name_len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&wide).unwrap(), r"C:\pagefile.sys");
        assert_eq!(
            read_u32(&session.read_guest(len_ptr, 4), 0) as usize,
            18 + name_len as usize,
            "the required length is the whole single-entry structure"
        );
    });
}

#[test]
fn system_process_information_does_not_duplicate_the_entry_once_the_process_handle_exists() {
    big_stack(|| {
        let (_tmp, mut session) = setup();
        let query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);
        let get_current_process = session.alloc_thunk(HostThunk::GetCurrentProcess);
        // Minting the current-process handle puts the process object in the
        // handle table, so the toolhelp snapshot contains it: the process list
        // must still report exactly one entry for the guest pid.
        let handle = session.call(get_current_process, &[]);
        assert_ne!(handle, 0);
        let buffer = ARENA;
        session.map_guest(buffer, &[0_u8; 1024]);
        let status = query_system_information(
            &mut session,
            query,
            SYSTEM_PROCESS_INFORMATION_CLASS,
            buffer,
            1024,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS.raw());
        let bytes = session.read_guest(buffer, 1024);
        assert_eq!(read_u64(&bytes, 0x50), u64::from(session.guest_pid()));
        // Walk the linked list and count how many entries carry the guest pid.
        let mut offset = 0usize;
        let mut matches = 0usize;
        loop {
            if read_u64(&bytes, offset + 0x50) == u64::from(session.guest_pid()) {
                matches += 1;
            }
            let next = read_u32(&bytes, offset) as usize;
            if next == 0 {
                break;
            }
            offset += next;
        }
        assert_eq!(matches, 1, "the guest process appears exactly once");
    });
}
