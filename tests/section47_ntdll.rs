//! Stage 4 — the NTDLL foundation: the native Windows API layer.
//!
//! The Nt* surface builds on the canonical layers: the single
//! [`crate::vm::VirtualMemory`] (the same address space the interpreter and
//! the JIT validate through), the live object/handle namespace of the
//! Win32 subsystem, the guest-process identity model (the GUEST pid — never
//! the host pid) and the guest scheduler's wait machinery.
//!
//! These tests drive the REAL dispatch path through the
//! [`crate::runtime::NtThunkSession`] scratch runtime (a thunk address per
//! API, x64 calling convention, canonical VM attached) and the pure
//! [`crate::ntdll`] layer functions.

mod support;

use casa1::ge::{GameEnvironment, GeArch};
use casa1::ntdll::KEY_VALUE_FULL_INFORMATION_CLASS;
use casa1::ntdll::registry::{
    HKEY_CURRENT_USER, nt_create_key, nt_query_value_key, nt_set_value_key,
};
use casa1::ntdll::sync::{nt_create_event, nt_set_event};
use casa1::ntdll::thread::{X64_CONTEXT_GPR_OFFSETS, X64_CONTEXT_RIP_OFFSET};
use casa1::ntdll::{
    NtStatus, STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_WAIT_0,
    dos_error_to_nt_status, nt_status_to_dos_error,
};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use casa1::vm::{VmProtection, VmState};
use casa1::win32::ObjectType;
use tempfile::TempDir;

fn setup_session() -> (TempDir, NtThunkSession) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), "ntdll-stage4", GeArch::X64, "win11-23h2")
        .expect("create GE");
    let session = NtThunkSession::new(ge);
    (temp_dir, session)
}

/// The scratch data arena addresses (mapped by the session).
const ARENA: u64 = 0x30_000;
const ARENA2: u64 = 0x40_000;
const ARENA3: u64 = 0x50_000;

#[test]
fn nt_allocate_virtual_memory_reserves_and_commits_through_the_canonical_vm() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let thunk = session.alloc_thunk(HostThunk::NtAllocateVirtualMemory);
            // BaseAddress + RegionSize in/out pointers in the arena.
            session.map_guest(ARENA, &[0_u8; 16]);
            let size_ptr = ARENA + 8;
            session.map_guest(size_ptr, &0x3000u64.to_le_bytes());
            let rax = session.call(
                thunk,
                &[
                    0xFFFF_FFFF, // process pseudo-handle
                    ARENA,       // BaseAddress in/out
                    0,           // ZeroBits
                    size_ptr,    // RegionSize in/out
                    0x3000,      // MEM_COMMIT | MEM_RESERVE
                    0x04,        // PAGE_READWRITE
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let base = u64::from_le_bytes(session.read_guest(ARENA, 8).try_into().unwrap());
            let size = u64::from_le_bytes(session.read_guest(size_ptr, 8).try_into().unwrap());
            assert_ne!(base, 0, "the canonical cursor picks the base");
            assert_eq!(base & 0xFFF, 0, "page-aligned");
            assert_eq!(size, 0x3000);

            // The canonical VM reflects the reservation + commitment.
            let query = session.vm().query(base);
            assert_eq!(query.state, VmState::Committed);
            assert_eq!(query.region_size, 0x3000);
            assert_eq!(query.protection, VmProtection::READ_WRITE);

            // NtQueryVirtualMemory reads the same canonical state back.
            let query_thunk = session.alloc_thunk(HostThunk::NtQueryVirtualMemory);
            let buffer = ARENA2;
            let rax = session.call(query_thunk, &[0xFFFF_FFFF, base, 0, buffer, 48, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let mbi = session.read_guest(buffer, 48);
            assert_eq!(u64::from_le_bytes(mbi[0..8].try_into().unwrap()), base);
            assert_eq!(u64::from_le_bytes(mbi[24..32].try_into().unwrap()), 0x3000);
            assert_eq!(
                u32::from_le_bytes(mbi[32..36].try_into().unwrap()),
                0x1000,
                "MEM_COMMIT"
            );
            assert_eq!(
                u32::from_le_bytes(mbi[36..40].try_into().unwrap()),
                0x04,
                "PAGE_READWRITE"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn nt_write_virtual_memory_to_unmapped_memory_returns_access_violation_and_never_creates_pages() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let write_thunk = session.alloc_thunk(HostThunk::NtWriteVirtualMemory);
            let bytes_written = ARENA2;
            let source = ARENA3;
            session.map_guest(source, b"hello world");
            let target = 0x7F00_0000_0000; // deep in unmapped space
            let rax = session.call(
                write_thunk,
                &[0xFFFF_FFFF, target, source, 11, bytes_written],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_ACCESS_VIOLATION);
            // Nothing was written and NO page was created.
            assert_eq!(
                u64::from_le_bytes(session.read_guest(bytes_written, 8).try_into().unwrap()),
                0,
                "no bytes written on fault"
            );
            assert_eq!(
                session.vm().query(target).state,
                VmState::Free,
                "the canonical VM still reports free memory — the write created no pages"
            );
            assert!(
                !session.vm().is_mapped(target),
                "the address is still unmapped"
            );
            // A mapped target succeeds and reports the transfer count.
            let mapped_target = session.alloc_thunk(HostThunk::NtAllocateVirtualMemory);
            let base_ptr = ARENA;
            let size_ptr = ARENA + 8;
            session.map_guest(ARENA, &[0_u8; 16]);
            session.map_guest(size_ptr, &0x1000u64.to_le_bytes());
            let rax = session.call(
                mapped_target,
                &[0xFFFF_FFFF, base_ptr, 0, size_ptr, 0x1000, 0x04],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let base = u64::from_le_bytes(session.read_guest(base_ptr, 8).try_into().unwrap());
            let rax = session.call(write_thunk, &[0xFFFF_FFFF, base, source, 11, bytes_written]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            assert_eq!(
                u64::from_le_bytes(session.read_guest(bytes_written, 8).try_into().unwrap()),
                11
            );
            assert_eq!(
                session.read_guest(base, 11),
                b"hello world".to_vec(),
                "the write landed"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn nt_create_event_wait_and_set_wake_the_waiter_via_the_scheduler() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let create_event = session.alloc_thunk(HostThunk::NtCreateEvent);
            let wait = session.alloc_thunk(HostThunk::NtWaitForSingleObject);
            let set_event = session.alloc_thunk(HostThunk::NtSetEvent);

            // Create an unsignaled auto-reset (synchronization) event.
            let handle_ptr = ARENA;
            session.map_guest(ARENA, &[0_u8; 4]);
            let rax = session.call(create_event, &[handle_ptr, 0x1F0003, 0, 1, 0]);
            assert_eq!(
                NtStatus::from_raw(rax as u32),
                STATUS_SUCCESS,
                "rax={rax:#x}"
            );
            let handle = u32::from_le_bytes(session.read_guest(handle_ptr, 4).try_into().unwrap());
            assert_ne!(handle, 0);
            assert_eq!(
                session.win32().handle_object_type(handle).unwrap(),
                ObjectType::Event,
                "the event lives in the shared object namespace"
            );

            // Zero-timeout wait on the unsignaled event: STATUS_TIMEOUT.
            let rax = session.call(wait, &[u64::from(handle), 0, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_TIMEOUT);

            // A finite wait parks the thread in the scheduler wait queue with a
            // wait descriptor (the dispatch epilogue parks; no result is produced).
            let _parked_rax = session.call(wait, &[u64::from(handle), 0, 10_000_000 /* 1 s */]);
            assert_eq!(
                session.parked_waiter_count(),
                1,
                "the waiter sits in the wait queue"
            );
            assert!(
                !session.parked_waiter_satisfiable(),
                "the unsignaled event cannot satisfy the wait"
            );

            // NtSetEvent signals the event: the scheduler readiness pass now sees
            // the parked waiter's descriptor as satisfiable — the pump would resume
            // it (wake the waiter) on its next cycle.
            let rax = session.call(set_event, &[u64::from(handle), 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            assert!(
                session.parked_waiter_satisfiable(),
                "the signaled event wakes the parked waiter via the scheduler"
            );

            // The consuming instant path reports STATUS_WAIT_0 and consumes the
            // auto-reset signal; the next zero-timeout wait times out again.
            let rax = session.call(wait, &[u64::from(handle), 0, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_WAIT_0);
            let rax = session.call(wait, &[u64::from(handle), 0, 0]);
            assert_eq!(
                NtStatus::from_raw(rax as u32),
                STATUS_TIMEOUT,
                "auto-reset consumed"
            );

            // The deadline path: a parked waiter with an expired deadline is
            // satisfiable (the pump would resume it with STATUS_TIMEOUT).  The
            // parked wait used a 1 s deadline, so the guest clock must pass it.
            session.advance_guest_clock(2000);
            assert!(
                session.parked_waiter_satisfiable(),
                "the expired deadline wakes the parked waiter"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn nt_close_on_an_invalid_handle_is_status_invalid_handle() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let close = session.alloc_thunk(HostThunk::NtClose);
            let rax = session.call(close, &[0x1234_5678]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_HANDLE);
            let rax = session.call(close, &[0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_HANDLE);

            // A live handle closes with STATUS_SUCCESS; a second close is invalid.
            let create_event = session.alloc_thunk(HostThunk::NtCreateEvent);
            let handle_ptr = ARENA;
            session.map_guest(ARENA, &[0_u8; 4]);
            let rax = session.call(create_event, &[handle_ptr, 0x1F0003, 0, 0, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let handle = u32::from_le_bytes(session.read_guest(handle_ptr, 4).try_into().unwrap());
            let rax = session.call(close, &[u64::from(handle)]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let rax = session.call(close, &[u64::from(handle)]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_HANDLE);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn nt_query_information_process_reports_the_guest_pid_never_the_host_pid() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let query = session.alloc_thunk(HostThunk::NtQueryInformationProcess);
            let buffer = ARENA;
            session.map_guest(ARENA, &[0_u8; 64]);
            let return_length = ARENA + 48;
            let rax = session.call(
                query,
                &[
                    0xFFFF_FFFF,
                    0, /* ProcessBasicInformation */
                    buffer,
                    64,
                    return_length,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let info = session.read_guest(buffer, 48);
            // ExitStatus = STATUS_PENDING, PebBaseAddress = the guest PEB base.
            assert_eq!(u32::from_le_bytes(info[0..4].try_into().unwrap()), 0x103);
            // UniqueProcessId at 0x20 — the GUEST pid.
            let pid = u64::from_le_bytes(info[32..40].try_into().unwrap());
            assert_eq!(pid, u64::from(session.guest_pid()));
            assert_ne!(pid, u64::from(std::process::id()), "never the host pid");
            assert!(pid >= 4, "the guest pid namespace starts at 4");
            // The returned length is the canonical 48-byte x64 structure.
            assert_eq!(
                u32::from_le_bytes(session.read_guest(return_length, 4).try_into().unwrap()),
                48
            );
            // An undersized buffer reports STATUS_INFO_LENGTH_MISMATCH.
            let rax = session.call(query, &[0xFFFF_FFFF, 0, buffer, 16, 0]);
            assert_eq!(
                NtStatus::from_raw(rax as u32),
                casa1::ntdll::STATUS_INFO_LENGTH_MISMATCH
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn nt_set_value_key_and_nt_query_value_key_round_trip_through_the_registry_store() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let create_key = session.alloc_thunk(HostThunk::NtCreateKey);
            let set_value = session.alloc_thunk(HostThunk::NtSetValueKey);
            let query_value = session.alloc_thunk(HostThunk::NtQueryValueKey);

            // NtCreateKey under HKCU with the OBJECT_ATTRIBUTES name.
            let name = "Software\\Casa1Stage4";
            let wide: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let name_buf = ARENA2;
            session.map_guest(name_buf, &wide);
            // UNICODE_STRING header at ARENA: Length, MaximumLength, Buffer.
            session.map_guest(ARENA, &[0_u8; 16]);
            session.map_guest(ARENA, &(wide.len() as u16).to_le_bytes());
            session.map_guest(ARENA + 2, &((wide.len() + 2) as u16).to_le_bytes());
            session.map_guest(ARENA + 8, &name_buf.to_le_bytes());
            // OBJECT_ATTRIBUTES at ARENA3 with ObjectName at +16 (x64).
            let attrs = ARENA3;
            session.map_guest(attrs, &[0_u8; 48]);
            session.map_guest(attrs + 16, &ARENA.to_le_bytes());

            let handle_ptr = 0x60_000;
            let disposition_ptr = 0x60_004;
            session.map_guest(handle_ptr, &[0_u8; 8]);
            let rax = session.call(
                create_key,
                &[handle_ptr, 0x20019, attrs, 0, 0, 0, 0, disposition_ptr],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let key_handle =
                u32::from_le_bytes(session.read_guest(handle_ptr, 4).try_into().unwrap());
            assert_eq!(
                u32::from_le_bytes(session.read_guest(disposition_ptr, 4).try_into().unwrap()),
                1,
                "REG_CREATED_NEW_KEY"
            );

            // NtSetValueKey: "Greeting" = REG_SZ "hello".
            let value_wide: Vec<u8> = "Greeting"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            let value_name_buf = 0x61_000;
            session.map_guest(value_name_buf, &value_wide);
            session.map_guest(0x61_020, &[0_u8; 16]);
            session.map_guest(0x61_020, &(value_wide.len() as u16).to_le_bytes());
            session.map_guest(0x61_022, &((value_wide.len() + 2) as u16).to_le_bytes());
            session.map_guest(0x61_028, &value_name_buf.to_le_bytes());
            let data_buf = 0x62_000;
            let mut data = "hello"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<_>>();
            data.extend_from_slice(&0u16.to_le_bytes());
            session.map_guest(data_buf, &data);
            let rax = session.call(
                set_value,
                &[
                    u64::from(key_handle),
                    0x61_020, // value-name UNICODE_STRING
                    0,        // TitleIndex
                    1,        // REG_SZ
                    data_buf,
                    data.len() as u64,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);

            // The value is visible through the WIN32 registry APIs too — ONE store.
            let (hive, key_path, view) = {
                let win32 = session.win32();
                let (hive, key_path, view) =
                    casa1::ntdll::registry::key_handle_target(win32, key_handle, true)
                        .expect("key target");
                (hive, key_path, view)
            };
            let stored = session
                .win32()
                .registry_get_value(&hive, &key_path, "Greeting", view)
                .expect("get value")
                .expect("value exists");
            assert_eq!(stored.value_type, "REG_SZ");
            assert_eq!(stored.data.as_str(), Some("hello"));

            // NtQueryValueKey (KeyValueFullInformation) reads it back.
            let query_buffer = 0x63_000;
            session.map_guest(query_buffer, &[0_u8; 256]);
            let result_length = 0x63_100;
            session.map_guest(result_length, &[0_u8; 8]);
            let rax = session.call(
                query_value,
                &[
                    u64::from(key_handle),
                    0x61_020, // value-name UNICODE_STRING
                    KEY_VALUE_FULL_INFORMATION_CLASS as u64,
                    query_buffer,
                    256,
                    result_length,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let body = session.read_guest(query_buffer, 128);
            assert_eq!(
                u32::from_le_bytes(body[4..8].try_into().unwrap()),
                1,
                "REG_SZ"
            );
            let data_offset = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
            let data_len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
            assert_eq!(
                &body[data_offset..data_offset + data_len],
                b"h\0e\0l\0l\0o\0\0\0"
            );

            // A missing value is STATUS_OBJECT_NAME_NOT_FOUND.
            let missing_name: Vec<u8> = "Absent"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            session.map_guest(0x64_000, &missing_name);
            session.map_guest(0x64_020, &[0_u8; 16]);
            session.map_guest(0x64_020, &(missing_name.len() as u16).to_le_bytes());
            session.map_guest(0x64_022, &((missing_name.len() + 2) as u16).to_le_bytes());
            session.map_guest(0x64_028, &0x64_000u64.to_le_bytes());
            let rax = session.call(
                query_value,
                &[
                    u64::from(key_handle),
                    0x64_020,
                    KEY_VALUE_FULL_INFORMATION_CLASS as u64,
                    query_buffer,
                    256,
                    result_length,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_OBJECT_NAME_NOT_FOUND);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn ntstatus_mapping_functions_round_trip_known_values() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // The canonical NTSTATUS → DOS mapping.
            assert_eq!(nt_status_to_dos_error(STATUS_SUCCESS), 0);
            assert_eq!(nt_status_to_dos_error(STATUS_INVALID_HANDLE), 6);
            assert_eq!(nt_status_to_dos_error(STATUS_ACCESS_VIOLATION), 998);
            assert_eq!(nt_status_to_dos_error(STATUS_INVALID_PARAMETER), 87);
            // The reverse mapping round-trips the subset used by the Nt layer.
            assert_eq!(dos_error_to_nt_status(6), STATUS_INVALID_HANDLE);
            assert_eq!(
                dos_error_to_nt_status(5),
                casa1::ntdll::STATUS_ACCESS_DENIED
            );
            assert_eq!(dos_error_to_nt_status(87), STATUS_INVALID_PARAMETER);
            assert_eq!(
                dos_error_to_nt_status(2),
                casa1::ntdll::STATUS_OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(dos_error_to_nt_status(1460), STATUS_TIMEOUT);
            // The full round trip through both legs is stable for the used subset.
            for (status, dos) in [
                (STATUS_SUCCESS, 0),
                (STATUS_INVALID_HANDLE, 6),
                (casa1::ntdll::STATUS_ACCESS_DENIED, 5),
                (STATUS_INVALID_PARAMETER, 87),
                (STATUS_TIMEOUT, 1460),
                (STATUS_ACCESS_VIOLATION, 998),
                (casa1::ntdll::STATUS_OBJECT_NAME_NOT_FOUND, 2),
            ] {
                assert_eq!(nt_status_to_dos_error(status), dos);
                assert_eq!(dos_error_to_nt_status(dos), status);
            }
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn rtl_and_native_helpers_exercise_the_canonical_layouts() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // The x64 CONTEXT GPR offsets follow the canonical winnt.h layout.
            assert_eq!(X64_CONTEXT_GPR_OFFSETS[0], 0x20); // Rax
            assert_eq!(X64_CONTEXT_GPR_OFFSETS[4], 0x40); // Rsp
            assert_eq!(X64_CONTEXT_GPR_OFFSETS[15], 0x98); // R15
            assert_eq!(X64_CONTEXT_RIP_OFFSET, 0xA0);
            // The pure sync layer round-trips through the shared event namespace.
            let (_tmp, mut session) = setup_session();
            let (handle, _) = nt_create_event(
                session.win32_mut(),
                casa1::ntdll::EVENT_TYPE_SYNCHRONIZATION,
                false,
                None,
            )
            .expect("create event");
            assert_eq!(nt_set_event(session.win32_mut(), handle), Ok(false));
            assert_eq!(nt_set_event(session.win32_mut(), handle), Ok(true));
            // The registry layer round-trips through the shared store.
            let (handle, _) = nt_create_key(
                session.win32_mut(),
                HKEY_CURRENT_USER,
                "Software\\Casa1Stage4Direct",
                0x20019,
                true,
            )
            .expect("create key");
            let mut data = "direct"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<_>>();
            data.extend_from_slice(&0u16.to_le_bytes());
            assert_eq!(
                nt_set_value_key(
                    session.win32_mut(),
                    handle,
                    "K",
                    casa1::ntdll::REG_SZ,
                    &data
                ),
                STATUS_SUCCESS
            );
            let (body, _, too_small) = nt_query_value_key(
                session.win32(),
                handle,
                "K",
                KEY_VALUE_FULL_INFORMATION_CLASS,
                4096,
            )
            .expect("query");
            assert!(!too_small);
            let data_offset = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
            let data_len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
            assert_eq!(
                &body[data_offset..data_offset + data_len],
                b"d\0i\0r\0e\0c\0t\0\0\0"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}
