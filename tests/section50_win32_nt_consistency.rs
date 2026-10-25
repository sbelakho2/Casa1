#![allow(dead_code, unused_imports)]
//! Stage 5 — the Win32-over-Nt layering audit: ONE semantic implementation
//! per Win32/Nt pair.
//!
//! Every test drives BOTH surfaces of one pair through the REAL dispatch
//! path ([`crate::runtime::NtThunkSession`], the same scratch runtime the
//! section47/49 tests use) and verifies they read/write the SAME canonical
//! state:
//!
//!  1. VM        — VirtualAlloc/Free/Query ↔ Nt*VirtualMemory
//!  2. Clocks    — GetTickCount/GetSystemTimeAsFileTime ↔ NtQuerySystemTime
//!  3. Topology  — GetSystemInfo ↔ NtQuerySystemInformation
//!  4. Version   — GetVersionExW ↔ RtlGetVersion
//!  5. Objects   — SetHandleInformation/DuplicateHandle/CloseHandle
//!     ↔ NtQueryObject/NtDuplicateObject/NtClose
//!  6. Sync      — CreateEventW/SetEvent/WaitForSingleObject
//!     ↔ NtWaitForSingleObject/NtSetEvent
//!  7. Threads   — SuspendThread/ResumeThread/SetThreadPriority
//!     ↔ NtSuspendThread/NtResumeThread/NtSetInformationThread
//!  8. Processes — GetCurrentProcessId ↔ NtQueryInformationProcess
//!  9. Registry  — RegSetValueExW/RegQueryValueExW ↔ NtSetValueKey/NtQueryValueKey
//! 10. Files     — CreateFileW ↔ NtCreateFile
//! 11. Sections  — CreateFileMappingW/MapViewOfFile ↔ NtCreateSection/NtQuerySection
//! 12. Errors    — nt_status_to_dos_error ↔ dos_error_to_nt_status round trips
//! 13. Time      — NtQuerySystemTime ↔ GetSystemTimeAsFileTime; timer domain

mod support;

use casa1::cpu::GuestArch;
use casa1::ge::{GameEnvironment, GeArch};
use casa1::ntdll::{
    NtStatus, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS, STATUS_TIMEOUT,
    STATUS_WAIT_0, dos_error_to_nt_status, nt_status_to_dos_error,
};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use casa1::vm::{VmProtection, VmState};
use tempfile::TempDir;

fn setup_session() -> (TempDir, NtThunkSession) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(
        temp_dir.path(),
        "win32-nt-layering",
        GeArch::X64,
        "win11-23h2",
    )
    .expect("create GE");
    let session = NtThunkSession::new(ge);
    (temp_dir, session)
}

const ARENA: u64 = 0x30_000;
const ARENA2: u64 = 0x40_000;
const ARENA3: u64 = 0x50_000;

const MEM_COMMIT_RESERVE: u32 = 0x3000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const MEM_RELEASE: u32 = 0x8000;
const MEM_COMMIT_STATE: u32 = 0x1000;
const OBJ_INHERIT: u32 = 0x0000_0002;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
const HANDLE_FLAG_PROTECT_FROM_CLOSE: u32 = 0x0000_0002;
const HKEY_CURRENT_USER: u32 = 0x8000_0001;
const KEY_READ: u32 = 0x20019;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const KEY_VALUE_FULL_INFORMATION_CLASS: u32 = 1;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_ALL: u32 = 7;
const CREATE_ALWAYS: u32 = 2;
const FILE_OPEN: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const OBJECT_BASIC_INFORMATION_CLASS: u32 = 0;
const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32"))
}

// ── 1. VM: VirtualAlloc/VirtualFree/VirtualQuery ↔ Nt*VirtualMemory ────────

#[test]
fn virtual_alloc_and_nt_query_virtual_memory_share_one_vm() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let alloc = session.alloc_thunk(HostThunk::VirtualAlloc);
            let nt_query = session.alloc_thunk(HostThunk::NtQueryVirtualMemory);
            let nt_alloc = session.alloc_thunk(HostThunk::NtAllocateVirtualMemory);
            let virtual_free = session.alloc_thunk(HostThunk::VirtualFree);
            let nt_free = session.alloc_thunk(HostThunk::NtFreeVirtualMemory);
            let virtual_query = session.alloc_thunk(HostThunk::VirtualQuery);

            // Win32 VirtualAlloc with PAGE_READONLY: the committed pages carry the
            // REQUESTED protection (the same conversion the Nt surface uses).
            let base = session.call(
                alloc,
                &[0, 0x3000, MEM_COMMIT_RESERVE as u64, PAGE_READONLY as u64],
            );
            assert_ne!(base, 0);
            let query = session.vm().query(base);
            assert_eq!(query.state, VmState::Committed);
            assert_eq!(
                query.protection,
                VmProtection::READ,
                "requested protection honored"
            );

            // NtQueryVirtualMemory reports the SAME region NtAllocateVirtualMemory
            // would create — the Win32-allocated region is fully visible on the Nt
            // surface.
            let buffer = ARENA;
            session.map_guest(buffer, &[0_u8; 48]);
            let rax = session.call(nt_query, &[0xFFFF_FFFF, base, 0, buffer, 48, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let mbi = session.read_guest(buffer, 48);
            assert_eq!(read_u64(&mbi, 0), base, "BaseAddress");
            assert_eq!(read_u64(&mbi, 24), 0x3000, "RegionSize");
            assert_eq!(read_u32(&mbi, 32), MEM_COMMIT_STATE, "State = MEM_COMMIT");
            assert_eq!(read_u32(&mbi, 36), PAGE_READONLY, "Protect = PAGE_READONLY");

            // The Win32 VirtualQuery reports the identical canonical run.
            let rax = session.call(virtual_query, &[base, buffer, 48]);
            assert_eq!(rax, 48);
            let win32_mbi = session.read_guest(buffer, 48);
            assert_eq!(read_u64(&win32_mbi, 0), read_u64(&mbi, 0));
            assert_eq!(read_u64(&win32_mbi, 24), read_u64(&mbi, 24));
            assert_eq!(read_u32(&win32_mbi, 32), read_u32(&mbi, 32));
            assert_eq!(read_u32(&win32_mbi, 36), read_u32(&mbi, 36));

            // A region created on the NT surface frees through the Win32 thunk and
            // vice versa — one canonical address space.
            let size_ptr = ARENA2;
            session.map_guest(size_ptr, &0x2000u64.to_le_bytes());
            let nt_base_ptr = ARENA2 + 8;
            session.map_guest(nt_base_ptr, &[0_u8; 8]);
            let rax = session.call(
                nt_alloc,
                &[
                    0xFFFF_FFFF,
                    nt_base_ptr,
                    0,
                    size_ptr,
                    MEM_COMMIT_RESERVE as u64,
                    PAGE_READWRITE as u64,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let nt_base = read_u64(&session.read_guest(nt_base_ptr, 8), 0);
            let rax = session.call(virtual_free, &[nt_base, 0, MEM_RELEASE as u64]);
            assert_eq!(rax, 1, "VirtualFree releases the Nt-allocated region");
            assert_eq!(session.vm().query(nt_base).state, VmState::Free);

            // NtFreeVirtualMemory releases the Win32-allocated region (the base is
            // passed through the in/out pointer, Windows-style).
            session.map_guest(ARENA3, &base.to_le_bytes());
            let rax = session.call(nt_free, &[0xFFFF_FFFF, ARENA3, 0, MEM_RELEASE as u64]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            assert_eq!(
                session.vm().query(base).state,
                VmState::Free,
                "NtFreeVirtualMemory releases the Win32-allocated region"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 2. Clocks: GetTickCount/GetSystemTimeAsFileTime ↔ NtQuerySystemTime ───

// ── 3. Topology: GetSystemInfo ↔ NtQuerySystemInformation ──────────────────

#[test]
fn system_info_topology_equals_nt_query_system_information() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let get_system_info = session.alloc_thunk(HostThunk::GetSystemInfo);
            let nt_query = session.alloc_thunk(HostThunk::NtQuerySystemInformation);

            // SYSTEM_INFO (x64): dwNumberOfProcessors at +0x20, the active
            // processor mask at +0x18.
            let info = ARENA;
            session.map_guest(info, &[0_u8; 64]);
            session.call(get_system_info, &[info]);
            let win32_nprocs = read_u32(&session.read_guest(info, 64), 0x20);
            let win32_mask = read_u64(&session.read_guest(info, 64), 0x18);
            assert_eq!(win32_nprocs, 8, "the configured topology is 8 processors");
            assert_eq!(win32_mask, 0xFF, "the active processor mask is 0xFF");

            // SYSTEM_BASIC_INFORMATION: NumberOfProcessors at +8 (+24/+60/+96).
            let nt_buffer = ARENA2;
            session.map_guest(nt_buffer, &[0_u8; 100]);
            let rax = session.call(
                nt_query,
                &[SYSTEM_BASIC_INFORMATION_CLASS as u64, nt_buffer, 100, 0],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let basic = session.read_guest(nt_buffer, 100);
            assert_eq!(
                read_u32(&basic, 8),
                win32_nprocs,
                "the Nt serializer reports the same processor count as GetSystemInfo"
            );
            assert_eq!(read_u32(&basic, 24), win32_nprocs);
            assert_eq!(read_u32(&basic, 60), win32_nprocs);
            assert_eq!(read_u32(&basic, 96), win32_nprocs);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 4. Version: GetVersionExW ↔ RtlGetVersion ──────────────────────────────

#[test]
fn get_version_ex_w_and_rtl_get_version_report_the_same_version() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let get_version_ex = session.alloc_thunk(HostThunk::GetVersionExW);
            let rtl_get_version = session.alloc_thunk(HostThunk::RtlGetVersion);

            // OSVERSIONINFOEXW: dwOSVersionInfoSize at +0; the version fields at
            // +4/+8/+0xC/+0x10; wServicePackMajor at +0x114; wProductType at +0x11A.
            let win32_buf = ARENA;
            session.map_guest(win32_buf, &0x11Cu32.to_le_bytes());
            let rax = session.call(get_version_ex, &[win32_buf]);
            assert_eq!(rax, 1, "GetVersionExW succeeds");

            let rtl_buf = ARENA2;
            session.map_guest(rtl_buf, &[0_u8; 0x11C]);
            let rax = session.call(rtl_get_version, &[rtl_buf]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);

            let win32 = session.read_guest(win32_buf, 0x11C);
            let rtl = session.read_guest(rtl_buf, 0x11C);
            for offset in [4, 8, 12, 16] {
                assert_eq!(
                    read_u32(&rtl, offset),
                    read_u32(&win32, offset),
                    "version field at +0x{offset:x} agrees"
                );
            }
            assert_eq!(
                u16::from_le_bytes(rtl[0x114..0x116].try_into().unwrap()),
                u16::from_le_bytes(win32[0x114..0x116].try_into().unwrap()),
                "wServicePackMajor agrees"
            );
            assert_eq!(rtl[0x11A], win32[0x11A], "wProductType agrees");
            assert!(
                read_u32(&rtl, 4) >= 10,
                "the win11-23h2 profile reports a 10.x version"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 5. Objects: handle flags/duplication/close ↔ NtQueryObject/Nt* ────────

#[test]
fn handle_information_duplication_and_close_share_the_handle_table() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let create_event = session.alloc_thunk(HostThunk::CreateEventW);
            let set_handle_info = session.alloc_thunk(HostThunk::SetHandleInformation);
            let nt_query_object = session.alloc_thunk(HostThunk::NtQueryObject);
            let nt_duplicate = session.alloc_thunk(HostThunk::NtDuplicateObject);
            let close_handle = session.alloc_thunk(HostThunk::CloseHandle);
            let nt_close = session.alloc_thunk(HostThunk::NtClose);
            let get_current_process = session.alloc_thunk(HostThunk::GetCurrentProcess);

            let handle_ptr = ARENA;
            session.map_guest(handle_ptr, &[0_u8; 4]);
            let rax = session.call(create_event, &[0, 0, 0, 0]);
            let handle = rax as u32;
            assert_ne!(handle, 0);

            // SetHandleInformation (Win32) flips the inheritable flag; NtQueryObject
            // (ObjectBasicInformation) reads it from the SAME handle-table entry.
            let rax = session.call(
                set_handle_info,
                &[
                    handle as u64,
                    HANDLE_FLAG_INHERIT as u64,
                    HANDLE_FLAG_INHERIT as u64,
                ],
            );
            assert_eq!(rax, 1);
            let obj_buf = ARENA2;
            session.map_guest(obj_buf, &[0_u8; 40]);
            let rax = session.call(
                nt_query_object,
                &[
                    handle as u64,
                    OBJECT_BASIC_INFORMATION_CLASS as u64,
                    obj_buf,
                    40,
                    0,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let basic = session.read_guest(obj_buf, 40);
            assert_eq!(
                read_u32(&basic, 0),
                OBJ_INHERIT,
                "NtQueryObject reports the Win32-set inheritable flag"
            );

            // NtDuplicateObject mints a duplicate in the same table; the Win32
            // CloseHandle closes it.
            let process_handle = session.call(get_current_process, &[]) as u32;
            let dup_ptr = ARENA3;
            session.map_guest(dup_ptr, &[0_u8; 4]);
            let rax = session.call(
                nt_duplicate,
                &[
                    process_handle as u64,
                    handle as u64,
                    process_handle as u64,
                    dup_ptr,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS as u64,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let duplicated = read_u32(&session.read_guest(dup_ptr, 4), 0);
            assert_ne!(duplicated, handle);
            assert_eq!(session.call(close_handle, &[duplicated as u64]), 1);

            // Close protection set through the Win32 thunk is enforced by NtClose.
            let rax = session.call(
                set_handle_info,
                &[
                    handle as u64,
                    HANDLE_FLAG_PROTECT_FROM_CLOSE as u64,
                    HANDLE_FLAG_PROTECT_FROM_CLOSE as u64,
                ],
            );
            assert_eq!(rax, 1);
            let rax = session.call(nt_close, &[handle as u64]);
            assert_eq!(
                NtStatus::from_raw(rax as u32),
                STATUS_ACCESS_DENIED,
                "a close-protected handle is refused by NtClose"
            );
            // Clearing the protection lets NtClose through.
            let rax = session.call(
                set_handle_info,
                &[handle as u64, HANDLE_FLAG_PROTECT_FROM_CLOSE as u64, 0],
            );
            assert_eq!(rax, 1);
            let rax = session.call(nt_close, &[handle as u64]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 6. Sync: events and auto-reset consumption across both surfaces ────────

#[test]
fn event_wait_signal_and_auto_reset_consumption_are_shared() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let create_event = session.alloc_thunk(HostThunk::CreateEventW);
            let set_event = session.alloc_thunk(HostThunk::SetEvent);
            let nt_set_event = session.alloc_thunk(HostThunk::NtSetEvent);
            let nt_wait = session.alloc_thunk(HostThunk::NtWaitForSingleObject);
            let win32_wait = session.alloc_thunk(HostThunk::WaitForSingleObject);

            // Win32 CreateEventW: auto-reset (manual_reset=0), initially unsignaled.
            let handle = session.call(create_event, &[0, 0, 0, 0]) as u32;
            assert_ne!(handle, 0);

            // An Nt wait on the Win32-created event times out while unsignaled.
            let rax = session.call(nt_wait, &[handle as u64, 0, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_TIMEOUT);

            // Win32 SetEvent signals; the Nt wait consumes the auto-reset signal.
            assert_eq!(session.call(set_event, &[handle as u64]), 1);
            let rax = session.call(nt_wait, &[handle as u64, 0, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_WAIT_0);

            // The consumption is visible to the Win32 surface: a zero-timeout
            // WaitForSingleObject now times out.
            let rax = session.call(win32_wait, &[handle as u64, 0]);
            assert_eq!(
                rax, 0x102,
                "WAIT_TIMEOUT — the auto-reset signal was consumed"
            );

            // Win32 wait consumes a signal set through NtSetEvent.
            let rax = session.call(nt_set_event, &[handle as u64, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let rax = session.call(win32_wait, &[handle as u64, 0]);
            assert_eq!(
                rax, 0,
                "WAIT_OBJECT_0 — the Nt-set signal wakes the Win32 wait"
            );
            let rax = session.call(nt_wait, &[handle as u64, 0, 0]);
            assert_eq!(
                NtStatus::from_raw(rax as u32),
                STATUS_TIMEOUT,
                "the Nt surface sees the auto-reset signal consumed by the Win32 wait"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 7. Threads: suspend/resume and priority — one thread state ─────────────

#[test]
fn suspend_resume_and_priority_surfaces_share_one_thread_state() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            session.set_guest_arch(GuestArch::X86);
            let create_thread = session.alloc_thunk(HostThunk::CreateThread);
            let suspend_thread = session.alloc_thunk(HostThunk::SuspendThread);
            let resume_thread = session.alloc_thunk(HostThunk::ResumeThread);
            let nt_suspend = session.alloc_thunk(HostThunk::NtSuspendThread);
            let nt_resume = session.alloc_thunk(HostThunk::NtResumeThread);
            let nt_query = session.alloc_thunk(HostThunk::NtQueryInformationThread);
            let nt_set_info = session.alloc_thunk(HostThunk::NtSetInformationThread);
            let set_priority = session.alloc_thunk(HostThunk::SetThreadPriority);
            let get_priority = session.alloc_thunk(HostThunk::GetThreadPriority);

            // Create a thread (the subsystem thread state + handle; x86 guest).
            let thread_id_ptr = 0x41_200;
            session.map_guest(thread_id_ptr, &[0_u8; 4]);
            let handle =
                session.call_x86(create_thread, &[0, 0, 0x1000, 0, 0, thread_id_ptr as u32]);
            assert_ne!(handle, 0);
            let thread_id = read_u32(&session.read_guest(thread_id_ptr, 4), 0);

            // Win32 suspend → previous 0; the subsystem counter is 1.
            assert_eq!(session.call_x86(suspend_thread, &[handle]), 0);
            assert_eq!(
                session
                    .win32()
                    .thread_suspend_count(thread_id)
                    .expect("count"),
                1
            );
            // NtResumeThread on the SAME thread returns the true previous count and
            // decrements the ONE counter.
            let prev_ptr = 0x41_300;
            session.map_guest(prev_ptr, &[0_u8; 4]);
            let rax = session.call_x86(nt_resume, &[handle, prev_ptr as u32]);
            assert_eq!(NtStatus::from_raw(rax), STATUS_SUCCESS);
            assert_eq!(
                read_u32(&session.read_guest(prev_ptr, 4), 0),
                1,
                "NtResumeThread reports the previous count the Win32 suspend set"
            );
            assert_eq!(
                session
                    .win32()
                    .thread_suspend_count(thread_id)
                    .expect("count"),
                0
            );
            // The Nt query surface sees the same counter.
            let out_ptr = 0x41_400;
            session.map_guest(out_ptr, &[0_u8; 32]);
            let rax = session.call_x86(
                nt_query,
                &[
                    handle,
                    casa1::ntdll::THREAD_SUSPEND_COUNT_CLASS,
                    out_ptr as u32,
                    32,
                    0,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax), STATUS_SUCCESS);
            assert_eq!(read_u32(&session.read_guest(out_ptr, 32), 0), 0);

            // NtSuspendThread → previous 0; Win32 ResumeThread → previous 1.
            session.map_guest(prev_ptr, &[0_u8; 4]);
            let rax = session.call_x86(nt_suspend, &[handle, prev_ptr as u32]);
            assert_eq!(NtStatus::from_raw(rax), STATUS_SUCCESS);
            assert_eq!(read_u32(&session.read_guest(prev_ptr, 4), 0), 0);
            assert_eq!(session.call_x86(resume_thread, &[handle]), 1);

            // Priority: the Win32 SetThreadPriority routes into the subsystem
            // priority domain the Nt query/set surfaces read and write.
            assert_eq!(session.call_x86(set_priority, &[handle, 5]), 1);
            assert_eq!(
                session.call_x86(get_priority, &[handle]),
                5,
                "GetThreadPriority reads back the Win32-set priority"
            );
            session.map_guest(out_ptr, &[0_u8; 32]);
            let rax = session.call_x86(
                nt_query,
                &[
                    handle,
                    casa1::ntdll::THREAD_PRIORITY_CLASS,
                    out_ptr as u32,
                    32,
                    0,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax), STATUS_SUCCESS);
            assert_eq!(
                read_u32(&session.read_guest(out_ptr, 32), 0),
                5,
                "NtQueryInformationThread(ThreadPriority) agrees with the Win32 pair"
            );
            session.map_guest(out_ptr, &7_i32.to_le_bytes());
            let rax = session.call_x86(
                nt_set_info,
                &[
                    handle,
                    casa1::ntdll::THREAD_PRIORITY_CLASS,
                    out_ptr as u32,
                    4,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax), STATUS_SUCCESS);
            assert_eq!(
                session.call_x86(get_priority, &[handle]),
                7,
                "the Win32 GetThreadPriority reads the Nt-set priority"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 8. Processes: GetCurrentProcessId ↔ NtQueryInformationProcess ──────────

#[test]
fn current_process_id_and_nt_query_information_process_share_the_guest_pid() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let get_pid = session.alloc_thunk(HostThunk::GetCurrentProcessId);
            let get_process = session.alloc_thunk(HostThunk::GetCurrentProcess);
            let nt_query = session.alloc_thunk(HostThunk::NtQueryInformationProcess);

            let win32_pid = session.call(get_pid, &[]) as u32;
            assert_ne!(win32_pid, 0);

            let buffer = ARENA;
            session.map_guest(buffer, &[0_u8; 64]);
            let rax = session.call(nt_query, &[0xFFFF_FFFF, 0, buffer, 64, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let basic = session.read_guest(buffer, 48);
            let nt_pid = read_u64(&basic, 0x20) as u32;
            assert_eq!(
                nt_pid, win32_pid,
                "NtQueryInformationProcess reports the Win32 current pid"
            );
            assert_ne!(nt_pid, std::process::id(), "never the host pid");
            assert!(nt_pid >= 4, "the guest pid namespace starts at 4");

            // The same answer through the GetCurrentProcess handle.
            let handle = session.call(get_process, &[]) as u32;
            let rax = session.call(nt_query, &[handle as u64, 0, buffer, 64, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let basic = session.read_guest(buffer, 48);
            assert_eq!(read_u64(&basic, 0x20) as u32, win32_pid);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 9. Registry: Reg* ↔ Nt*Key over the ONE backing store ─────────────────

#[test]
fn reg_set_value_ex_w_and_nt_query_value_key_share_the_registry_store() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let reg_create = session.alloc_thunk(HostThunk::RegCreateKeyExW);
            let reg_set = session.alloc_thunk(HostThunk::RegSetValueExW);
            let reg_query = session.alloc_thunk(HostThunk::RegQueryValueExW);
            let nt_query_value = session.alloc_thunk(HostThunk::NtQueryValueKey);
            let nt_set_value = session.alloc_thunk(HostThunk::NtSetValueKey);

            // RegCreateKeyExW under HKCU.
            let subkey_wide: Vec<u8> = "Software\\Casa1Section50"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect();
            let subkey_ptr = ARENA;
            session.map_guest(subkey_ptr, &subkey_wide);
            let result_ptr = ARENA + 0x200;
            let disposition_ptr = ARENA + 0x204;
            session.map_guest(result_ptr, &[0_u8; 8]);
            let rax = session.call(
                reg_create,
                &[
                    HKEY_CURRENT_USER as u64,
                    subkey_ptr,
                    0,
                    0,
                    0,
                    KEY_READ as u64,
                    0,
                    result_ptr,
                    disposition_ptr,
                ],
            );
            assert_eq!(rax, 0, "RegCreateKeyExW returns ERROR_SUCCESS");
            let key_handle = read_u32(&session.read_guest(result_ptr, 8), 0);
            assert_ne!(key_handle, 0);

            // RegSetValueExW writes "Greeting" = REG_SZ "hello".
            let name_wide: Vec<u8> = "Greeting"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect();
            let name_ptr = ARENA + 0x400;
            session.map_guest(name_ptr, &name_wide);
            let mut data = "hello"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<_>>();
            data.extend_from_slice(&0u16.to_le_bytes());
            let data_ptr = ARENA + 0x500;
            session.map_guest(data_ptr, &data);
            let rax = session.call(
                reg_set,
                &[
                    key_handle as u64,
                    name_ptr,
                    0,
                    REG_SZ as u64,
                    data_ptr,
                    data.len() as u64,
                ],
            );
            assert_eq!(rax, 0, "RegSetValueExW returns ERROR_SUCCESS");

            // NtQueryValueKey reads the Win32-written value from the SAME store.
            let us_ptr = ARENA + 0x600;
            session.map_guest(us_ptr, &[0_u8; 16]);
            session.map_guest(us_ptr, &(name_wide.len() as u16 - 2).to_le_bytes());
            session.map_guest(us_ptr + 2, &(name_wide.len() as u16).to_le_bytes());
            session.map_guest(us_ptr + 8, &name_ptr.to_le_bytes());
            let query_buffer = ARENA + 0x700;
            session.map_guest(query_buffer, &[0_u8; 256]);
            let result_length = ARENA + 0x800;
            session.map_guest(result_length, &[0_u8; 8]);
            let rax = session.call(
                nt_query_value,
                &[
                    key_handle as u64,
                    us_ptr,
                    KEY_VALUE_FULL_INFORMATION_CLASS as u64,
                    query_buffer,
                    256,
                    result_length,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let body = session.read_guest(query_buffer, 128);
            assert_eq!(read_u32(&body, 4), REG_SZ, "the stored type is REG_SZ");
            let data_offset = read_u32(&body, 8) as usize;
            let data_len = read_u32(&body, 12) as usize;
            assert_eq!(
                &body[data_offset..data_offset + data_len],
                b"h\0e\0l\0l\0o\0\0\0"
            );

            // Reverse direction: NtSetValueKey writes "Reverse" = REG_DWORD 42; the
            // Win32 RegQueryValueExW reads it back.
            let reverse_wide: Vec<u8> = "Reverse"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect();
            let reverse_ptr = ARENA + 0x900;
            session.map_guest(reverse_ptr, &reverse_wide);
            let reverse_us = ARENA + 0xA00;
            session.map_guest(reverse_us, &[0_u8; 16]);
            session.map_guest(reverse_us, &(reverse_wide.len() as u16 - 2).to_le_bytes());
            session.map_guest(reverse_us + 2, &(reverse_wide.len() as u16).to_le_bytes());
            session.map_guest(reverse_us + 8, &reverse_ptr.to_le_bytes());
            let dword_buf = ARENA + 0xB00;
            session.map_guest(dword_buf, &42u32.to_le_bytes());
            let rax = session.call(
                nt_set_value,
                &[
                    key_handle as u64,
                    reverse_us,
                    0,
                    REG_DWORD as u64,
                    dword_buf,
                    4,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let query_data = ARENA + 0xC00;
            let query_len = ARENA + 0xC04;
            let query_type = ARENA + 0xC08;
            session.map_guest(query_data, &[0_u8; 16]);
            session.map_guest(query_len, &64u32.to_le_bytes());
            session.map_guest(query_type, &[0_u8; 4]);
            let rax = session.call(
                reg_query,
                &[
                    key_handle as u64,
                    reverse_ptr,
                    0,
                    query_type,
                    query_data,
                    query_len,
                ],
            );
            assert_eq!(rax, 0, "RegQueryValueExW returns ERROR_SUCCESS");
            assert_eq!(read_u32(&session.read_guest(query_type, 4), 0), REG_DWORD);
            assert_eq!(read_u32(&session.read_guest(query_data, 4), 0), 42);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 10. Files: CreateFileW ↔ NtCreateFile over the ONE file layer ─────────

#[test]
fn create_file_w_and_nt_create_file_resolve_the_same_normalized_path() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let create_file = session.alloc_thunk(HostThunk::CreateFileW);
            let nt_create_file = session.alloc_thunk(HostThunk::NtCreateFile);
            let close_handle = session.alloc_thunk(HostThunk::CloseHandle);
            let nt_close = session.alloc_thunk(HostThunk::NtClose);

            let path = "C:\\section50-cross-file.txt";
            let path_wide: Vec<u8> = path
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect();
            let path_ptr = ARENA;
            session.map_guest(path_ptr, &path_wide);

            // CreateFileW (Win32) creates the file.
            let handle = session.call(
                create_file,
                &[
                    path_ptr,
                    (GENERIC_READ | GENERIC_WRITE) as u64,
                    FILE_SHARE_ALL as u64,
                    0,
                    CREATE_ALWAYS as u64,
                    0x80, // FILE_ATTRIBUTE_NORMAL
                    0,
                ],
            ) as u32;
            assert_ne!(handle, u32::MAX, "CreateFileW succeeded");
            assert_eq!(session.last_error(), 0);
            let win32_path = session
                .win32()
                .file_state(handle)
                .expect("file state")
                .normalized_path;

            // NtCreateFile on the NT-spelling of the SAME path resolves to the SAME
            // normalized guest path (the shared file layer is one).
            let nt_name_wide: Vec<u8> = "\\??\\C:\\section50-cross-file.txt"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            let nt_name_buf = ARENA2;
            session.map_guest(nt_name_buf, &nt_name_wide);
            let us_ptr = ARENA2 + 0x100;
            session.map_guest(us_ptr, &[0_u8; 16]);
            session.map_guest(us_ptr, &(nt_name_wide.len() as u16).to_le_bytes());
            session.map_guest(us_ptr + 2, &((nt_name_wide.len() + 2) as u16).to_le_bytes());
            session.map_guest(us_ptr + 8, &nt_name_buf.to_le_bytes());
            let attrs = ARENA2 + 0x200;
            session.map_guest(attrs, &[0_u8; 48]);
            session.map_guest(attrs + 16, &us_ptr.to_le_bytes());
            let nt_handle_ptr = ARENA2 + 0x300;
            let iosb = ARENA2 + 0x304;
            session.map_guest(nt_handle_ptr, &[0_u8; 16]);
            let rax = session.call(
                nt_create_file,
                &[
                    nt_handle_ptr,
                    GENERIC_READ as u64,
                    attrs,
                    iosb,
                    0,
                    0,
                    FILE_SHARE_ALL as u64,
                    FILE_OPEN as u64,
                    FILE_SYNCHRONOUS_IO_NONALERT as u64,
                    0,
                    0,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let nt_handle = read_u32(&session.read_guest(nt_handle_ptr, 8), 0);
            let nt_path = session
                .win32()
                .file_state(nt_handle)
                .expect("nt file state")
                .normalized_path;
            assert_eq!(
                nt_path, win32_path,
                "NtCreateFile resolves the same normalized path as CreateFileW"
            );

            // The same error-code domain: a missing file reports
            // ERROR_FILE_NOT_FOUND (Win32) ↔ STATUS_OBJECT_NAME_NOT_FOUND (Nt),
            // which round-trip through the canonical mapping.
            let missing_wide: Vec<u8> = "C:\\section50-missing.txt"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0u8, 0])
                .collect();
            let missing_ptr = ARENA3;
            session.map_guest(missing_ptr, &missing_wide);
            let handle = session.call(
                create_file,
                &[
                    missing_ptr,
                    GENERIC_READ as u64,
                    FILE_SHARE_ALL as u64,
                    0,
                    OPEN_EXISTING as u64,
                    0x80,
                    0,
                ],
            ) as u32;
            assert_eq!(handle, u32::MAX);
            assert_eq!(session.last_error(), ERROR_FILE_NOT_FOUND);
            assert_eq!(
                nt_status_to_dos_error(casa1::ntdll::STATUS_OBJECT_NAME_NOT_FOUND),
                ERROR_FILE_NOT_FOUND,
                "the Nt name for the same failure maps back to the Win32 error"
            );

            // Close both handles across the surfaces.
            assert_eq!(
                session.call(close_handle, &[handle as u64]),
                0,
                "failed handle returns FALSE"
            );
            assert_eq!(session.call(close_handle, &[nt_handle as u64]), 1);
            assert_eq!(
                NtStatus::from_raw(session.call(nt_close, &[handle as u64]) as u32),
                casa1::ntdll::STATUS_INVALID_HANDLE,
                "NtClose on the failed handle value is an invalid handle"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 11. Sections: CreateFileMappingW/MapViewOfFile ↔ Nt*Section ───────────

#[test]
fn file_mapping_and_nt_section_share_the_section_object() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let create_mapping = session.alloc_thunk(HostThunk::CreateFileMappingW);
            let map_view = session.alloc_thunk(HostThunk::MapViewOfFile);
            let unmap_view = session.alloc_thunk(HostThunk::UnmapViewOfFile);
            let nt_query_section = session.alloc_thunk(HostThunk::NtQuerySection);
            let nt_map_view = session.alloc_thunk(HostThunk::NtMapViewOfSection);
            let nt_unmap_view = session.alloc_thunk(HostThunk::NtUnmapViewOfSection);

            // CreateFileMappingW with PAGE_READONLY, 0x4000 bytes.
            let section =
                session.call(create_mapping, &[0, 0, PAGE_READONLY as u64, 0, 0x4000, 0]) as u32;
            assert_ne!(section, 0);

            // NtQuerySection reports the SAME section size and the SAME protection
            // the Win32 call recorded in the shared SectionObject.
            let buffer = ARENA;
            session.map_guest(buffer, &[0_u8; 48]);
            let rax = session.call(nt_query_section, &[section as u64, 0, buffer, 48, 0]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let info = session.read_guest(buffer, 48);
            assert_eq!(read_u64(&info, 16), 0x4000, "MaximumSize");
            assert_eq!(read_u32(&info, 24), PAGE_READONLY, "SectionPageProtection");

            // Both mapping surfaces register the views in the SAME canonical VM and
            // tie them to the section's shared backing.
            let win32_base = session.call(map_view, &[section as u64, 0, 0, 0, 0]);
            assert_ne!(win32_base, 0);
            assert!(
                session.win32().mapped_view_section(win32_base).is_some(),
                "the Win32 view is tied to the section backing"
            );
            let base_ptr = ARENA2;
            let offset_ptr = ARENA2 + 8;
            let size_ptr = ARENA2 + 16;
            session.map_guest(base_ptr, &[0_u8; 24]);
            let rax = session.call(
                nt_map_view,
                &[
                    0xFFFF_FFFF,
                    section as u64,
                    base_ptr,
                    0,
                    0,
                    offset_ptr,
                    size_ptr,
                    1,
                    0,
                    PAGE_READONLY as u64,
                ],
            );
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let nt_base = read_u64(&session.read_guest(base_ptr, 8), 0);
            assert_ne!(nt_base, 0);
            assert_ne!(nt_base, win32_base);
            assert!(session.win32().mapped_view_section(nt_base).is_some());

            // Each surface unmaps the view the OTHER surface mapped.
            let rax = session.call(nt_unmap_view, &[0xFFFF_FFFF, win32_base]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            assert_eq!(session.call(unmap_view, &[nt_base]), 1);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 12. Errors: nt_status_to_dos_error ↔ dos_error_to_nt_status ────────────

#[test]
fn error_domains_round_trip_in_both_directions() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            // The documented subset: every Win32 error the Nt layer can produce maps
            // to a canonical NTSTATUS and back to the SAME Win32 error.
            for (status, dos) in [
                (0x0000_0000u32, 0u32), // STATUS_SUCCESS
                (0xC000_0034, 2),       // STATUS_OBJECT_NAME_NOT_FOUND
                (0xC000_003A, 3),       // STATUS_OBJECT_PATH_NOT_FOUND
                (0xC000_0022, 5),       // STATUS_ACCESS_DENIED
                (0xC000_0008, 6),       // STATUS_INVALID_HANDLE
                (0xC000_0017, 8),       // STATUS_NO_MEMORY
                (0xC000_0043, 32),      // STATUS_SHARING_VIOLATION
                (0xC000_004B, 33),      // STATUS_LOCK_VIOLATION
                (0xC000_00BB, 50),      // STATUS_NOT_SUPPORTED
                (0xC000_000D, 87),      // STATUS_INVALID_PARAMETER
                (0xC000_0023, 122),     // STATUS_BUFFER_TOO_SMALL
                (0xC000_0033, 123),     // STATUS_OBJECT_NAME_INVALID
                (0xC000_0135, 126),     // STATUS_DLL_NOT_FOUND
                (0xC000_0139, 127),     // STATUS_ENTRYPOINT_NOT_FOUND
                (0xC000_0035, 183),     // STATUS_OBJECT_NAME_COLLISION
                (0x8000_0005, 234),     // STATUS_BUFFER_OVERFLOW
                (0x8000_001A, 259),     // STATUS_NO_MORE_ENTRIES
                (0xC000_0005, 998),     // STATUS_ACCESS_VIOLATION
                (0x0000_0102, 1460),    // STATUS_TIMEOUT
            ] {
                let nt = NtStatus::from_raw(status);
                assert_eq!(nt_status_to_dos_error(nt), dos, "nt → dos for {status:#x}");
                assert_eq!(
                    dos_error_to_nt_status(dos).raw(),
                    status,
                    "dos → nt for {dos}"
                );
            }

            // The thunk-level boundary (RtlNtStatusToDosError) uses the canonical
            // map.
            let (_tmp, mut session) = setup_session();
            let rtl_status_to_dos = session.alloc_thunk(HostThunk::RtlNtStatusToDosError);
            let rax = session.call(rtl_status_to_dos, &[0xC000_0034]);
            assert_eq!(rax, 2);
            let rax = session.call(rtl_status_to_dos, &[0xC000_000D]);
            assert_eq!(rax, 87);
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 13. Time: system time identity + timer resolution domain ───────────────

#[test]
fn system_time_and_timer_resolution_domains_are_consistent() {
    // The host-thunk dispatch match frame exceeds libtest's 2 MiB
    // test-thread stack in debug builds — run on the 8 MiB big-stack thread.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let nt_query_time = session.alloc_thunk(HostThunk::NtQuerySystemTime);
            let get_system_time = session.alloc_thunk(HostThunk::GetSystemTimeAsFileTime);
            let nt_query_resolution = session.alloc_thunk(HostThunk::NtQueryTimerResolution);
            let nt_set_resolution = session.alloc_thunk(HostThunk::NtSetTimerResolution);
            let time_get_time = session.alloc_thunk(HostThunk::TimeGetTime);

            // NtQuerySystemTime and GetSystemTimeAsFileTime report the SAME
            // FILETIME at every instant (one derivation).
            let ft_ptr = ARENA;
            let win32_ft_ptr = ARENA + 8;
            session.map_guest(ft_ptr, &[0_u8; 16]);
            let _ = session.call(nt_query_time, &[ft_ptr]);
            let _ = session.call(get_system_time, &[win32_ft_ptr]);
            assert_eq!(
                read_u64(&session.read_guest(ft_ptr, 8), 0),
                read_u64(&session.read_guest(win32_ft_ptr, 8), 0)
            );
            session.advance_guest_clock(100);
            let _ = session.call(nt_query_time, &[ft_ptr]);
            let _ = session.call(get_system_time, &[win32_ft_ptr]);
            assert_eq!(
                read_u64(&session.read_guest(ft_ptr, 8), 0),
                read_u64(&session.read_guest(win32_ft_ptr, 8), 0),
                "the surfaces stay identical after the clock advances"
            );

            // The timer resolution domain: a 1 ms minimum (the timeGetTime
            // granularity) and the classic 15.6 ms maximum; NtSetTimerResolution
            // clamps into the same range.
            let min_ptr = ARENA + 0x10;
            let max_ptr = ARENA + 0x14;
            let current_ptr = ARENA + 0x18;
            session.map_guest(min_ptr, &[0_u8; 12]);
            let rax = session.call(nt_query_resolution, &[min_ptr, max_ptr, current_ptr]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            let min_100ns = read_u32(&session.read_guest(min_ptr, 12), 0);
            let max_100ns = read_u32(&session.read_guest(min_ptr, 12), 4);
            let current_100ns = read_u32(&session.read_guest(min_ptr, 12), 8);
            assert_eq!(min_100ns, 10_000, "1 ms minimum");
            assert_eq!(max_100ns, 156_250, "15.6 ms maximum");
            assert_eq!(current_100ns, 156_250);
            assert_eq!(
                min_100ns / 10_000,
                1,
                "the minimum is the 1 ms timeGetTime domain"
            );
            let actual_ptr = ARENA + 0x20;
            session.map_guest(actual_ptr, &[0_u8; 4]);
            let rax = session.call(nt_set_resolution, &[5000, 1, actual_ptr]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            assert_eq!(
                read_u32(&session.read_guest(actual_ptr, 4), 0),
                10_000,
                "clamped to the minimum"
            );
            let rax = session.call(nt_set_resolution, &[1_000_000, 1, actual_ptr]);
            assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
            assert_eq!(
                read_u32(&session.read_guest(actual_ptr, 4), 0),
                156_250,
                "clamped to the maximum"
            );

            // timeGetTime reports the same millisecond domain (the minimum
            // resolution is exactly its granularity).
            let ms = session.call(time_get_time, &[]);
            assert!(
                ms < 10_000_000,
                "timeGetTime is a milliseconds-since-start counter"
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

// ── 14. Directory objects, volume facts, attestation (dispatch failures) ──

fn write_object_attributes(session: &mut NtThunkSession, attrs: u64, name: u64) {
    let mut bytes = [0_u8; 48];
    bytes[0..4].copy_from_slice(&48_u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&name.to_le_bytes());
    session.map_guest(attrs, &bytes);
}

fn write_unicode_name(session: &mut NtThunkSession, header: u64, buffer: u64, text: &str) {
    let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut header_bytes = [0_u8; 16];
    header_bytes[0..2].copy_from_slice(&(((units.len() - 1) * 2) as u16).to_le_bytes());
    header_bytes[2..4].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
    header_bytes[8..16].copy_from_slice(&buffer.to_le_bytes());
    session.map_guest(header, &header_bytes);
    let mut string_bytes = vec![0_u8; units.len() * 2];
    for (index, unit) in units.iter().enumerate() {
        string_bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    session.map_guest(buffer, &string_bytes);
}

#[test]
fn directory_objects_reject_missing_paths_and_undersized_query_buffers() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let open = session.alloc_thunk(HostThunk::NtOpenDirectoryObject);
            let query = session.alloc_thunk(HostThunk::NtQueryDirectoryObject);

            // No OBJECT_ATTRIBUTES name means no directory to open.
            let handle_out = 0x30_100_u64;
            session.map_guest(handle_out, &[0_u8; 8]);
            assert_eq!(
                NtStatus::from_raw(session.call(open, &[handle_out, 0, 0]) as u32),
                casa1::ntdll::STATUS_OBJECT_NAME_INVALID
            );

            // A missing child of the existing \Device directory is
            // NAME_NOT_FOUND, never a fabricated handle.
            let attrs = 0x30_200_u64;
            let name_header = 0x30_300_u64;
            let name_buffer = 0x30_400_u64;
            write_unicode_name(
                &mut session,
                name_header,
                name_buffer,
                "\\Device\\Casa1MissingDevice",
            );
            write_object_attributes(&mut session, attrs, name_header);
            assert_eq!(
                NtStatus::from_raw(session.call(open, &[handle_out, 0, attrs]) as u32),
                STATUS_OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(
                read_u64(&session.read_guest(handle_out, 8), 0),
                0,
                "a failed open must not write a handle"
            );

            // Root enumeration with a too-small buffer reports the exact
            // required size and does not emit a partial record.
            write_unicode_name(&mut session, name_header, name_buffer, "\\");
            assert_eq!(
                NtStatus::from_raw(session.call(open, &[handle_out, 0, attrs]) as u32),
                STATUS_SUCCESS
            );
            let root = read_u64(&session.read_guest(handle_out, 8), 0);
            assert_ne!(root, 0);
            let context = 0x40_000_u64;
            let required = 0x40_010_u64;
            session.map_guest(context, &0_u32.to_le_bytes());
            session.map_guest(required, &0_u32.to_le_bytes());
            assert_eq!(
                NtStatus::from_raw(
                    session.call(query, &[root, 0x50_000, 8, 1, 0, context, required]) as u32
                ),
                STATUS_BUFFER_TOO_SMALL
            );
            assert!(
                read_u32(&session.read_guest(required, 4), 0) > 8,
                "required size must exceed the caller buffer"
            );

            // An unknown handle is INVALID_HANDLE, before any buffer check.
            assert_eq!(
                NtStatus::from_raw(
                    session.call(query, &[0xDEAD, 0x50_000, 0x100, 0, 1, 0, 0]) as u32
                ),
                STATUS_INVALID_HANDLE
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}

#[test]
fn volume_query_rejects_null_io_status_and_non_file_handles() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (_tmp, mut session) = setup_session();
            let query = session.alloc_thunk(HostThunk::NtQueryVolumeInformationFile);
            let io_status = 0x30_000_u64;
            session.map_guest(io_status, &[0_u8; 16]);

            assert_eq!(
                NtStatus::from_raw(session.call(query, &[0xDEAD, 0, 0, 0, 1]) as u32),
                STATUS_INVALID_PARAMETER,
                "a null IoStatusBlock is rejected before handle lookup"
            );

            assert_eq!(
                NtStatus::from_raw(session.call(query, &[0xDEAD, io_status, 0, 0, 1]) as u32),
                STATUS_INVALID_HANDLE
            );
            assert_eq!(
                read_u32(&session.read_guest(io_status, 4), 0),
                STATUS_INVALID_HANDLE.raw()
            );

            // An event handle is a real object of the wrong type.
            let create_event = session.alloc_thunk(HostThunk::CreateEventW);
            let event = session.call(create_event, &[0, 0, 0, 0]) as u32;
            assert_ne!(event, 0);
            assert_eq!(
                NtStatus::from_raw(
                    session.call(query, &[u64::from(event), io_status, 0, 0, 1]) as u32
                ),
                STATUS_OBJECT_TYPE_MISMATCH
            );
        })
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked");
}
