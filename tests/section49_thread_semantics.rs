//! Thread semantics hardening — suspension, exit races and suspend-aware
//! waits across the Win32 and Nt dispatch paths.
//!
//! These tests drive the REAL dispatch path through the
//! [`crate::runtime::NtThunkSession`] scratch runtime with an x86 guest
//! (thread creation only queues scheduler records for x86 guests) and the
//! live Win32 subsystem handle namespace.
//!
//! Coverage:
//! * Win32/Nt suspend/resume thunks interleaved on one queued thread keep
//!   the subsystem counter and the scheduler record equal (single source
//!   of truth).
//! * Suspend/resume on a terminated thread fails (THREAD_SUSPEND_FAILED /
//!   ERROR_ACCESS_DENIED; Nt: STATUS_THREAD_IS_TERMINATING).
//! * Waiting on a suspended thread never completes while suspended, and
//!   completes only after resume + exit.
//! * CREATE_SUSPENDED threads stay pending until ResumeThread releases
//!   them.
//! * The query classes report values consistent with the Win32 subsystem.

mod support;

use casa1::cpu::GuestArch;
use casa1::error::ERROR_ACCESS_DENIED;
use casa1::ge::{GameEnvironment, GeArch};
use casa1::ntdll::{
    STATUS_SUCCESS, STATUS_THREAD_IS_TERMINATING, THREAD_AFFINITY_MASK_CLASS,
    THREAD_AM_I_LAST_THREAD_CLASS, THREAD_BASE_PRIORITY_CLASS, THREAD_BASIC_INFORMATION_CLASS,
    THREAD_HIDE_FROM_DEBUGGER_CLASS, THREAD_IS_TERMINATED_CLASS, THREAD_PRIORITY_BOOST_CLASS,
    THREAD_PRIORITY_CLASS, THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS, THREAD_SUSPEND_COUNT_CLASS,
    THREAD_TIMES_CLASS,
};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use tempfile::TempDir;

fn setup_session() -> (TempDir, NtThunkSession) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(
        temp_dir.path(),
        "thread-semantics",
        GeArch::X86,
        "win11-23h2",
    )
    .expect("create GE");
    let mut session = NtThunkSession::new(ge);
    session.set_guest_arch(GuestArch::X86);
    (temp_dir, session)
}

/// The scratch arena addresses (mapped by the session).
const ENTRY_POINT: u64 = 0x41_100;
const FLAG_PTR: u64 = 0x41_200;
const THREAD_ID_PTR: u64 = 0x41_204;
const OUT_PTR: u64 = 0x41_300;

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const THREAD_SUSPEND_FAILED: u32 = 0xFFFF_FFFF;

/// Map a trivial thread start routine: `mov eax, FLAG_PTR; mov dword ptr
/// [eax], 1; xor eax, eax; ret` — writes the flag and returns exit code 0.
fn map_thread_entrypoint(session: &mut NtThunkSession) {
    let mut bytes = vec![0x90; 0x40];
    bytes[..14].copy_from_slice(&[
        0xB8,
        (FLAG_PTR & 0xFF) as u8,
        ((FLAG_PTR >> 8) & 0xFF) as u8,
        ((FLAG_PTR >> 16) & 0xFF) as u8,
        ((FLAG_PTR >> 24) & 0xFF) as u8,
        0xC7,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x33,
        0xC0,
        0xC3,
    ]);
    session.map_guest(ENTRY_POINT, &bytes);
    session.map_guest(FLAG_PTR, &[0_u8; 8]);
    session.map_guest(THREAD_ID_PTR, &[0_u8; 4]);
    session.map_guest(OUT_PTR, &[0_u8; 16]);
}

/// Create a queued (not-yet-run) x86 guest thread.  Returns the thread
/// handle and its guest thread id.
fn create_queued_thread(
    session: &mut NtThunkSession,
    create_thread: u64,
    creation_flags: u32,
) -> (u32, u32) {
    map_thread_entrypoint(session);
    let handle = session.call_x86(
        create_thread,
        &[
            0,
            0,
            ENTRY_POINT as u32,
            0,
            creation_flags,
            THREAD_ID_PTR as u32,
        ],
    );
    assert_ne!(handle, 0);
    let thread_id = u32::from_le_bytes(
        session
            .read_guest(THREAD_ID_PTR, 4)
            .try_into()
            .expect("thread id"),
    );
    (handle, thread_id)
}

/// NtQueryInformationThread helper: query a u32-sized class and return the
/// value written at the output buffer.
fn query_thread_u32(session: &mut NtThunkSession, query: u64, handle: u32, info_class: u32) -> u32 {
    session.map_guest(OUT_PTR, &[0_u8; 32]);
    let status = session.call_x86(query, &[handle, info_class, OUT_PTR as u32, 32, 0]);
    assert_eq!(
        status,
        STATUS_SUCCESS.raw(),
        "class {info_class} must succeed"
    );
    u32::from_le_bytes(session.read_guest(OUT_PTR, 4).try_into().unwrap())
}

#[test]
fn interleaved_win32_and_nt_suspend_resume_keep_counters_equal() {
    let (_tmp, mut session) = setup_session();
    let create_thread = session.alloc_thunk(HostThunk::CreateThread);
    let suspend_thread = session.alloc_thunk(HostThunk::SuspendThread);
    let nt_resume = session.alloc_thunk(HostThunk::NtResumeThread);
    let (handle, thread_id) = create_queued_thread(&mut session, create_thread, 0);

    let assert_counters_equal = |session: &NtThunkSession| {
        let subsystem = session
            .win32()
            .thread_suspend_count(thread_id)
            .expect("subsystem count");
        let scheduler = session
            .pending_thread_suspend_count(handle)
            .expect("scheduler count");
        assert_eq!(
            subsystem, scheduler,
            "the subsystem counter and the scheduler record must agree"
        );
    };

    // Win32 suspend: previous count 0 → 1.
    assert_eq!(session.call_x86(suspend_thread, &[handle]), 0);
    assert_counters_equal(&session);
    // Win32 suspend again: previous count 1 → 2.
    assert_eq!(session.call_x86(suspend_thread, &[handle]), 1);
    assert_counters_equal(&session);
    // Nt resume: previous count 2 → 1 — the thread is still suspended.
    let prev_ptr = OUT_PTR as u32;
    session.map_guest(OUT_PTR, &[0xFF_u8; 4]);
    assert_eq!(
        session.call_x86(nt_resume, &[handle, prev_ptr]),
        STATUS_SUCCESS.raw()
    );
    assert_eq!(
        u32::from_le_bytes(session.read_guest(OUT_PTR, 4).try_into().unwrap()),
        2,
        "NtResumeThread reports the true previous count"
    );
    assert_counters_equal(&session);
    assert!(!session.pump_pending_guest_thread(), "still suspended");

    // Nt resume: previous count 1 → 0 — the pump may start the thread.
    assert_eq!(
        session.call_x86(nt_resume, &[handle, 0]),
        STATUS_SUCCESS.raw()
    );
    assert_counters_equal(&session);
    assert!(
        session.pump_pending_guest_thread(),
        "starts after the final resume"
    );
    assert_eq!(
        u32::from_le_bytes(session.read_guest(FLAG_PTR, 4).try_into().unwrap()),
        1,
        "the thread ran exactly after the last suspension was released"
    );
}

#[test]
fn suspend_resume_on_terminated_thread_fails_win32_and_nt() {
    let (_tmp, mut session) = setup_session();
    let create_thread = session.alloc_thunk(HostThunk::CreateThread);
    let suspend_thread = session.alloc_thunk(HostThunk::SuspendThread);
    let resume_thread = session.alloc_thunk(HostThunk::ResumeThread);
    let terminate_thread = session.alloc_thunk(HostThunk::TerminateThread);
    let nt_suspend = session.alloc_thunk(HostThunk::NtSuspendThread);
    let nt_resume = session.alloc_thunk(HostThunk::NtResumeThread);
    let (handle, _thread_id) = create_queued_thread(&mut session, create_thread, 0);

    // Terminate the thread: the queue entry is dropped and the subsystem
    // state records the exit, but the handle stays open.
    assert_eq!(session.call_x86(terminate_thread, &[handle, 0x77]), 1);

    // Win32: THREAD_SUSPEND_FAILED with ERROR_ACCESS_DENIED — Windows
    // behavior for terminated threads.
    assert_eq!(
        session.call_x86(suspend_thread, &[handle]),
        THREAD_SUSPEND_FAILED
    );
    assert_eq!(session.last_error(), ERROR_ACCESS_DENIED);
    assert_eq!(
        session.call_x86(resume_thread, &[handle]),
        THREAD_SUSPEND_FAILED
    );
    assert_eq!(session.last_error(), ERROR_ACCESS_DENIED);

    // Nt: STATUS_THREAD_IS_TERMINATING (0xC000004A).
    let prev_ptr = OUT_PTR as u32;
    session.map_guest(OUT_PTR, &[0xFF_u8; 4]);
    assert_eq!(
        session.call_x86(nt_suspend, &[handle, prev_ptr]),
        STATUS_THREAD_IS_TERMINATING.raw()
    );
    assert_eq!(
        session.call_x86(nt_resume, &[handle, prev_ptr]),
        STATUS_THREAD_IS_TERMINATING.raw()
    );
    // The previous-count out parameter is untouched on failure.
    assert_eq!(
        u32::from_le_bytes(session.read_guest(OUT_PTR, 4).try_into().unwrap()),
        0xFFFF_FFFF,
        "the previous-count out parameter is not written on failure"
    );
}

#[test]
fn create_suspended_wait_stays_pending_until_resume() {
    let (_tmp, mut session) = setup_session();
    let create_thread = session.alloc_thunk(HostThunk::CreateThread);
    let resume_thread = session.alloc_thunk(HostThunk::ResumeThread);
    let wait_for_single_object = session.alloc_thunk(HostThunk::WaitForSingleObject);
    let (handle, thread_id) = create_queued_thread(&mut session, create_thread, CREATE_SUSPENDED);

    // The initial suspension is recorded in BOTH counters.
    assert_eq!(
        session
            .win32()
            .thread_suspend_count(thread_id)
            .expect("count"),
        1
    );
    assert_eq!(session.pending_thread_suspend_count(handle), Some(1));
    assert!(
        !session.pump_pending_guest_thread(),
        "a CREATE_SUSPENDED thread does not start"
    );

    // A wait on it stays pending (a suspended thread cannot exit).
    session.call_x86(wait_for_single_object, &[handle, u32::MAX]);
    assert_eq!(session.parked_waiter_count(), 2);
    assert!(!session.parked_waiter_satisfiable());

    // ResumeThread releases the thread; it runs to completion and the
    // waiter's descriptor becomes satisfiable.
    assert_eq!(session.call_x86(resume_thread, &[handle]), 1);
    assert_eq!(
        session
            .win32()
            .thread_suspend_count(thread_id)
            .expect("count"),
        0
    );
    assert!(
        session.pump_pending_guest_thread(),
        "the thread starts after ResumeThread"
    );
    assert!(session.parked_waiter_satisfiable());
}

#[test]
fn query_information_thread_classes_agree_with_the_win32_subsystem() {
    let (_tmp, mut session) = setup_session();
    let create_thread = session.alloc_thunk(HostThunk::CreateThread);
    let nt_set_information = session.alloc_thunk(HostThunk::NtSetInformationThread);
    let suspend_thread = session.alloc_thunk(HostThunk::SuspendThread);
    let resume_thread = session.alloc_thunk(HostThunk::ResumeThread);
    let get_thread_times = session.alloc_thunk(HostThunk::GetThreadTimes);
    let terminate_thread = session.alloc_thunk(HostThunk::TerminateThread);
    let query = session.alloc_thunk(HostThunk::NtQueryInformationThread);
    let (handle, _thread_id) = create_queued_thread(&mut session, create_thread, 0);

    // ThreadPriority: NtSetInformationThread routes into the Win32
    // subsystem, and NtQueryInformationThread reports the same value
    // GetThreadPriority reads.
    session.map_guest(OUT_PTR, &7_i32.to_le_bytes());
    assert_eq!(
        session.call_x86(
            nt_set_information,
            &[handle, THREAD_PRIORITY_CLASS, OUT_PTR as u32, 4]
        ),
        STATUS_SUCCESS.raw()
    );
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_PRIORITY_CLASS),
        7
    );
    assert_eq!(
        session
            .win32()
            .get_thread_priority(handle)
            .expect("priority"),
        7
    );

    // ThreadBasePriority: the process base priority, the same value
    // ThreadBasicInformation reports.
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_BASE_PRIORITY_CLASS),
        0
    );

    // ThreadAffinityMask: the fixed 8-way mask.
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_AFFINITY_MASK_CLASS),
        0xFF
    );

    // ThreadIsTerminated: 0 while the thread is alive.
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_IS_TERMINATED_CLASS),
        0
    );

    // ThreadBasicInformation: exit status pending, priority and base
    // priority consistent with the subsystem (28 bytes on x86).
    session.map_guest(OUT_PTR, &[0_u8; 32]);
    let status = session.call_x86(
        query,
        &[
            handle,
            THREAD_BASIC_INFORMATION_CLASS,
            OUT_PTR as u32,
            28,
            0,
        ],
    );
    assert_eq!(status, STATUS_SUCCESS.raw());
    let basic = session.read_guest(OUT_PTR, 28);
    assert_eq!(
        u32::from_le_bytes(basic[0..4].try_into().unwrap()),
        casa1::ntdll::STATUS_PENDING.raw(),
        "exit status is STATUS_PENDING while alive"
    );
    assert_eq!(
        u32::from_le_bytes(basic[20..24].try_into().unwrap()),
        7,
        "priority matches SetThreadPriority"
    );
    assert_eq!(
        u32::from_le_bytes(basic[24..28].try_into().unwrap()),
        0,
        "base priority matches ThreadBasePriority"
    );

    // ThreadQuerySetWin32StartAddress: the queued thread's start routine.
    let status = session.call_x86(
        query,
        &[
            handle,
            THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS,
            OUT_PTR as u32,
            4,
            0,
        ],
    );
    assert_eq!(status, STATUS_SUCCESS.raw());
    assert_eq!(
        u32::from_le_bytes(session.read_guest(OUT_PTR, 4).try_into().unwrap()),
        ENTRY_POINT as u32
    );

    // ThreadAmILastThread: the queued thread is not the last one while the
    // main thread exists.
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_AM_I_LAST_THREAD_CLASS),
        0
    );

    // ThreadPriorityBoost: enabled (the Windows default).
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_PRIORITY_BOOST_CLASS),
        1
    );

    // ThreadHideFromDebugger: not hidden.
    let status = session.call_x86(
        query,
        &[
            handle,
            THREAD_HIDE_FROM_DEBUGGER_CLASS,
            OUT_PTR as u32,
            1,
            0,
        ],
    );
    assert_eq!(status, STATUS_SUCCESS.raw());
    assert_eq!(session.read_guest(OUT_PTR, 1), [0]);

    // ThreadSuspendCount: the subsystem count (the single source of truth)
    // is reported verbatim, including while suspended.
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_SUSPEND_COUNT_CLASS),
        0
    );
    assert_eq!(session.call_x86(suspend_thread, &[handle]), 0);
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_SUSPEND_COUNT_CLASS),
        1
    );
    assert_eq!(session.call_x86(resume_thread, &[handle]), 1);
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_SUSPEND_COUNT_CLASS),
        0
    );

    // ThreadTimes and GetThreadTimes derive from the same guest-clock
    // domain, so the Nt query and the Win32 API always agree (deterministic
    // sessions report the clock delta — zero here).
    session.map_guest(OUT_PTR, &[0xFF_u8; 32]);
    let status = session.call_x86(query, &[handle, THREAD_TIMES_CLASS, OUT_PTR as u32, 32, 0]);
    assert_eq!(status, STATUS_SUCCESS.raw());
    let nt_times = session.read_guest(OUT_PTR, 32);
    let win32_times_buf = 0x41_400;
    session.map_guest(win32_times_buf, &[0_u8; 32]);
    let ok = session.call_x86(
        get_thread_times,
        &[
            handle,
            win32_times_buf as u32,
            (win32_times_buf + 8) as u32,
            (win32_times_buf + 16) as u32,
            (win32_times_buf + 24) as u32,
        ],
    );
    assert_eq!(ok, 1, "GetThreadTimes succeeds");
    let win32_times = session.read_guest(win32_times_buf, 32);
    assert_eq!(
        win32_times, nt_times,
        "GetThreadTimes and ThreadTimes report the same values"
    );

    // ThreadIsTerminated flips to 1 once the thread is terminated.
    assert_eq!(session.call_x86(terminate_thread, &[handle, 0x55]), 1);
    assert_eq!(
        query_thread_u32(&mut session, query, handle, THREAD_IS_TERMINATED_CLASS),
        1
    );
    assert_eq!(
        session
            .win32()
            .get_exit_code_thread(handle)
            .expect("exit code"),
        Some(0x55)
    );
}

#[test]
fn wait_on_suspended_thread_stays_pending_until_resumed_and_exited() {
    let (_tmp, mut session) = setup_session();
    let create_thread = session.alloc_thunk(HostThunk::CreateThread);
    let suspend_thread = session.alloc_thunk(HostThunk::SuspendThread);
    let resume_thread = session.alloc_thunk(HostThunk::ResumeThread);
    let wait_for_single_object = session.alloc_thunk(HostThunk::WaitForSingleObject);
    let (handle, thread_id) = create_queued_thread(&mut session, create_thread, 0);

    // Suspend the queued thread: both counters move to 1 together.
    let prev = session.call_x86(suspend_thread, &[handle]);
    assert_eq!(prev, 0);
    assert_eq!(
        session
            .win32()
            .thread_suspend_count(thread_id)
            .expect("count"),
        1
    );
    assert_eq!(session.pending_thread_suspend_count(handle), Some(1));

    // WaitForSingleObject on the suspended thread parks the waiter (the
    // main thread) — a suspended thread cannot exit, so the wait never
    // completes while the suspension holds.  The park path leaves the
    // resume result to the pump, so the evidence is the parked descriptor.
    session.call_x86(wait_for_single_object, &[handle, u32::MAX]);
    assert_eq!(session.parked_waiter_count(), 2, "target + parked waiter");

    // Nothing is runnable: the target is suspended, the waiter is parked.
    assert!(!session.pump_pending_guest_thread());
    assert!(
        !session.parked_waiter_satisfiable(),
        "a wait on a suspended thread must never complete"
    );

    // Resume releases the pump gate; the thread runs to completion and
    // exits, which makes the waiter's descriptor satisfiable.
    let prev = session.call_x86(resume_thread, &[handle]);
    assert_eq!(prev, 1);
    assert!(
        session.pump_pending_guest_thread(),
        "target ran after resume"
    );
    assert_eq!(
        u32::from_le_bytes(session.read_guest(FLAG_PTR, 4).try_into().unwrap()),
        1,
        "the thread start routine ran"
    );
    assert!(
        session.parked_waiter_satisfiable(),
        "the waiter completes once the thread has exited"
    );
    assert_eq!(session.parked_waiter_count(), 1, "only the waiter remains");
}

#[test]
fn nt_wait_on_suspended_thread_stays_pending_until_resumed_and_exited() {
    let (_tmp, mut session) = setup_session();
    let create_thread = session.alloc_thunk(HostThunk::CreateThread);
    let suspend_thread = session.alloc_thunk(HostThunk::SuspendThread);
    let resume_thread = session.alloc_thunk(HostThunk::ResumeThread);
    let nt_wait = session.alloc_thunk(HostThunk::NtWaitForSingleObject);
    let (handle, thread_id) = create_queued_thread(&mut session, create_thread, 0);

    let prev = session.call_x86(suspend_thread, &[handle]);
    assert_eq!(prev, 0);
    assert_eq!(
        session
            .win32()
            .thread_suspend_count(thread_id)
            .expect("count"),
        1
    );

    // NtWaitForSingleObject with a long finite timeout parks (never
    // host-blocks); the suspended target keeps it pending.
    session.call_x86(nt_wait, &[handle, 0, 0xFFFF_FFFF]);
    assert_eq!(session.parked_waiter_count(), 2);
    assert!(!session.pump_pending_guest_thread());
    assert!(
        !session.parked_waiter_satisfiable(),
        "an Nt wait on a suspended thread must never complete"
    );

    let prev = session.call_x86(resume_thread, &[handle]);
    assert_eq!(prev, 1);
    assert!(
        session.pump_pending_guest_thread(),
        "target ran after resume"
    );
    assert!(
        session.parked_waiter_satisfiable(),
        "the Nt waiter completes once the thread has exited"
    );
}

#[test]
fn terminate_suspended_thread_succeeds_and_thread_never_starts() {
    let (_tmp, mut session) = setup_session();
    let create_thread = session.alloc_thunk(HostThunk::CreateThread);
    let suspend_thread = session.alloc_thunk(HostThunk::SuspendThread);
    let terminate_thread = session.alloc_thunk(HostThunk::TerminateThread);
    let get_exit_code = session.alloc_thunk(HostThunk::GetExitCodeThread);
    let (handle, thread_id) = create_queued_thread(&mut session, create_thread, 0);

    // Suspend it, then terminate it while suspended.
    let prev = session.call_x86(suspend_thread, &[handle]);
    assert_eq!(prev, 0);
    assert_eq!(
        session
            .win32()
            .thread_suspend_count(thread_id)
            .expect("count"),
        1
    );

    let terminated = session.call_x86(terminate_thread, &[handle, 0x1234]);
    assert_eq!(
        terminated, 1,
        "TerminateThread on a suspended thread succeeds"
    );
    assert_eq!(session.last_error(), 0);

    // The queued record is gone: the thread can never start.
    assert_eq!(session.parked_waiter_count(), 0);
    assert!(!session.pump_pending_guest_thread(), "nothing to run");
    assert_eq!(
        u32::from_le_bytes(session.read_guest(FLAG_PTR, 4).try_into().unwrap()),
        0,
        "the suspended thread never ran"
    );

    // GetExitCodeThread reports the termination code.
    let ok = session.call_x86(get_exit_code, &[handle, OUT_PTR as u32]);
    assert_eq!(ok, 1);
    assert_eq!(
        u32::from_le_bytes(session.read_guest(OUT_PTR, 4).try_into().unwrap()),
        0x1234,
        "the termination code is reported"
    );
}
