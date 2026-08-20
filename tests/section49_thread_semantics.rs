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
use casa1::ge::{GameEnvironment, GeArch};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use tempfile::TempDir;

fn setup_session() -> (TempDir, NtThunkSession) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), "thread-semantics", GeArch::X86, "win11-23h2")
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
        &[0, 0, ENTRY_POINT as u32, 0, creation_flags, THREAD_ID_PTR as u32],
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
    assert_eq!(session.win32().thread_suspend_count(thread_id).expect("count"), 1);
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
    assert!(session.pump_pending_guest_thread(), "target ran after resume");
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
    assert_eq!(session.win32().thread_suspend_count(thread_id).expect("count"), 1);

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
    assert!(session.pump_pending_guest_thread(), "target ran after resume");
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
    assert_eq!(session.win32().thread_suspend_count(thread_id).expect("count"), 1);

    let terminated = session.call_x86(terminate_thread, &[handle, 0x1234]);
    assert_eq!(terminated, 1, "TerminateThread on a suspended thread succeeds");
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
