#![allow(dead_code, unused_imports)]
//! Phase 0.2: CreateProcessW/A — sub-process spawning, handle inheritance,
//! process handle management, STARTUPINFOW parsing, ANSI/Wide variants,
//! environment block passing, working directory support.
//!
//! F-09 (HIGH): Guest CreateProcessW / CreateProcessA.

mod support;

use casa1::ge::{GameEnvironment, GeArch};
use casa1::reason::ReasonCode;
use casa1::win32::{self, CreateProcessResult, WaitStatus, Win32Subsystem};
use std::collections::BTreeMap;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup_win32() -> (TempDir, Win32Subsystem) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), "test-proc", GeArch::X64, "win11-23h2")
        .expect("create GE");
    let win32 = Win32Subsystem::new(ge, true);
    (temp_dir, win32)
}

fn create_test_process(
    win32: &mut Win32Subsystem,
    application: &str,
    command_line: &str,
    inherit_handles: bool,
) -> CreateProcessResult {
    let env = BTreeMap::new();
    win32
        .create_process_w(application, command_line, &env, "C:\\", inherit_handles)
        .expect("create_process_w")
}

// ---------------------------------------------------------------------------
// build_environment_block_utf16
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// windows_command_line_to_argv
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// create_process_w — process / thread object creation
// ---------------------------------------------------------------------------

#[test]
fn test_create_process_w_basic() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe --flag", false);

    // The process handle must be non-zero.
    assert_ne!(result.process_handle, 0);
    assert_ne!(result.thread_handle, 0);
    // Process IDs should be > 0.
    assert!(result.process_id > 0);
    assert!(result.thread_id > 0);
    // argv[0] should be rewritten to the application name.
    assert_eq!(result.argv[0], "C:\\test.exe");
    // Environment block must be present.
    assert!(!result.environment_block_utf16.is_empty());
}

// ---------------------------------------------------------------------------
// Handle inheritance
// ---------------------------------------------------------------------------

#[test]
fn test_create_process_w_inherit_handles_true() {
    let (_tmp, mut win32) = setup_win32();

    // Create an inheritable event handle (manual_reset, initial_state, inheritable, name).
    let (_evt, _) = win32.create_event(true, true, true, None);
    // Create a non-inheritable event handle.
    let (_evt_no_inherit, _) = win32.create_event(true, false, false, None);

    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", true);
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");

    // The inherited_handles should contain an Event descriptor with inheritable == true.
    assert!(
        state
            .inherited_handles
            .iter()
            .any(|h| h.object_type == win32::ObjectType::Event && h.inheritable),
        "inheritable event descriptor must appear in inherited_handles"
    );
    // The non-inheritable event descriptor must NOT appear.
    assert!(
        !state
            .inherited_handles
            .iter()
            .any(|h| h.object_type == win32::ObjectType::Event && !h.inheritable),
        "non-inheritable event descriptor must NOT appear in inherited_handles"
    );
}

// ---------------------------------------------------------------------------
// Process exit code
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// WaitForSingleObject with process handles (condvar-based synchronisation)
// ---------------------------------------------------------------------------

#[test]
fn test_wait_for_single_object_process_timeout() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    // Without exit_sync installed, wait_for_single_object on a process handle
    // with a zero timeout should return WAIT_TIMEOUT because the process
    // has not exited yet (exit_code is None and no exit sync condvar).
    let status = win32
        .wait_for_single_object(result.process_handle, 0, false, None)
        .expect("wait_for_single_object");
    assert_eq!(status, WaitStatus::Timeout);
}

// ---------------------------------------------------------------------------
// OpenProcess
// ---------------------------------------------------------------------------

#[test]
fn test_open_process_invalid_id() {
    let (_tmp, mut win32) = setup_win32();
    // Opening a non-existent process ID should fail.
    let err = win32.open_process(0x1F0FFF, false, 99999).unwrap_err();
    assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
}

// ---------------------------------------------------------------------------
// DuplicateHandle on process handles
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_process_handle() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    let dup = win32
        .duplicate_handle(
            result.process_handle,
            0x1F0FFF, // desired_access
            true,     // inheritable
            false,    // same_access — use explicit access mask
            false,    // close_source — do not close the source
        )
        .expect("duplicate_handle");
    assert_ne!(dup, 0);
    assert_ne!(dup, result.process_handle);

    let state = win32.process_state(dup).expect("process_state");
    assert_eq!(state.process_id, result.process_id);
}

// ---------------------------------------------------------------------------
// Full create_process_w round-trip: create process, set exit code,
// verify state — using a guest path that does not need to exist on disk.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// set_process_exit_code_and_notify — verifies the notify path used by
// launch_guest_child_process background threads.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn test_create_process_w_invalid_handle_operations() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    // Closing the handle should work.
    win32
        .close_handle(result.process_handle)
        .expect("close process handle");
    win32
        .close_handle(result.thread_handle)
        .expect("close thread handle");

    // After closing, process_state should fail.
    let err = win32.process_state(result.process_handle).unwrap_err();
    assert_eq!(err.code, ReasonCode::RcWin32InvalidHandle);
}
