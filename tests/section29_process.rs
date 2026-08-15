//! Phase 0.2: CreateProcessW/A — sub-process spawning, handle inheritance,
//! process handle management, STARTUPINFOW parsing, ANSI/Wide variants,
//! environment block passing, working directory support.
//!
//! F-09 (HIGH): Guest CreateProcessW / CreateProcessA.

mod support;

use casa1::ge::{GameEnvironment, GeArch};
use casa1::reason::ReasonCode;
use casa1::win32::{
    self, CreateProcessResult, WaitStatus, Win32Subsystem, build_environment_block_utf16,
    windows_command_line_to_argv,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a temporary GameEnvironment and Win32Subsystem for a test.
fn setup_win32() -> (TempDir, Win32Subsystem) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), "test-proc", GeArch::X64, "win11-23h2")
        .expect("create GE");
    let win32 = Win32Subsystem::new(ge, true);
    (temp_dir, win32)
}

/// Convenience: create a process with default empty environment and cwd.
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

#[test]
fn test_build_environment_block_utf16_empty() {
    let env = BTreeMap::new();
    let block = build_environment_block_utf16(&env);
    // An empty block is a single null terminator (the trailing null added
    // after all key=value pairs).
    assert_eq!(block, vec![0_u16]);
}

#[test]
fn test_build_environment_block_utf16_single_entry() {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin".to_string());
    let block = build_environment_block_utf16(&env);
    // "PATH=/usr/bin\0\0"
    let expected: Vec<u16> = "PATH=/usr/bin\0"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    assert_eq!(block, expected);
}

#[test]
fn test_build_environment_block_utf16_multiple_entries() {
    let mut env = BTreeMap::new();
    env.insert("A".to_string(), "1".to_string());
    env.insert("B".to_string(), "2".to_string());
    let block = build_environment_block_utf16(&env);
    // BTreeMap iterates in key order: A=1\0 B=2\0 \0
    let mut expected: Vec<u16> = Vec::new();
    expected.extend("A=1\0".encode_utf16());
    expected.extend("B=2\0".encode_utf16());
    expected.push(0);
    assert_eq!(block, expected);
}

// ---------------------------------------------------------------------------
// windows_command_line_to_argv
// ---------------------------------------------------------------------------

#[test]
fn test_windows_command_line_to_argv_simple() {
    let argv = windows_command_line_to_argv("app.exe --help");
    assert_eq!(argv, vec!["app.exe", "--help"]);
}

#[test]
fn test_windows_command_line_to_argv_quoted() {
    let argv = windows_command_line_to_argv("\"app.exe\" \"-o output.txt\"");
    assert_eq!(argv, vec!["app.exe", "-o output.txt"]);
}

#[test]
fn test_windows_command_line_to_argv_empty() {
    let argv = windows_command_line_to_argv("");
    assert_eq!(argv, Vec::<String>::new());
}

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

#[test]
fn test_create_process_w_state() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    // Check process state via process_state()
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    assert_eq!(state.process_id, result.process_id);
    assert_eq!(state.executable, "C:\\test.exe");
    assert_eq!(state.cwd, "C:\\");
    assert_eq!(state.exit_code, None); // still running
}

#[test]
fn test_create_process_w_consecutive_ids_increment() {
    let (_tmp, mut win32) = setup_win32();
    let r1 = create_test_process(&mut win32, "C:\\a.exe", "a.exe", false);
    let r2 = create_test_process(&mut win32, "C:\\b.exe", "b.exe", false);
    assert_eq!(r2.process_id, r1.process_id + 1);
    assert_eq!(r2.thread_id, r1.thread_id + 1);
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

#[test]
fn test_create_process_w_inherit_handles_false() {
    let (_tmp, mut win32) = setup_win32();
    // Create an inheritable handle.
    let (_evt, _) = win32.create_event(true, true, true, None);

    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    // When inherit_handles is false, inherited_handles should be empty.
    assert!(
        state.inherited_handles.is_empty(),
        "inherited_handles should be empty when bInheritHandles is FALSE"
    );
}

// ---------------------------------------------------------------------------
// Process exit code
// ---------------------------------------------------------------------------

#[test]
fn test_set_process_exit_code() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    // Initially no exit code.
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    assert_eq!(state.exit_code, None);

    // Set exit code.
    win32
        .set_process_exit_code(result.process_handle, 42)
        .expect("set exit code");
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    assert_eq!(state.exit_code, Some(42));
}

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

#[test]
fn test_wait_for_single_object_process_with_exit_sync() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    // Install the exit-sync condvar pair.
    let sync = Arc::new((Mutex::new(None::<u32>), Condvar::new()));
    win32
        .install_process_exit_sync(result.process_handle, sync.clone())
        .expect("install_process_exit_sync");

    // Simulate what the background monitor thread does in
    // set_process_exit_code_and_notify: set a value into the condvar guard
    // and notify all waiters.
    let sync_clone = sync.clone();
    std::thread::spawn(move || {
        let (lock, cvar) = &*sync_clone;
        let mut guard = lock.lock().unwrap();
        *guard = Some(0);
        cvar.notify_all();
    })
    .join()
    .expect("notify thread");

    // Now wait should succeed with WAIT_OBJECT_0 (the exit sync was triggered).
    let status = win32
        .wait_for_single_object(result.process_handle, 5000, false, None)
        .expect("wait_for_single_object");
    assert_eq!(status, WaitStatus::Object0);

    // NOTE: wait_for_single_object only *reads* the condvar to decide whether
    // to return Object0; it does NOT update the process object's exit_code field.
    // The exit code must be set explicitly via set_process_exit_code (which
    // is tested separately in test_set_process_exit_code_and_notify).
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    assert_eq!(state.exit_code, None);
}

// ---------------------------------------------------------------------------
// OpenProcess
// ---------------------------------------------------------------------------

#[test]
fn test_open_process_by_id() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    // Open the same process by its process ID.
    let opened = win32
        .open_process(0x1F0FFF, false, result.process_id)
        .expect("open_process");
    assert_ne!(opened, 0);

    let state = win32.process_state(opened).expect("process_state");
    assert_eq!(state.process_id, result.process_id);
}

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

#[test]
fn test_create_process_w_round_trip_with_env_and_cwd() {
    let (_tmp, mut win32) = setup_win32();

    let mut env = BTreeMap::new();
    env.insert("MY_VAR".to_string(), "my_value".to_string());
    env.insert("PATH".to_string(), "C:\\Windows".to_string());

    let result = win32
        .create_process_w(
            "C:\\tools\\my_app.exe",
            "my_app.exe --output result.txt",
            &env,
            "C:\\workdir",
            false,
        )
        .expect("create_process_w with env and cwd");

    assert_ne!(result.process_handle, 0);
    assert!(result.process_id > 0);

    // Verify process state includes the custom env and cwd.
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    assert_eq!(state.executable, "C:\\tools\\my_app.exe");
    assert_eq!(state.cwd, "C:\\workdir");
    assert_eq!(
        state.environment.get("MY_VAR"),
        Some(&"my_value".to_string())
    );
    assert_eq!(
        state.environment.get("PATH"),
        Some(&"C:\\Windows".to_string())
    );

    // The environment block UTF-16 output should include both entries.
    let block_str = String::from_utf16_lossy(&result.environment_block_utf16);
    assert!(block_str.contains("MY_VAR=my_value"));
    assert!(block_str.contains("PATH=C:\\Windows"));

    // Set exit code after simulated completion.
    win32
        .set_process_exit_code(result.process_handle, 7)
        .expect("set exit code");
    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    assert_eq!(state.exit_code, Some(7));
}

// ---------------------------------------------------------------------------
// set_process_exit_code_and_notify — verifies the notify path used by
// launch_guest_child_process background threads.
// ---------------------------------------------------------------------------

#[test]
fn test_set_process_exit_code_and_notify() {
    let (_tmp, mut win32) = setup_win32();
    let result = create_test_process(&mut win32, "C:\\test.exe", "test.exe", false);

    let sync = Arc::new((Mutex::new(None::<u32>), Condvar::new()));
    win32
        .install_process_exit_sync(result.process_handle, sync.clone())
        .expect("install_process_exit_sync");

    // Spawn a waiter thread.
    let sync_clone = sync.clone();
    let waiter = std::thread::spawn(move || {
        let (lock, cvar) = &*sync_clone;
        let mut guard = lock.lock().unwrap();
        while guard.is_none() {
            guard = cvar.wait(guard).unwrap();
        }
        guard.unwrap()
    });

    // Notify from the main thread.
    win32
        .set_process_exit_code_and_notify(result.process_handle, 99)
        .expect("set_process_exit_code_and_notify");

    let exit_code = waiter.join().expect("waiter thread");
    assert_eq!(exit_code, 99);

    let state = win32
        .process_state(result.process_handle)
        .expect("process_state");
    assert_eq!(state.exit_code, Some(99));
}

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
