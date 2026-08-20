//! Stage-4 NTDLL — the synchronization surface (`NtCreateEvent`,
//! `NtSetEvent`, `NtClearEvent`, wait machinery).
//!
//! Event objects live in the ONE kernel-object namespace of the
//! [`crate::win32::Win32Subsystem`] (the same objects `CreateEventW` /
//! `SetEvent` / `ResetEvent` operate on), so a handle minted on either side
//! waits/signals on the other.
//!
//! Waits route through the guest scheduler's wait-descriptor machinery:
//! [`crate::runtime::scheduler::GuestWait`] + `park_for_wait` — the same
//! cooperative park the `WaitForSingleObject` thunk uses.  The Nt layer
//! never blocks the host thread.  The dispatch wiring owns the descriptor
//! construction (it needs the runtime); this module owns the object-side
//! operations and the wait-status domain.

use crate::ntdll::{NtStatus, STATUS_INVALID_PARAMETER};
use crate::win32::Win32Subsystem;

/// `NtCreateEvent` — create (or open, when `name` matches an existing event)
/// a notification (manual-reset) or synchronization (auto-reset) event with
/// `initial_state`.  Returns the handle; `Ok(true)` reports that the event
/// already existed (the caller's `EventHandleCreated` / collision reporting
/// uses it — Windows NtCreateEvent reports STATUS_OBJECT_NAME_COLLISION only
/// when the existing object's attributes conflict, which this layer does not
/// model, so the existing object's handle is returned with STATUS_SUCCESS).
pub fn nt_create_event(
    win32: &mut Win32Subsystem,
    event_type: u32,
    initial_state: bool,
    name: Option<&str>,
) -> Result<(u32, bool), NtStatus> {
    match event_type {
        crate::ntdll::EVENT_TYPE_NOTIFICATION | crate::ntdll::EVENT_TYPE_SYNCHRONIZATION => {}
        _ => return Err(STATUS_INVALID_PARAMETER),
    }
    let manual_reset = event_type == crate::ntdll::EVENT_TYPE_NOTIFICATION;
    let (handle, already_exists) = win32.create_event(manual_reset, initial_state, false, name);
    Ok((handle, already_exists))
}

/// `NtSetEvent` — signal the event; returns the previous signal state
/// (the `PreviousState` out-parameter).  Non-event handles are
/// `STATUS_INVALID_HANDLE`.
pub fn nt_set_event(win32: &mut Win32Subsystem, handle: u32) -> Result<bool, NtStatus> {
    let previous = win32
        .event_previous_state(handle)
        .map_err(nt_status_from_win32_error)?;
    win32
        .set_event(handle)
        .map_err(nt_status_from_win32_error)?;
    Ok(previous)
}

/// `NtClearEvent` — reset the event; returns the previous signal state.
pub fn nt_clear_event(win32: &mut Win32Subsystem, handle: u32) -> Result<bool, NtStatus> {
    let previous = win32
        .event_previous_state(handle)
        .map_err(nt_status_from_win32_error)?;
    win32
        .reset_event(handle)
        .map_err(nt_status_from_win32_error)?;
    Ok(previous)
}

/// Map an `AppError` from the Win32 object layer to the canonical NTSTATUS
/// (the Win32 wrapper boundary: the Nt layer never leaks DOS errors).
pub fn nt_status_from_win32_error(error: crate::error::AppError) -> NtStatus {
    error.code.nt_status()
}

/// `NtWaitForSingleObject`'s timeout parameter is a relative 100 ns
/// interval; `u64::MAX` means infinite.  Convert to guest-clock ticks
/// (milliseconds) with ceiling rounding, returning `None` for infinite.
pub fn timeout_100ns_to_ticks(timeout_100ns: u64) -> Option<u64> {
    if timeout_100ns == u64::MAX {
        return None;
    }
    // Ceiling division so a sub-millisecond timeout still wakes up.
    Some(timeout_100ns.saturating_add(9999) / 10_000)
}

/// The Nt wait-status codes (STATUS_WAIT_0 + index, STATUS_ABANDONED_0 +
/// index, STATUS_TIMEOUT) — the same numeric domain the scheduler's
/// `WaitResume` carries.
#[allow(dead_code)]
const _: u32 = crate::ntdll::STATUS_OBJECT_NAME_COLLISION.raw();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use crate::ntdll::{STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE};
    use tempfile::TempDir;

    fn setup() -> (TempDir, Win32Subsystem) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "ntdll-sync", GeArch::X64, "win11-23h2")
                .expect("create GE");
        let win32 = Win32Subsystem::new(ge, true);
        (temp_dir, win32)
    }

    #[test]
    fn create_set_clear_event_round_trip_through_the_object_manager() {
        let (_tmp, mut win32) = setup();
        let (handle, existed) = nt_create_event(
            &mut win32,
            crate::ntdll::EVENT_TYPE_SYNCHRONIZATION,
            false,
            None,
        )
        .expect("create event");
        assert!(!existed);
        // Auto-reset event: set reports the previous (false) state.
        assert_eq!(nt_set_event(&mut win32, handle), Ok(false));
        assert_eq!(nt_set_event(&mut win32, handle), Ok(true));
        assert_eq!(nt_clear_event(&mut win32, handle), Ok(true));
        assert_eq!(nt_clear_event(&mut win32, handle), Ok(false));
        // A named event resolves to the same object.
        let (named, existed) = nt_create_event(
            &mut win32,
            crate::ntdll::EVENT_TYPE_NOTIFICATION,
            true,
            Some("Casa1NtTestEvent"),
        )
        .expect("named event");
        assert!(!existed);
        let (same, existed) = nt_create_event(
            &mut win32,
            crate::ntdll::EVENT_TYPE_NOTIFICATION,
            false,
            Some("Casa1NtTestEvent"),
        )
        .expect("reopen named event");
        assert!(existed);
        assert_ne!(same, named);
        assert_eq!(nt_set_event(&mut win32, same), Ok(true), "shared object");
    }

    #[test]
    fn event_ops_validate_handles_and_types() {
        let (_tmp, mut win32) = setup();
        assert_eq!(nt_set_event(&mut win32, 0xBAD), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            nt_create_event(&mut win32, 77, false, None,),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn timeout_conversion_matches_nt_100ns_units() {
        assert_eq!(timeout_100ns_to_ticks(u64::MAX), None);
        assert_eq!(timeout_100ns_to_ticks(0), Some(0));
        assert_eq!(timeout_100ns_to_ticks(10_000), Some(1));
        assert_eq!(timeout_100ns_to_ticks(10_001), Some(2));
        assert_eq!(timeout_100ns_to_ticks(1_000_000), Some(100));
    }

    #[allow(dead_code)]
    const _: NtStatus = STATUS_ACCESS_DENIED;
}
