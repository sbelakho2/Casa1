//! Canonical NTSTATUS values used by the CasaK executive personality.
//!
//! The object and I/O modules predate this list and keep their public
//! constants for compatibility. New executive modules import from here so the
//! exact status contract is defined once for processes, memory, security,
//! configuration, ALPC, power and diagnostics.

use crate::casak::object::NtStatus;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_WAIT_0: NtStatus = 0;
pub const STATUS_ABANDONED_WAIT_0: NtStatus = 0x0000_0080;
pub const STATUS_USER_APC: NtStatus = 0x0000_00C0;
pub const STATUS_TIMEOUT: NtStatus = 0x0000_0102;
pub const STATUS_PENDING: NtStatus = 0x0000_0103;
pub const STATUS_BUFFER_OVERFLOW: NtStatus = 0x8000_0005u32 as NtStatus;
pub const STATUS_NO_MORE_ENTRIES: NtStatus = 0x8000_001Au32 as NtStatus;
pub const STATUS_INVALID_INFO_CLASS: NtStatus = 0xC000_0003u32 as NtStatus;
pub const STATUS_ACCESS_VIOLATION: NtStatus = 0xC000_0005u32 as NtStatus;
pub const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008u32 as NtStatus;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as NtStatus;
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010u32 as NtStatus;
pub const STATUS_MORE_PROCESSING_REQUIRED: NtStatus = 0xC000_0016u32 as NtStatus;
pub const STATUS_NO_MEMORY: NtStatus = 0xC000_0017u32 as NtStatus;
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = 0xC000_0018u32 as NtStatus;
pub const STATUS_INVALID_VIEW_SIZE: NtStatus = 0xC000_001Fu32 as NtStatus;
pub const STATUS_ALREADY_COMMITTED: NtStatus = 0xC000_0021u32 as NtStatus;
pub const STATUS_ACCESS_DENIED: NtStatus = 0xC000_0022u32 as NtStatus;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023u32 as NtStatus;
pub const STATUS_NOT_COMMITTED: NtStatus = 0xC000_002Du32 as NtStatus;
pub const STATUS_INVALID_PORT_ATTRIBUTES: NtStatus = 0xC000_002Eu32 as NtStatus;
pub const STATUS_PORT_MESSAGE_TOO_LONG: NtStatus = 0xC000_002Fu32 as NtStatus;
pub const STATUS_OBJECT_TYPE_MISMATCH: NtStatus = 0xC000_00EAu32 as NtStatus;
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = 0xC000_0033u32 as NtStatus;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034u32 as NtStatus;
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035u32 as NtStatus;
pub const STATUS_PORT_DISCONNECTED: NtStatus = 0xC000_0037u32 as NtStatus;
pub const STATUS_OBJECT_PATH_INVALID: NtStatus = 0xC000_0039u32 as NtStatus;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = 0xC000_003Au32 as NtStatus;
pub const STATUS_SECTION_TOO_BIG: NtStatus = 0xC000_0040u32 as NtStatus;
pub const STATUS_PORT_CONNECTION_REFUSED: NtStatus = 0xC000_0041u32 as NtStatus;
pub const STATUS_INVALID_PORT_HANDLE: NtStatus = 0xC000_0042u32 as NtStatus;
pub const STATUS_INVALID_PAGE_PROTECTION: NtStatus = 0xC000_0045u32 as NtStatus;
pub const STATUS_SEMAPHORE_LIMIT_EXCEEDED: NtStatus = 0xC000_0047u32 as NtStatus;
pub const STATUS_INVALID_SID: NtStatus = 0xC000_0078u32 as NtStatus;
pub const STATUS_SECTION_NOT_EXTENDED: NtStatus = 0xC000_0087u32 as NtStatus;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009Au32 as NtStatus;
pub const STATUS_DEVICE_NOT_READY: NtStatus = 0xC000_00A3u32 as NtStatus;
pub const STATUS_NOT_SUPPORTED: NtStatus = 0xC000_00BBu32 as NtStatus;
pub const STATUS_PROCESS_IS_TERMINATING: NtStatus = 0xC000_010Au32 as NtStatus;
pub const STATUS_CANCELLED: NtStatus = 0xC000_0120u32 as NtStatus;
pub const STATUS_COMMITMENT_LIMIT: NtStatus = 0xC000_012Du32 as NtStatus;
pub const STATUS_INVALID_ADDRESS: NtStatus = 0xC000_0141u32 as NtStatus;
pub const STATUS_KEY_HAS_CHILDREN: NtStatus = 0xC000_0180u32 as NtStatus;
pub const STATUS_INVALID_DEVICE_STATE: NtStatus = 0xC000_0184u32 as NtStatus;
pub const STATUS_REPLY_MESSAGE_MISMATCH: NtStatus = 0xC000_021Fu32 as NtStatus;
pub const STATUS_NOT_FOUND: NtStatus = 0xC000_0225u32 as NtStatus;
pub const STATUS_PORT_UNREACHABLE: NtStatus = 0xC000_023Fu32 as NtStatus;
pub const STATUS_POWER_STATE_INVALID: NtStatus = 0xC000_02D3u32 as NtStatus;
pub const STATUS_DEVICE_HARDWARE_ERROR: NtStatus = 0xC000_0483u32 as NtStatus;
pub const STATUS_PRIVILEGE_NOT_HELD: NtStatus = 0xC000_0061u32 as NtStatus;
pub const STATUS_THREAD_IS_TERMINATING: NtStatus = 0xC000_004Bu32 as NtStatus;
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001u32 as NtStatus;
pub const STATUS_DELETE_PENDING: NtStatus = 0xC000_0056u32 as NtStatus;

/// Returns `true` for a successful or informational status (bit 31 clear).
pub const fn is_success(status: NtStatus) -> bool {
    status >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_helpers_reject_error_and_accept_warning_codes() {
        assert_eq!(is_success(STATUS_SUCCESS), true);
        assert_eq!(is_success(STATUS_TIMEOUT), true);
        assert_eq!(is_success(STATUS_BUFFER_OVERFLOW), false);
        assert_eq!(is_success(STATUS_ACCESS_DENIED), false);
        assert_eq!(is_success(STATUS_PENDING), true);
    }
}
