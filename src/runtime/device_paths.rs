//! Serial/USB dispatch-path helpers.

use super::*;

/// Maps an `AppError` to the Win32 `GetLastError` value the thunks record.
/// Public so the release gates can pin Steam's observed error codes against
/// the exact mapping the thunks use (this is the guest-visible mapping, not
/// `AppError::last_error()`).
pub const IOCTL_USB_ENUMERATE_DEVICES: u32 = 0x0022_2400;
pub(crate) const IOCTL_USB_VALIDATE_TRANSFER: u32 = 0x0022_2404;
pub(crate) const IOCTL_USB_SUBMIT_TRANSFER: u32 = 0x0022_2408;

#[derive(Debug)]
pub(crate) enum DispatchOpenError {
    NotFound,
    InvalidParameter,
    Device(crate::real_hid::DeviceError),
}

pub(crate) fn dispatch_open_error_win32(error: &DispatchOpenError) -> u32 {
    match error {
        DispatchOpenError::NotFound => ERROR_FILE_NOT_FOUND,
        DispatchOpenError::InvalidParameter => ERROR_INVALID_PARAMETER,
        DispatchOpenError::Device(error) => error.windows_error(),
    }
}

pub(crate) fn com_port_index(path: &str) -> Option<u32> {
    let upper = path.to_ascii_uppercase();
    let rest = upper.strip_prefix("\\\\.\\COM")?;
    if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
}

pub(crate) fn looks_like_serial_path(path: &str) -> bool {
    path.to_ascii_uppercase().starts_with("\\\\.\\COM") || path.starts_with("/dev/")
}

pub(crate) fn looks_like_usb_path(path: &str) -> bool {
    path.starts_with("\\\\.\\Casa1Usb#")
}

pub(crate) fn parse_usb_dispatch_path(path: &str) -> Option<u64> {
    let rest = path.strip_prefix("\\\\.\\Casa1Usb#")?;
    (rest.len() == 16 && rest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(rest, 16).ok())
        .flatten()
}

pub fn last_error_from_app_error(error: &AppError) -> u32 {
    match error.code {
        ReasonCode::RcFsNotFound => ERROR_FILE_NOT_FOUND,
        ReasonCode::RcFsPathInvalid => ERROR_PATH_NOT_FOUND,
        ReasonCode::RcWin32InvalidHandle => ERROR_INVALID_HANDLE,
        ReasonCode::RcFsSharingViolation => ERROR_SHARING_VIOLATION,
        ReasonCode::RcFsLockViolation => ERROR_LOCK_VIOLATION,
        ReasonCode::RcFsAlreadyExists => ERROR_ALREADY_EXISTS,
        ReasonCode::RcCliInvalid => ERROR_INVALID_PARAMETER,
        ReasonCode::RcWin32NotOwner => 288, // ERROR_NOT_OWNER
        _ => ERROR_ACCESS_DENIED,
    }
}
