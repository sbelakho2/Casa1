//! Exact physical-device errors.  These are deliberately typed (not strings so
//! dispatch can map them to Windows status codes) and stable enough for tests
//! to pin every failure path: permission, unplugged, unsupported, busy, missing,
//! malformed report, invalid configuration, and double open/close.

use crate::error::AppError;
use crate::reason::ReasonCode;

use super::model::StableDeviceId;
use super::usb::UsbTransferType;

/// An exact host-device failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    PermissionDenied {
        operation: &'static str,
    },
    DeviceMissing {
        id: StableDeviceId,
    },
    Unplugged {
        id: StableDeviceId,
    },
    Unsupported {
        feature: &'static str,
    },
    UnsupportedTransferFlag {
        flag: u32,
    },
    UnsupportedTransferType {
        kind: UsbTransferType,
    },
    Busy {
        path: String,
    },
    AlreadyOpen {
        id: StableDeviceId,
    },
    AlreadyClosed {
        id: StableDeviceId,
    },
    InvalidArgument {
        field: &'static str,
        reason: &'static str,
    },
    InvalidReportLength {
        expected: usize,
        actual: usize,
    },
    VendorMismatch {
        id: StableDeviceId,
        expected_vendor: u16,
        expected_product: u16,
        actual_vendor: u16,
        actual_product: u16,
    },
    EndpointMissing {
        interface: u8,
        endpoint: u8,
    },
    MalformedDescriptor {
        offset: usize,
        reason: &'static str,
    },
    Timeout {
        timeout_ms: u64,
    },
    Io {
        operation: &'static str,
        os_code: i32,
    },
    NotOpen {
        id: StableDeviceId,
    },
}

impl DeviceError {
    /// Best-effort Windows `GetLastError` value for host dispatch.
    pub const fn windows_error(&self) -> u32 {
        match self {
            Self::PermissionDenied { .. } => 5,
            Self::DeviceMissing { .. } | Self::Unplugged { .. } => 1167,
            Self::Unsupported { .. }
            | Self::UnsupportedTransferFlag { .. }
            | Self::UnsupportedTransferType { .. } => 50,
            Self::Busy { .. } => 32,
            Self::AlreadyOpen { .. } | Self::AlreadyClosed { .. } => 6,
            Self::InvalidArgument { .. }
            | Self::InvalidReportLength { .. }
            | Self::VendorMismatch { .. }
            | Self::EndpointMissing { .. }
            | Self::MalformedDescriptor { .. } => 87,
            Self::Timeout { .. } => 1460,
            Self::Io { .. } => 1117,
            Self::NotOpen { .. } => 6,
        }
    }

    pub fn to_app_error(&self) -> AppError {
        AppError::new(self.reason_code(), self.to_string())
    }

    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            Self::PermissionDenied { .. } => ReasonCode::RcWin32AccessDenied,
            Self::DeviceMissing { .. } | Self::Unplugged { .. } => ReasonCode::RcNotFound,
            Self::Unsupported { .. }
            | Self::UnsupportedTransferFlag { .. }
            | Self::UnsupportedTransferType { .. } => ReasonCode::RcInputUnsupported,
            Self::Busy { .. } => ReasonCode::RcPipeBusy,
            Self::AlreadyOpen { .. } | Self::AlreadyClosed { .. } | Self::NotOpen { .. } => {
                ReasonCode::RcInvalidState
            }
            Self::InvalidArgument { .. }
            | Self::InvalidReportLength { .. }
            | Self::VendorMismatch { .. }
            | Self::EndpointMissing { .. }
            | Self::MalformedDescriptor { .. } => ReasonCode::RcInvalidParameter,
            Self::Timeout { .. } | Self::Io { .. } => ReasonCode::RcIo,
        }
    }
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied { operation } => {
                write!(f, "permission denied during {operation}")
            }
            Self::DeviceMissing { id } => write!(f, "device {id} is not present"),
            Self::Unplugged { id } => write!(f, "device {id} was unplugged"),
            Self::Unsupported { feature } => write!(f, "unsupported feature: {feature}"),
            Self::UnsupportedTransferFlag { flag } => {
                write!(f, "unsupported USB transfer flag 0x{flag:08x}")
            }
            Self::UnsupportedTransferType { kind } => {
                write!(f, "unsupported USB transfer type {kind:?}")
            }
            Self::Busy { path } => write!(f, "device is busy: {path}"),
            Self::AlreadyOpen { id } => write!(f, "device {id} is already open"),
            Self::AlreadyClosed { id } => write!(f, "device {id} is already closed"),
            Self::InvalidArgument { field, reason } => {
                write!(f, "invalid {field}: {reason}")
            }
            Self::InvalidReportLength { expected, actual } => {
                write!(
                    f,
                    "invalid report length {actual}; expected at most {expected}"
                )
            }
            Self::VendorMismatch {
                id,
                expected_vendor,
                expected_product,
                actual_vendor,
                actual_product,
            } => write!(
                f,
                "device {id} vendor mismatch: expected {expected_vendor:04x}:{expected_product:04x}, got {actual_vendor:04x}:{actual_product:04x}"
            ),
            Self::EndpointMissing {
                interface,
                endpoint,
            } => write!(
                f,
                "USB interface {interface} has no endpoint 0x{endpoint:02x}"
            ),
            Self::MalformedDescriptor { offset, reason } => {
                write!(f, "malformed descriptor at offset {offset}: {reason}")
            }
            Self::Timeout { timeout_ms } => write!(f, "I/O timed out after {timeout_ms} ms"),
            Self::Io { operation, os_code } => {
                write!(f, "{operation} failed with OS error {os_code}")
            }
            Self::NotOpen { id } => write!(f, "device {id} is not open"),
        }
    }
}

impl std::error::Error for DeviceError {}

impl From<DeviceError> for AppError {
    fn from(error: DeviceError) -> Self {
        error.to_app_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_error_every_variant_maps_to_exact_windows_and_reason_code() {
        let id = StableDeviceId::from_raw(0x42);
        let cases = vec![
            (
                DeviceError::PermissionDenied {
                    operation: "IOHIDDeviceOpen",
                },
                5,
                ReasonCode::RcWin32AccessDenied,
                "permission denied during IOHIDDeviceOpen",
            ),
            (
                DeviceError::DeviceMissing { id },
                1167,
                ReasonCode::RcNotFound,
                "device 0000000000000042 is not present",
            ),
            (
                DeviceError::Unplugged { id },
                1167,
                ReasonCode::RcNotFound,
                "device 0000000000000042 was unplugged",
            ),
            (
                DeviceError::Unsupported { feature: "x" },
                50,
                ReasonCode::RcInputUnsupported,
                "unsupported feature: x",
            ),
            (
                DeviceError::UnsupportedTransferFlag { flag: 0x10 },
                50,
                ReasonCode::RcInputUnsupported,
                "unsupported USB transfer flag 0x00000010",
            ),
            (
                DeviceError::UnsupportedTransferType {
                    kind: UsbTransferType::Bulk,
                },
                50,
                ReasonCode::RcInputUnsupported,
                "unsupported USB transfer type Bulk",
            ),
            (
                DeviceError::Busy {
                    path: "/dev/cu.test".to_string(),
                },
                32,
                ReasonCode::RcPipeBusy,
                "device is busy: /dev/cu.test",
            ),
            (
                DeviceError::AlreadyOpen { id },
                6,
                ReasonCode::RcInvalidState,
                "device 0000000000000042 is already open",
            ),
            (
                DeviceError::AlreadyClosed { id },
                6,
                ReasonCode::RcInvalidState,
                "device 0000000000000042 is already closed",
            ),
            (
                DeviceError::InvalidArgument {
                    field: "baud_rate",
                    reason: "unsupported rate",
                },
                87,
                ReasonCode::RcInvalidParameter,
                "invalid baud_rate: unsupported rate",
            ),
            (
                DeviceError::InvalidReportLength {
                    expected: 8,
                    actual: 9,
                },
                87,
                ReasonCode::RcInvalidParameter,
                "invalid report length 9; expected at most 8",
            ),
            (
                DeviceError::VendorMismatch {
                    id,
                    expected_vendor: 0x054c,
                    expected_product: 0x0ce6,
                    actual_vendor: 0x045e,
                    actual_product: 0x028e,
                },
                87,
                ReasonCode::RcInvalidParameter,
                "device 0000000000000042 vendor mismatch: expected 054c:0ce6, got 045e:028e",
            ),
            (
                DeviceError::EndpointMissing {
                    interface: 1,
                    endpoint: 0x82,
                },
                87,
                ReasonCode::RcInvalidParameter,
                "USB interface 1 has no endpoint 0x82",
            ),
            (
                DeviceError::MalformedDescriptor {
                    offset: 4,
                    reason: "truncated",
                },
                87,
                ReasonCode::RcInvalidParameter,
                "malformed descriptor at offset 4: truncated",
            ),
            (
                DeviceError::Timeout { timeout_ms: 5 },
                1460,
                ReasonCode::RcIo,
                "I/O timed out after 5 ms",
            ),
            (
                DeviceError::Io {
                    operation: "read",
                    os_code: 9,
                },
                1117,
                ReasonCode::RcIo,
                "read failed with OS error 9",
            ),
            (
                DeviceError::NotOpen { id },
                6,
                ReasonCode::RcInvalidState,
                "device 0000000000000042 is not open",
            ),
        ];
        for (error, windows, reason, text) in &cases {
            assert_eq!(error.windows_error(), *windows);
            assert_eq!(error.reason_code(), *reason);
            assert_eq!(error.to_string(), *text);
            let app = error.to_app_error();
            assert_eq!(app.code, *reason);
            assert_eq!(app.message, *text);
        }
        let converted: AppError = cases[1].0.clone().into();
        assert_eq!(converted.code, ReasonCode::RcNotFound);
        assert_eq!(converted.message, cases[1].3);
        assert!(std::error::Error::source(&cases[0].0).is_none());
    }
}
