//! Real serial-port enumeration through IOKit and native termios I/O.
//!
//! Enumeration walks `IOSerialBSDClient` services and exposes the callout
//! (`/dev/cu.*`) and dialin (`/dev/tty.*`) paths.  Open/config/read/write use
//! the real BSD device with an exclusive advisory lock; absent hardware yields
//! an empty table and every operation returns a typed failure.

use std::time::Duration;
#[cfg(all(target_os = "macos", not(test)))]
use std::time::Instant;

use super::error::DeviceError;
use super::model::{
    DeviceClass, DeviceRecord, DeviceTable, HotplugEvent, OpenState, StableDeviceId,
};

#[cfg(all(target_os = "macos", not(test)))]
use super::ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialParity {
    None,
    Odd,
    Even,
    Mark,
    Space,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialStopBits {
    One,
    OnePointFive,
    Two,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialConfig {
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: SerialParity,
    pub stop_bits: SerialStopBits,
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            baud_rate: 115_200,
            data_bits: 8,
            parity: SerialParity::None,
            stop_bits: SerialStopBits::One,
        }
    }
}

impl SerialConfig {
    pub fn validate(self) -> Result<(), DeviceError> {
        if !supported_baud(self.baud_rate) {
            return Err(DeviceError::InvalidArgument {
                field: "baud_rate",
                reason: "unsupported rate",
            });
        }
        if !(5..=8).contains(&self.data_bits) {
            return Err(DeviceError::InvalidArgument {
                field: "data_bits",
                reason: "must be between 5 and 8",
            });
        }
        match self.parity {
            SerialParity::None | SerialParity::Odd | SerialParity::Even => {}
            SerialParity::Mark | SerialParity::Space => {
                return Err(DeviceError::Unsupported {
                    feature: "serial parity mark/space",
                });
            }
        }
        if self.stop_bits == SerialStopBits::OnePointFive {
            return Err(DeviceError::Unsupported {
                feature: "serial 1.5 stop bits",
            });
        }
        Ok(())
    }
}

fn supported_baud(baud: u32) -> bool {
    matches!(
        baud,
        50 | 75
            | 110
            | 134
            | 150
            | 200
            | 300
            | 600
            | 1200
            | 1800
            | 2400
            | 4800
            | 7200
            | 9600
            | 14400
            | 19200
            | 28800
            | 38400
            | 57600
            | 76800
            | 115_200
            | 230_400
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialDeviceInfo {
    pub id: StableDeviceId,
    pub registry_entry_id: u64,
    pub callout_path: String,
    pub dialin_path: Option<String>,
    pub tty_device: Option<String>,
    pub base_name: Option<String>,
    pub client_type: Option<String>,
}

impl SerialDeviceInfo {
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            id: self.id,
            class: DeviceClass::Serial,
            vendor_id: None,
            product_id: None,
            manufacturer: None,
            product: self.tty_device.clone(),
            serial_number: None,
            path: Some(self.callout_path.clone()),
            registry_entry_id: self.registry_entry_id,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SerialBridge {
    devices: Vec<SerialDeviceInfo>,
    table: DeviceTable,
}

impl SerialBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &[SerialDeviceInfo] {
        &self.devices
    }

    pub fn table(&self) -> &DeviceTable {
        &self.table
    }

    pub fn device(&self, id: StableDeviceId) -> Option<&SerialDeviceInfo> {
        self.devices.iter().find(|device| device.id == id)
    }

    pub fn apply(&mut self, devices: Vec<SerialDeviceInfo>) -> Vec<HotplugEvent> {
        let mut devices = devices;
        devices.sort_by_key(|device| device.id);
        let records = devices.iter().map(SerialDeviceInfo::record).collect();
        self.devices = devices;
        self.table.reconcile(records)
    }

    pub fn enumerate(&mut self) -> Result<Vec<HotplugEvent>, DeviceError> {
        let devices = scan_serial_devices()?;
        Ok(self.apply(devices))
    }

    pub fn open(
        &self,
        id: StableDeviceId,
        config: SerialConfig,
    ) -> Result<SerialDevice, DeviceError> {
        let info = self
            .device(id)
            .ok_or(DeviceError::DeviceMissing { id })?
            .clone();
        SerialDevice::open_info(&info, config)
    }
}

pub struct SerialDevice {
    #[cfg(all(target_os = "macos", not(test)))]
    fd: std::os::fd::RawFd,
    info: SerialDeviceInfo,
    config: SerialConfig,
    state: OpenState,
}

impl SerialDevice {
    #[cfg(test)]
    pub(crate) fn test_device(path: &str) -> Self {
        let info = SerialDeviceInfo {
            id: StableDeviceId::derive(crate::real_hid::DeviceClass::Serial, &[path]),
            registry_entry_id: 1,
            callout_path: path.to_string(),
            dialin_path: None,
            tty_device: None,
            base_name: None,
            client_type: Some("IOSerialBSDClient".to_string()),
        };
        let mut state = OpenState::default();
        let _ = state.begin(info.id);
        Self {
            info,
            config: SerialConfig::default(),
            state,
        }
    }

    pub fn id(&self) -> StableDeviceId {
        self.info.id
    }

    pub fn path(&self) -> &str {
        &self.info.callout_path
    }

    pub fn config(&self) -> SerialConfig {
        self.config
    }

    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    #[cfg(all(target_os = "macos", not(test)))]
    fn open_info(info: &SerialDeviceInfo, config: SerialConfig) -> Result<Self, DeviceError> {
        config.validate()?;
        let fd = open_exclusive(info)?;
        let mut device = Self {
            fd,
            info: info.clone(),
            config,
            state: OpenState::default(),
        };
        if let Err(error) = apply_termios(fd, config) {
            let _ = device.close_fd();
            return Err(error);
        }
        device.state.begin(info.id)?;
        Ok(device)
    }

    #[cfg(test)]
    fn open_info(info: &SerialDeviceInfo, config: SerialConfig) -> Result<Self, DeviceError> {
        config.validate()?;
        let mut state = OpenState::default();
        state.begin(info.id)?;
        Ok(Self {
            info: info.clone(),
            config,
            state,
        })
    }

    #[cfg(all(not(target_os = "macos"), not(test)))]
    fn open_info(_info: &SerialDeviceInfo, _config: SerialConfig) -> Result<Self, DeviceError> {
        Err(DeviceError::Unsupported {
            feature: "serial access requires macOS termios",
        })
    }

    pub fn configure(&mut self, config: SerialConfig) -> Result<(), DeviceError> {
        self.ensure_open()?;
        config.validate()?;
        #[cfg(all(target_os = "macos", not(test)))]
        {
            apply_termios(self.fd, config)?;
        }
        self.config = config;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), DeviceError> {
        self.ensure_open()?;
        #[cfg(all(target_os = "macos", not(test)))]
        {
            // SAFETY: fd is an open terminal descriptor owned by this handle.
            let rc = unsafe { libc::tcflush(self.fd, libc::TCIOFLUSH) };
            if rc != 0 {
                return Err(map_io(
                    "tcflush",
                    self.errno(),
                    self.info.id,
                    &self.info.callout_path,
                ));
            }
        }
        Ok(())
    }

    pub fn read(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<usize, DeviceError> {
        self.ensure_open()?;
        if buffer.is_empty() {
            return Ok(0);
        }
        #[cfg(all(target_os = "macos", not(test)))]
        {
            let timeout_ms = duration_ms(timeout);
            let mut pollfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd is valid for one descriptor.
            let ready = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
            if ready == 0 {
                return Err(DeviceError::Timeout {
                    timeout_ms: timeout_ms as u64,
                });
            }
            if ready < 0 {
                let errno = self.errno();
                if errno == libc::EINTR {
                    return Ok(0);
                }
                return Err(map_io("poll", errno, self.info.id, &self.info.callout_path));
            }
            // SAFETY: buffer is valid for buffer.len() bytes and fd is open.
            let count = unsafe { libc::read(self.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count < 0 {
                let errno = self.errno();
                return Err(map_io("read", errno, self.info.id, &self.info.callout_path));
            }
            if count == 0 {
                return Err(DeviceError::Unplugged { id: self.info.id });
            }
            return Ok(count as usize);
        }
        #[cfg(not(all(target_os = "macos", not(test))))]
        {
            let _ = (buffer, timeout);
            Err(DeviceError::Unsupported {
                feature: "serial read requires macOS termios",
            })
        }
    }

    pub fn write(&mut self, buffer: &[u8], timeout: Duration) -> Result<usize, DeviceError> {
        self.ensure_open()?;
        if buffer.is_empty() {
            return Ok(0);
        }
        #[cfg(all(target_os = "macos", not(test)))]
        {
            let deadline = Instant::now() + timeout;
            let mut written = 0;
            while written < buffer.len() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(DeviceError::Timeout {
                        timeout_ms: duration_ms(timeout) as u64,
                    });
                }
                let mut pollfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: pollfd is valid for one descriptor.
                let ready = unsafe { libc::poll(&mut pollfd, 1, duration_ms(remaining)) };
                if ready == 0 {
                    return Err(DeviceError::Timeout {
                        timeout_ms: duration_ms(timeout) as u64,
                    });
                }
                if ready < 0 {
                    let errno = self.errno();
                    if errno == libc::EINTR {
                        continue;
                    }
                    return Err(map_io("poll", errno, self.info.id, &self.info.callout_path));
                }
                // SAFETY: the slice is valid for the remaining bytes.
                let count = unsafe {
                    libc::write(
                        self.fd,
                        buffer[written..].as_ptr().cast(),
                        buffer.len() - written,
                    )
                };
                if count < 0 {
                    let errno = self.errno();
                    if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                        continue;
                    }
                    return Err(map_io(
                        "write",
                        errno,
                        self.info.id,
                        &self.info.callout_path,
                    ));
                }
                if count == 0 {
                    return Err(DeviceError::Unplugged { id: self.info.id });
                }
                written += count as usize;
            }
            return Ok(written);
        }
        #[cfg(not(all(target_os = "macos", not(test))))]
        {
            let _ = (buffer, timeout);
            Err(DeviceError::Unsupported {
                feature: "serial write requires macOS termios",
            })
        }
    }

    /// EscapeCommFunction passthrough.  Function codes are the Win32
    /// `SETXOFF`(1) .. `CLRBREAK`(9) values; invalid codes are rejected before
    /// touching the terminal.
    pub fn escape(&mut self, function: u32) -> Result<(), DeviceError> {
        self.ensure_open()?;
        if !(1..=9).contains(&function) {
            return Err(DeviceError::InvalidArgument {
                field: "function",
                reason: "unsupported escape function",
            });
        }
        #[cfg(all(target_os = "macos", not(test)))]
        {
            self.escape_platform(function)
        }
        #[cfg(not(all(target_os = "macos", not(test))))]
        {
            let _ = function;
            Err(DeviceError::Unsupported {
                feature: "serial escape function",
            })
        }
    }

    #[cfg(all(target_os = "macos", not(test)))]
    fn escape_platform(&mut self, function: u32) -> Result<(), DeviceError> {
        let ioctl_int = |request: libc::c_ulong, value: libc::c_int| {
            // SAFETY: fd is an owned, open terminal and `value` lives for the
            // duration of the ioctl.
            let rc = unsafe { libc::ioctl(self.fd, request, &value) };
            if rc == 0 {
                Ok(())
            } else {
                Err(map_io(
                    "ioctl",
                    self.errno(),
                    self.info.id,
                    &self.info.callout_path,
                ))
            }
        };
        match function {
            1 => self.tcflow(libc::TCOOFF),
            2 => self.tcflow(libc::TCOON),
            3 => ioctl_int(libc::TIOCMBIS, libc::TIOCM_RTS),
            4 => ioctl_int(libc::TIOCMBIC, libc::TIOCM_RTS),
            5 => ioctl_int(libc::TIOCMBIS, libc::TIOCM_DTR),
            6 => ioctl_int(libc::TIOCMBIC, libc::TIOCM_DTR),
            7 => self.flush(),
            8 => ioctl_int(libc::TIOCSBRK as libc::c_ulong, 0),
            9 => ioctl_int(libc::TIOCCBRK as libc::c_ulong, 0),
            _ => unreachable!("validated escape function"), // coverage: unreachable
        }
    }

    #[cfg(all(target_os = "macos", not(test)))]
    fn tcflow(&self, action: libc::c_int) -> Result<(), DeviceError> {
        // SAFETY: fd is an owned, open terminal descriptor.
        let rc = unsafe { libc::tcflow(self.fd, action) };
        if rc == 0 {
            Ok(())
        } else {
            Err(map_io(
                "tcflow",
                self.errno(),
                self.info.id,
                &self.info.callout_path,
            ))
        }
    }

    pub fn close(&mut self) -> Result<(), DeviceError> {
        let _id = self.state.end()?;
        self.close_fd()
    }

    fn ensure_open(&self) -> Result<(), DeviceError> {
        if self.state.is_open() {
            Ok(())
        } else {
            Err(DeviceError::NotOpen {
                id: self.state.last_id(),
            })
        }
    }

    #[cfg(all(target_os = "macos", not(test)))]
    fn close_fd(&mut self) -> Result<(), DeviceError> {
        if self.fd < 0 {
            return Ok(());
        }
        // SAFETY: fd is an owned, open descriptor.  close releases the flock.
        let rc = unsafe { libc::close(self.fd) };
        self.fd = -1;
        if rc != 0 {
            return Err(DeviceError::Io {
                operation: "close",
                os_code: self.errno(),
            });
        }
        Ok(())
    }

    #[cfg(not(all(target_os = "macos", not(test))))]
    fn close_fd(&mut self) -> Result<(), DeviceError> {
        Ok(())
    }

    #[cfg(all(target_os = "macos", not(test)))]
    fn errno(&self) -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }
}

impl Drop for SerialDevice {
    fn drop(&mut self) {
        if self.state.is_open() {
            let _ = self.close_fd();
            let _ = self.state.end();
        }
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn open_exclusive(info: &SerialDeviceInfo) -> Result<std::os::fd::RawFd, DeviceError> {
    let path = std::ffi::CString::new(info.callout_path.clone()).map_err(|_| {
        DeviceError::InvalidArgument {
            field: "serial_path",
            reason: "contains an interior NUL",
        }
    })?;
    // SAFETY: path is a NUL-terminated filesystem path.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(map_open(errno, info));
    }
    // SAFETY: fd is open; flock only sets advisory state on this descriptor.
    let lock = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if lock != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EWOULDBLOCK || errno == libc::EAGAIN || errno == libc::EBUSY {
            // SAFETY: close the descriptor on the busy path.
            unsafe { libc::close(fd) };
            return Err(DeviceError::Busy {
                path: info.callout_path.clone(),
            });
        }
        if !ignorable_lock_errno(errno) {
            // SAFETY: close the descriptor on the failure path.
            unsafe { libc::close(fd) };
            return Err(map_open(errno, info));
        }
    }
    Ok(fd)
}

#[cfg(all(target_os = "macos", not(test)))]
fn ignorable_lock_errno(errno: i32) -> bool {
    errno == libc::ENOTSUP
        || errno == libc::EOPNOTSUPP
        || errno == libc::ENOTTY
        || errno == libc::EINVAL
}

#[cfg(all(target_os = "macos", not(test)))]
fn map_open(errno: i32, info: &SerialDeviceInfo) -> DeviceError {
    match errno {
        libc::EACCES | libc::EPERM => DeviceError::PermissionDenied { operation: "open" },
        libc::ENOENT | libc::ENODEV | libc::ENXIO => DeviceError::DeviceMissing { id: info.id },
        libc::EBUSY => DeviceError::Busy {
            path: info.callout_path.clone(),
        },
        _ => DeviceError::Io {
            operation: "open",
            os_code: errno,
        },
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn map_io(operation: &'static str, errno: i32, id: StableDeviceId, path: &str) -> DeviceError {
    match errno {
        libc::EACCES | libc::EPERM => DeviceError::PermissionDenied { operation },
        libc::ENOENT | libc::ENODEV | libc::ENXIO => DeviceError::DeviceMissing { id },
        libc::EBUSY => DeviceError::Busy {
            path: path.to_string(),
        },
        libc::EBADF | libc::ENOTCONN => DeviceError::NotOpen { id },
        libc::EAGAIN => DeviceError::Timeout { timeout_ms: 0 },
        libc::EIO => DeviceError::Unplugged { id },
        _ => DeviceError::Io {
            operation,
            os_code: errno,
        },
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn apply_termios(fd: std::os::fd::RawFd, config: SerialConfig) -> Result<(), DeviceError> {
    // SAFETY: termios is initialized by tcgetattr on success.
    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: fd is open and termios points to writable storage.
    if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
        return Err(DeviceError::Io {
            operation: "tcgetattr",
            os_code: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }

    termios.c_iflag &= !(libc::IGNBRK
        | libc::BRKINT
        | libc::PARMRK
        | libc::ISTRIP
        | libc::INLCR
        | libc::IGNCR
        | libc::ICRNL
        | libc::IXON
        | libc::IXOFF);
    termios.c_oflag &= !libc::OPOST;
    termios.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
    termios.c_cflag &= !(libc::CSIZE | libc::PARENB | libc::PARODD | libc::CSTOPB);
    termios.c_cflag |= libc::CREAD | libc::CLOCAL;
    termios.c_cflag |= match config.data_bits {
        5 => libc::CS5,
        6 => libc::CS6,
        7 => libc::CS7,
        _ => libc::CS8,
    };
    match config.parity {
        SerialParity::None => {}
        SerialParity::Odd => termios.c_cflag |= libc::PARENB | libc::PARODD,
        SerialParity::Even => termios.c_cflag |= libc::PARENB,
        SerialParity::Mark | SerialParity::Space => {
            return Err(DeviceError::Unsupported {
                feature: "serial parity mark/space",
            });
        }
    }
    if config.stop_bits == SerialStopBits::Two {
        termios.c_cflag |= libc::CSTOPB;
    }
    termios.c_cc[libc::VMIN] = 0;
    termios.c_cc[libc::VTIME] = 0;

    let speed = baud_speed(config.baud_rate).ok_or(DeviceError::InvalidArgument {
        field: "baud_rate",
        reason: "unsupported rate",
    })?;
    // SAFETY: termios points to a valid termios structure.
    if unsafe { libc::cfsetispeed(&mut termios, speed) } != 0
        || unsafe { libc::cfsetospeed(&mut termios, speed) } != 0
    {
        return Err(DeviceError::Io {
            operation: "cfsetispeed",
            os_code: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    // SAFETY: fd is open and termios is fully initialized.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(DeviceError::Io {
            operation: "tcsetattr",
            os_code: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        });
    }
    Ok(())
}

#[cfg(all(target_os = "macos", not(test)))]
fn baud_speed(baud: u32) -> Option<libc::speed_t> {
    Some(match baud {
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1200 => libc::B1200,
        1800 => libc::B1800,
        2400 => libc::B2400,
        4800 => libc::B4800,
        7200 => libc::B7200,
        9600 => libc::B9600,
        14400 => libc::B14400,
        19200 => libc::B19200,
        28800 => libc::B28800,
        38400 => libc::B38400,
        57600 => libc::B57600,
        76800 => libc::B76800,
        115_200 => libc::B115200,
        230_400 => libc::B230400,
        _ => return None,
    })
}

fn duration_ms(duration: Duration) -> i32 {
    duration.as_millis().min(i32::MAX as u128) as i32
}

#[cfg(all(target_os = "macos", not(test)))]
pub fn scan_serial_devices() -> Result<Vec<SerialDeviceInfo>, DeviceError> {
    let services = ffi::matching_services("IOSerialBSDClient");
    let mut devices = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for service in services {
        let Some(callout_path) = service.string("IOCalloutDevice") else {
            continue;
        };
        if !callout_path.starts_with("/dev/") || !seen.insert(callout_path.clone()) {
            continue;
        }
        let id = StableDeviceId::derive(DeviceClass::Serial, &[&callout_path]);
        devices.push(SerialDeviceInfo {
            id,
            registry_entry_id: service.registry_entry_id().unwrap_or(0),
            callout_path,
            dialin_path: service.string("IODialinDevice"),
            tty_device: service.string("IOTTYDevice"),
            base_name: service.string("IOTTYBaseName"),
            client_type: service.string("IOSerialBSDClientType"),
        });
    }
    devices.sort_by_key(|device| device.id);
    Ok(devices)
}

#[cfg(test)]
pub fn scan_serial_devices() -> Result<Vec<SerialDeviceInfo>, DeviceError> {
    Ok(Vec::new())
}

#[cfg(all(not(target_os = "macos"), not(test)))]
pub fn scan_serial_devices() -> Result<Vec<SerialDeviceInfo>, DeviceError> {
    Err(DeviceError::Unsupported {
        feature: "serial enumeration requires macOS IOKit",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_config_boundaries_are_rejected_exactly() {
        let base = SerialConfig::default();
        assert_eq!(
            SerialConfig {
                baud_rate: 0,
                ..base
            }
            .validate(),
            Err(DeviceError::InvalidArgument {
                field: "baud_rate",
                reason: "unsupported rate"
            })
        );
        assert_eq!(
            SerialConfig {
                data_bits: 4,
                ..base
            }
            .validate(),
            Err(DeviceError::InvalidArgument {
                field: "data_bits",
                reason: "must be between 5 and 8"
            })
        );
        assert_eq!(
            SerialConfig {
                data_bits: 9,
                ..base
            }
            .validate(),
            Err(DeviceError::InvalidArgument {
                field: "data_bits",
                reason: "must be between 5 and 8"
            })
        );
        assert_eq!(
            SerialConfig {
                stop_bits: SerialStopBits::OnePointFive,
                ..base
            }
            .validate(),
            Err(DeviceError::Unsupported {
                feature: "serial 1.5 stop bits"
            })
        );
        assert_eq!(
            SerialConfig {
                parity: SerialParity::Mark,
                ..base
            }
            .validate(),
            Err(DeviceError::Unsupported {
                feature: "serial parity mark/space"
            })
        );
        assert_eq!(
            SerialConfig {
                baud_rate: 50,
                data_bits: 5,
                ..base
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            SerialConfig {
                baud_rate: 230_400,
                data_bits: 8,
                parity: SerialParity::Even,
                stop_bits: SerialStopBits::Two,
            }
            .validate(),
            Ok(())
        );
        assert_eq!(
            SerialConfig {
                baud_rate: 230_401,
                ..base
            }
            .validate(),
            Err(DeviceError::InvalidArgument {
                field: "baud_rate",
                reason: "unsupported rate"
            })
        );
        assert_eq!(duration_ms(Duration::from_millis(0)), 0);
        assert_eq!(duration_ms(Duration::from_secs(u64::MAX)), i32::MAX);
    }

    #[test]
    fn serial_missing_device_open_is_exact_and_never_synthetic() {
        let id = StableDeviceId::from_raw(0x5150);
        let bridge = SerialBridge::new();
        assert_eq!(
            bridge.open(id, SerialConfig::default()).map(|_| ()),
            Err(DeviceError::DeviceMissing { id })
        );
        assert!(bridge.devices().is_empty());
    }

    #[test]
    fn serial_double_open_and_close_are_exact_via_state() {
        let id = StableDeviceId::from_raw(0x5151);
        let mut state = OpenState::default();
        assert_eq!(state.begin(id), Ok(()));
        assert_eq!(state.begin(id), Err(DeviceError::AlreadyOpen { id }));
        assert_eq!(state.end(), Ok(id));
        assert_eq!(state.end(), Err(DeviceError::AlreadyClosed { id }));
    }

    #[test]
    fn serial_device_lifecycle_and_config_boundaries_are_exact() {
        let info = SerialDeviceInfo {
            id: StableDeviceId::from_raw(0x5152),
            registry_entry_id: 0x5152,
            callout_path: "/dev/cu.casa1-test".to_string(),
            dialin_path: Some("/dev/tty.casa1-test".to_string()),
            tty_device: Some("casa1-test".to_string()),
            base_name: Some("casa1-test".to_string()),
            client_type: Some("IOSerialBSDClientType".to_string()),
        };
        let record = info.record();
        assert_eq!(record.class, DeviceClass::Serial);
        assert_eq!(record.path.as_deref(), Some("/dev/cu.casa1-test"));
        assert_eq!(record.product.as_deref(), Some("casa1-test"));
        assert_eq!(record.vendor_id, None);

        let mut bridge = SerialBridge::new();
        assert_eq!(bridge.devices().len(), 0);
        assert_eq!(bridge.table().len(), 0);
        assert_eq!(bridge.enumerate(), Ok(Vec::new()));
        assert_eq!(
            bridge.apply(vec![info.clone()]),
            vec![HotplugEvent::Arrived(info.record())]
        );
        assert_eq!(bridge.devices().len(), 1);
        assert_eq!(bridge.table().len(), 1);
        assert_eq!(bridge.device(info.id), Some(&info));

        let invalid = SerialConfig {
            baud_rate: 230_401,
            ..SerialConfig::default()
        };
        assert_eq!(
            bridge.open(info.id, invalid).map(|_| ()),
            Err(DeviceError::InvalidArgument {
                field: "baud_rate",
                reason: "unsupported rate"
            })
        );

        let mut device = bridge
            .open(info.id, SerialConfig::default())
            .expect("open fixture serial device");
        assert_eq!(device.id(), info.id);
        assert_eq!(device.path(), info.callout_path);
        assert_eq!(device.config(), SerialConfig::default());
        assert!(device.is_open());
        let configured = SerialConfig {
            baud_rate: 9_600,
            data_bits: 7,
            parity: SerialParity::Even,
            stop_bits: SerialStopBits::Two,
        };
        assert_eq!(device.configure(configured), Ok(()));
        assert_eq!(device.config(), configured);
        assert_eq!(
            device.configure(invalid),
            Err(DeviceError::InvalidArgument {
                field: "baud_rate",
                reason: "unsupported rate"
            })
        );
        assert_eq!(device.config(), configured);
        assert_eq!(device.flush(), Ok(()));
        assert_eq!(
            device.escape(0),
            Err(DeviceError::InvalidArgument {
                field: "function",
                reason: "unsupported escape function"
            })
        );
        assert_eq!(
            device.escape(5),
            Err(DeviceError::Unsupported {
                feature: "serial escape function"
            })
        );
        let mut buffer = [0u8; 4];
        assert_eq!(device.read(&mut [], Duration::ZERO), Ok(0));
        assert_eq!(
            device.read(&mut buffer, Duration::ZERO),
            Err(DeviceError::Unsupported {
                feature: "serial read requires macOS termios"
            })
        );
        assert_eq!(device.write(&[], Duration::ZERO), Ok(0));
        assert_eq!(
            device.write(&buffer, Duration::ZERO),
            Err(DeviceError::Unsupported {
                feature: "serial write requires macOS termios"
            })
        );
        assert_eq!(device.close(), Ok(()));
        assert!(!device.is_open());
        assert_eq!(
            device.close(),
            Err(DeviceError::AlreadyClosed { id: info.id })
        );
        assert_eq!(
            device.configure(configured),
            Err(DeviceError::NotOpen { id: info.id })
        );
        assert_eq!(device.flush(), Err(DeviceError::NotOpen { id: info.id }));
        assert_eq!(
            device.read(&mut buffer, Duration::ZERO),
            Err(DeviceError::NotOpen { id: info.id })
        );
        assert_eq!(
            device.write(&buffer, Duration::ZERO),
            Err(DeviceError::NotOpen { id: info.id })
        );

        let device = bridge
            .open(info.id, SerialConfig::default())
            .expect("reopen fixture serial device");
        drop(device);
    }

    #[test]
    fn serial_busy_or_missing_host_port_is_exact_never_synthetic() {
        let mut bridge = SerialBridge::new();
        let Ok(_) = bridge.enumerate() else {
            return;
        };
        let Some(info) = bridge.devices().first().cloned() else {
            return;
        };
        match bridge.open(info.id, SerialConfig::default()) {
            Ok(mut first) => {
                assert_eq!(
                    bridge.open(info.id, SerialConfig::default()).map(|_| ()),
                    Err(DeviceError::Busy {
                        path: info.callout_path.clone()
                    })
                );
                assert_eq!(first.close(), Ok(()));
            }
            Err(DeviceError::Busy { path }) => assert_eq!(path, info.callout_path),
            Err(DeviceError::PermissionDenied { operation }) => assert_eq!(operation, "open"),
            Err(DeviceError::DeviceMissing { id }) => assert_eq!(id, info.id),
            Err(DeviceError::Unplugged { id }) => assert_eq!(id, info.id),
            Err(error) => panic!("unexpected serial open error: {error:?}"),
        }
    }
}
