//! Serial and USB device dispatch glue.

use super::*;

impl PeHostRuntime {
    pub(crate) fn ensure_serial_ports(&mut self) {
        if self.user32.serial_ports().is_empty() {
            let _ = self.user32.refresh_physical_devices();
        }
    }

    pub(crate) fn serial_port_for_path(
        &self,
        path: &str,
    ) -> Option<crate::real_hid::SerialPortEntry> {
        let ports = self.user32.serial_ports();
        if let Some(index) = com_port_index(path) {
            let com_port = format!("COM{index}");
            return ports
                .into_iter()
                .find(|port| port.com_port.eq_ignore_ascii_case(&com_port));
        }
        let trimmed = path.trim_start_matches("\\\\.\\");
        ports.into_iter().find(|port| {
            port.callout_path == path
                || port.dialin_path.as_deref() == Some(path)
                || port.callout_path.trim_start_matches("/dev/") == trimmed
        })
    }

    pub(crate) fn open_serial_dispatch(&mut self, path: &str) -> Result<u64, DispatchOpenError> {
        let port = self
            .serial_port_for_path(path)
            .ok_or(DispatchOpenError::NotFound)?;
        let device = self
            .user32
            .physical_devices()
            .open_serial(port.device_id, crate::real_hid::SerialConfig::default())
            .map_err(DispatchOpenError::Device)?;
        crate::real_hid::dispatch::register_serial(device).map_err(DispatchOpenError::Device)
    }

    pub(crate) fn open_usb_dispatch(&mut self, path: &str) -> Result<u64, DispatchOpenError> {
        let id = parse_usb_dispatch_path(path).ok_or(DispatchOpenError::InvalidParameter)?;
        let id = crate::real_hid::StableDeviceId::from_raw(id);
        if self.user32.usb_devices().is_empty() {
            let _ = self.user32.refresh_physical_devices();
        }
        let device = self
            .user32
            .physical_devices()
            .usb_device(id)
            .ok_or(DispatchOpenError::NotFound)?;
        let path = device
            .record()
            .path
            .unwrap_or_else(|| format!("IOUSBHostDevice:{:016x}", device.registry_entry_id));
        Ok(crate::real_hid::dispatch::register_usb(id, path))
    }

    pub(crate) fn usb_io_control(
        &mut self,
        memory: &mut MemoryImage,
        handle: u64,
        io_code: u32,
        in_buffer: u64,
        in_size: u32,
        out_buffer: u64,
        out_size: u32,
        bytes_ret_ptr: u64,
    ) -> u32 {
        let id = match crate::real_hid::dispatch::usb_device_id(handle) {
            Ok(id) => id,
            Err(error) => return error.windows_error(),
        };
        match io_code {
            IOCTL_USB_ENUMERATE_DEVICES => {
                let entries = self.user32.usb_devices();
                let required = (entries.len() * 32) as u32;
                if bytes_ret_ptr != 0 {
                    write_u32(memory, bytes_ret_ptr, required);
                }
                if out_size < required {
                    return ERROR_INSUFFICIENT_BUFFER;
                }
                for (index, entry) in entries.iter().enumerate() {
                    let base = out_buffer + (index as u64 * 32);
                    write_u64(memory, base, entry.handle);
                    write_u32(memory, base + 8, u32::from(entry.vendor_id));
                    write_u32(memory, base + 12, u32::from(entry.product_id));
                    write_u32(memory, base + 16, entry.configurations as u32);
                    write_u32(memory, base + 20, entry.interfaces as u32);
                    write_u32(memory, base + 24, entry.endpoints as u32);
                    write_u32(memory, base + 28, entry.device_id.as_u64() as u32);
                }
                0
            }
            IOCTL_USB_VALIDATE_TRANSFER | IOCTL_USB_SUBMIT_TRANSFER => {
                if in_buffer == 0 || in_size < 24 {
                    return ERROR_INVALID_PARAMETER;
                }
                let mut fields = [0u32; 6];
                for (index, field) in fields.iter_mut().enumerate() {
                    let Ok(value) = read_u32(memory, in_buffer + (index as u64 * 4)) else {
                        return 998; // ERROR_NOACCESS
                    };
                    *field = value;
                }
                let direction = match fields[3] {
                    0 => crate::real_hid::UsbDirection::Out,
                    1 => crate::real_hid::UsbDirection::In,
                    _ => return ERROR_INVALID_PARAMETER,
                };
                let request = crate::real_hid::UsbTransferRequest {
                    interface_number: fields[0] as u8,
                    endpoint_address: fields[1] as u8,
                    transfer_type: crate::real_hid::UsbTransferType::from_bits(fields[2] as u8)
                        .unwrap_or(crate::real_hid::UsbTransferType::Control),
                    direction,
                    flags: fields[4],
                    length: fields[5] as usize,
                };
                let result = if io_code == IOCTL_USB_VALIDATE_TRANSFER {
                    self.user32
                        .physical_devices()
                        .validate_usb_transfer(id, &request)
                } else {
                    self.user32
                        .physical_devices()
                        .usb()
                        .submit_transfer(id, &request)
                        .map(|_| ())
                };
                match result {
                    Ok(()) => {
                        if bytes_ret_ptr != 0 {
                            write_u32(memory, bytes_ret_ptr, 0);
                        }
                        0
                    }
                    Err(error) => error.windows_error(),
                }
            }
            _ => ERROR_NOT_SUPPORTED,
        }
    }
}
