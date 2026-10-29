//! Guest address-space helpers: pointers, unicode, probes, alignment.

use super::*;

pub(crate) fn write_image_pointer(image: &mut [u8], offset: usize, value: u64, arch: GuestArch) {
    match arch {
        GuestArch::X86 => {
            image[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
        GuestArch::X64 => {
            image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
}

pub(crate) fn copy_unicode_string(
    memory: &mut MemoryImage,
    source: u64,
    destination: u64,
    arch: GuestArch,
) -> AppResult<()> {
    let length = memory.read_u16(source)?;
    let maximum = memory.read_u16(source + 2)?;
    let buffer = read_guest_pointer(memory, source + unicode_string_buffer_offset(arch), arch)?;
    write_unicode_string_header(memory, destination, length, maximum, buffer, arch)?;
    Ok(())
}

pub(crate) fn write_unicode_string_header(
    memory: &mut MemoryImage,
    destination: u64,
    length: u16,
    maximum: u16,
    buffer: u64,
    arch: GuestArch,
) -> AppResult<()> {
    memory.write_u16(destination, length);
    memory.write_u16(destination + 2, maximum);
    memory.write_u32(destination + 4, 0);
    write_guest_pointer(
        memory,
        destination + unicode_string_buffer_offset(arch),
        buffer,
        arch,
    )
}

pub(crate) fn unicode_string_buffer_offset(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X86 => 4,
        GuestArch::X64 => 8,
    }
}

pub(crate) fn unicode_string_size(arch: GuestArch) -> usize {
    match arch {
        GuestArch::X86 => 8,
        GuestArch::X64 => 16,
    }
}

pub(crate) fn write_guest_pointer(
    memory: &mut MemoryImage,
    address: u64,
    value: u64,
    arch: GuestArch,
) -> AppResult<()> {
    match arch {
        GuestArch::X86 => memory.write_u32(address, value as u32),
        GuestArch::X64 => memory.write_u64(address, value),
    }
    Ok(())
}

pub(crate) fn read_guest_pointer(
    memory: &MemoryImage,
    address: u64,
    arch: GuestArch,
) -> AppResult<u64> {
    match arch {
        GuestArch::X86 => memory.read_u32(address).map(u64::from),
        GuestArch::X64 => memory.read_u64(address),
    }
}

pub(crate) fn allocate_unicode_string(
    state: &mut IslandState,
    memory: &mut MemoryImage,
    text: &str,
) -> AppResult<u64> {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let buffer = state.arena.alloc(memory, (units.len() + 1) * 2, 2)?;
    for (index, unit) in units.iter().enumerate() {
        memory.write_u16(buffer + index as u64 * 2, *unit);
    }
    memory.write_u16(buffer + units.len() as u64 * 2, 0);
    let header = state
        .arena
        .alloc(memory, unicode_string_size(state.arch), 8)?;
    write_unicode_string_header(
        memory,
        header,
        (units.len() * 2) as u16,
        ((units.len() + 1) * 2) as u16,
        buffer,
        state.arch,
    )?; // coverage: unreachable — write_unicode_string_header only performs infallible MemoryImage writes
    Ok(header)
}

pub(crate) fn read_unicode_string(
    memory: &MemoryImage,
    address: u64,
    arch: GuestArch,
) -> AppResult<(String, u16, u64)> {
    if address == 0 {
        return Ok((String::new(), 0, 0));
    }
    let length = memory.read_u16(address)?;
    let _maximum = memory.read_u16(address + 2)?;
    let buffer = read_guest_pointer(memory, address + unicode_string_buffer_offset(arch), arch)?;
    if length == 0 {
        return Ok((String::new(), 0, buffer));
    }
    if length % 2 != 0 || buffer == 0 {
        return Err(AppError::new(
            ReasonCode::RcMemoryAccessViolation,
            format!("invalid UNICODE_STRING at {address:#x} (Length={length})"),
        ));
    }
    let mut units = Vec::with_capacity(length as usize / 2);
    for index in 0..length / 2 {
        units.push(memory.read_u16(buffer + index as u64 * 2)?);
    }
    Ok((String::from_utf16_lossy(&units), length, buffer))
}

pub(crate) fn read_utf16_z(
    memory: &MemoryImage,
    address: u64,
    maximum_units: usize,
) -> AppResult<String> {
    if address == 0 {
        return Ok(String::new());
    }
    let mut units = Vec::new();
    for index in 0..maximum_units {
        let unit = memory.read_u16(address + index as u64 * 2)?;
        if unit == 0 {
            return Ok(String::from_utf16_lossy(&units));
        }
        units.push(unit);
    }
    Err(AppError::new(
        ReasonCode::RcMemoryAccessViolation,
        format!("unterminated UTF-16 string at {address:#x}"),
    ))
}

pub(crate) fn read_ansi_z(memory: &MemoryImage, address: u64, maximum: usize) -> AppResult<String> {
    if address == 0 {
        return Ok(String::new());
    }
    let mut bytes = Vec::new();
    for index in 0..maximum {
        let byte = memory.read_u8(address + index as u64)?;
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte);
    }
    Err(AppError::new(
        ReasonCode::RcMemoryAccessViolation,
        format!("unterminated ANSI string at {address:#x}"),
    ))
}

pub(crate) fn format_dbg_print(
    format: &str,
    args: &[u64],
    memory: &MemoryImage,
    arch: GuestArch,
) -> String {
    let characters = format.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    let mut argument = 0;
    while index < characters.len() {
        if characters[index] != '%' {
            output.push(characters[index]);
            index += 1;
            continue;
        }
        index += 1;
        if index >= characters.len() {
            output.push('%');
            break;
        }
        if characters[index] == '%' {
            output.push('%');
            index += 1;
            continue;
        }
        let mut wide = false;
        while index < characters.len()
            && matches!(characters[index], 'h' | 'l' | 'w' | 'I' | '6' | '4' | 'z')
        {
            wide |= characters[index] == 'w';
            index += 1;
        }
        if index >= characters.len() {
            output.push('%');
            break;
        }
        let conversion = characters[index];
        index += 1;
        let value = args.get(argument).copied().unwrap_or(0);
        argument += 1;
        match conversion {
            's' | 'S' => {
                let string = if wide {
                    read_utf16_z(memory, value, 4096).unwrap_or_default()
                } else {
                    read_ansi_z(memory, value, 4096).unwrap_or_default()
                };
                output.push_str(&string);
            }
            'Z' => {
                output.push_str(
                    &read_unicode_string(memory, value, arch)
                        .map(|(text, _, _)| text)
                        .unwrap_or_default(),
                );
            }
            'u' => output.push_str(&(value as u32).to_string()),
            'd' | 'i' => output.push_str(&(value as i32).to_string()),
            'x' => output.push_str(&format!("{:x}", value as u32)),
            'X' => output.push_str(&format!("{:X}", value as u32)),
            'p' => output.push_str(&format!("{value:#x}")),
            'c' => output.push(char::from_u32(value as u32).unwrap_or('?')),
            other => {
                output.push('%');
                output.push(other);
            }
        }
    }
    output
}

pub(crate) fn guest_arg(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<u64> {
    match state.arch {
        GuestArch::X64 => match index {
            0 => Ok(state.get(Register::Rcx)),
            1 => Ok(state.get(Register::Rdx)),
            2 => Ok(state.get(Register::R8)),
            3 => Ok(state.get(Register::R9)),
            _ => memory.read_u64(state.get(Register::Rsp) + 0x20 + (index as u64 - 4) * 8),
        },
        GuestArch::X86 => memory
            .read_u32(state.get(Register::Rsp) + index as u64 * 4)
            .map(u64::from),
    }
}

pub(crate) fn set_status(state: &mut CpuState, status: i32) {
    state.set(Register::Rax, status as i64 as u64);
}

pub(crate) fn status_is_success(status: i32) -> bool {
    (status as u32) < 0x8000_0000
}

pub(crate) fn strip_device_prefix(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("\\device\\") {
        &name[8..]
    } else {
        name.trim_start_matches('\\')
    }
}

pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value.wrapping_add(align - 1) & !(align - 1)
}

pub(crate) fn align_up_usize(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Wall-clock time as a Windows `FILETIME` (100ns ticks since 1601-01-01).
pub(crate) fn system_time_100ns() -> u64 {
    const WINDOWS_EPOCH_OFFSET_SECONDS: u64 = 11_644_473_600;
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (elapsed.as_secs() + WINDOWS_EPOCH_OFFSET_SECONDS)
        .saturating_mul(10_000_000)
        .saturating_add(u64::from(elapsed.subsec_nanos() / 100))
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|bytes| {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    })
}
