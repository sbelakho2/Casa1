//! Guest API string and formatting helpers.

use super::*;

/// Write an ANSI string into a guest buffer following the Windows
/// required-size contract shared by the APIs that use this helper
/// (GetModuleFileNameA, GetModuleBaseNameA):
///
/// - `buffer == 0 || size == 0` (the required-size query idiom): write
///   nothing and return the required size in characters INCLUDING the NUL
///   terminator.
/// - `size <= value.len()` (truncation): write `size - 1` characters plus a
///   NUL terminator and return the required size INCLUDING the NUL
///   terminator.
/// - `size > value.len()` (success): write the full string plus a NUL
///   terminator and return the length EXCLUDING the NUL terminator.
///
/// The caller (thunk) is responsible for the API-specific last-error value
/// on truncation (ERROR_INSUFFICIENT_BUFFER) and for the API-specific
/// interpretation of the returned size.
pub(crate) fn write_ansi_api_string(
    memory: &mut MemoryImage,
    buffer: u64,
    size: u32,
    value: &str,
) -> AppResult<u32> {
    let bytes = value.as_bytes();
    let required_with_nul = bytes.len() as u32 + 1;
    if buffer == 0 || size == 0 {
        return Ok(required_with_nul);
    }
    let truncated = size <= bytes.len() as u32;
    let copy_len = if truncated {
        size.saturating_sub(1) as usize
    } else {
        bytes.len()
    };
    let written_len = copy_len + 1;
    let page_tail = 0x1000_usize - (buffer as usize & 0xfff);
    let mut output = vec![0_u8; written_len];
    output[..copy_len].copy_from_slice(&bytes[..copy_len]);
    memory.map_bytes(buffer, &output);
    if page_tail > written_len {
        memory.map_zeroed_if_unmapped(buffer + written_len as u64, page_tail - written_len);
    }
    Ok(if truncated {
        required_with_nul
    } else {
        copy_len as u32
    })
}

/// Write a UTF-16 string into a guest buffer following the Windows
/// required-size contract used by GetCurrentDirectoryW, GetModuleFileNameW,
/// GetFullPathNameW, GetTempPathW and friends:
///
/// - `buffer == 0 || size == 0` (the required-size query idiom): write
///   nothing (including when the buffer is non-NULL but `size == 0`) and
///   return the required size in UTF-16 code units INCLUDING the NUL
///   terminator.
/// - `size <= required_without_nul` (truncation): write `size - 1` code
///   units plus a NUL terminator and return the required size INCLUDING the
///   NUL terminator.
/// - `size > required_without_nul` (success): write the full string plus a
///   NUL terminator and return the length EXCLUDING the NUL terminator.
///
/// The caller (thunk) is responsible for the API-specific last-error value
/// on truncation (ERROR_INSUFFICIENT_BUFFER) and for the API-specific
/// interpretation of the returned size.
pub(crate) fn write_utf16_api_string(
    memory: &mut MemoryImage,
    buffer: u64,
    size: u32,
    value: &str,
) -> AppResult<u32> {
    let units = value.encode_utf16().collect::<Vec<_>>();
    let required_without_nul = units.len() as u32;
    let required_with_nul = required_without_nul + 1;
    if buffer != 0 && size != 0 {
        let copy_units = units.len().min(size.saturating_sub(1) as usize);
        let written_len = (copy_units + 1) * 2;
        let page_tail = 0x1000_usize - (buffer as usize & 0xfff);
        let mut bytes = vec![0_u8; written_len];
        for (index, unit) in units.iter().take(copy_units).enumerate() {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        memory.map_bytes(buffer, &bytes);
        if page_tail > written_len {
            memory.map_zeroed_if_unmapped(buffer + written_len as u64, page_tail - written_len);
        }
    }
    Ok(if size <= required_without_nul {
        required_with_nul
    } else {
        required_without_nul
    })
}

pub(crate) fn write_utf16_fixed_buffer(
    memory: &mut MemoryImage,
    buffer: u64,
    len: usize,
    value: &str,
) {
    let mut bytes = vec![0_u8; len * 2];
    for (index, unit) in value.encode_utf16().take(len.saturating_sub(1)).enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    memory.map_bytes(buffer, &bytes);
}

pub(crate) fn write_find_data_w(
    memory: &mut MemoryImage,
    address: u64,
    data: &FindData,
) -> AppResult<()> {
    write_u32(memory, address, file_attributes_mask(&data.attributes));
    write_filetime(memory, address + 4, data.creation_time_ticks);
    write_filetime(memory, address + 12, data.last_access_time_ticks);
    write_filetime(memory, address + 20, data.last_write_time_ticks);
    write_u32(memory, address + 28, (data.size >> 32) as u32);
    write_u32(memory, address + 32, data.size as u32);
    write_u32(memory, address + 36, 0);
    write_u32(memory, address + 40, 0);
    write_utf16_fixed_buffer(
        memory,
        address + 44,
        WIN32_FIND_DATAW_FILE_NAME_CHARS,
        &data.file_name,
    );
    write_utf16_fixed_buffer(
        memory,
        address + 44 + (WIN32_FIND_DATAW_FILE_NAME_CHARS * 2) as u64,
        WIN32_FIND_DATAW_ALT_FILE_NAME_CHARS,
        "",
    );
    Ok(())
}

pub(crate) fn write_file_information_by_handle(
    memory: &mut MemoryImage,
    address: u64,
    data: &FileInformation,
) {
    let mut attributes = file_attributes_mask(&data.attributes);
    if data.is_directory {
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    let file_index = synthetic_file_index(&data.normalized_path);
    write_u32(memory, address, attributes);
    write_filetime(memory, address + 4, data.creation_time_ticks);
    write_filetime(memory, address + 12, data.last_access_time_ticks);
    write_filetime(memory, address + 20, data.last_write_time_ticks);
    write_u32(memory, address + 28, 0x4341_5341);
    write_u32(memory, address + 32, (data.size >> 32) as u32);
    write_u32(memory, address + 36, data.size as u32);
    write_u32(memory, address + 40, 1);
    write_u32(memory, address + 44, (file_index >> 32) as u32);
    write_u32(memory, address + 48, file_index as u32);
}

pub(crate) fn write_file_attribute_data(
    memory: &mut MemoryImage,
    address: u64,
    data: &FileInformation,
) {
    let mut attributes = file_attributes_mask(&data.attributes);
    if data.is_directory {
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    write_u32(memory, address, attributes);
    write_filetime(memory, address + 4, data.creation_time_ticks);
    write_filetime(memory, address + 12, data.last_access_time_ticks);
    write_filetime(memory, address + 20, data.last_write_time_ticks);
    write_u32(memory, address + 28, (data.size >> 32) as u32);
    write_u32(memory, address + 32, data.size as u32);
}

pub(crate) fn synthetic_file_index(path: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn message_box_response(style: u32) -> i32 {
    match style & 0x0000_000f {
        0x0000_0000 => IDOK,
        0x0000_0001 => IDOK,
        0x0000_0002 => IDIGNORE,
        0x0000_0003 => IDYES,
        0x0000_0004 => IDYES,
        0x0000_0005 => IDRETRY,
        0x0000_0006 => IDCONTINUE,
        _ => IDCANCEL,
    }
}

/// Upper bound for a single parsed wsprintf field width or precision.
///
/// The format string is guest-controlled and the width/precision digits are
/// unbounded in principle; the formatter materializes the field (zero/space
/// padding), so an absurd width must not be able to force a huge host
/// allocation.  Fields are clamped at parse time (saturating arithmetic), so
/// a hostile `%9999999999d` renders a bounded field instead of aborting.
pub(crate) const MAX_FORMAT_FIELD_WIDTH: usize = 4096;

/// Shared `wsprintf` formatter used by both the W and A variants.
///
/// Implements the documented wsprintf surface: `c d i o u x X s S p %` with
/// the `- + # 0 space` flags, field width, `.precision`, and the `l`/`w`
/// (wide) and `h` (narrow) length modifiers.  Floating point is NOT part of
/// the wsprintf contract (Windows leaves it undefined); an unsupported
/// specifier fails loudly instead of silently corrupting the output.
///
/// `ansi_strings` selects the default string convention for `%s` (ANSI bytes
/// for the A variant, UTF-16 for the W variant; `%S` is the opposite, and an
/// explicit `l`/`w`/`h` modifier always wins).
pub(crate) fn format_wsprintf(
    state: &CpuState,
    memory: &MemoryImage,
    format_string: &str,
    first_arg_index: usize,
    ansi_strings: bool,
) -> AppResult<String> {
    let chars = format_string.chars().collect::<Vec<_>>();
    let mut rendered = String::new();
    let mut cursor = 0usize;
    let mut arg_index = first_arg_index;
    while cursor < chars.len() {
        if chars[cursor] != '%' {
            rendered.push(chars[cursor]);
            cursor += 1;
            continue;
        }
        cursor += 1;
        if cursor < chars.len() && chars[cursor] == '%' {
            rendered.push('%');
            cursor += 1;
            continue;
        }
        let mut flags = String::new();
        while cursor < chars.len() && matches!(chars[cursor], '-' | '+' | ' ' | '#' | '0') {
            flags.push(chars[cursor]);
            cursor += 1;
        }
        let mut width = 0usize;
        while cursor < chars.len() && chars[cursor].is_ascii_digit() {
            width = width
                .saturating_mul(10)
                .saturating_add(chars[cursor].to_digit(10).unwrap_or(0) as usize)
                .min(MAX_FORMAT_FIELD_WIDTH);
            cursor += 1;
        }
        let mut precision: Option<usize> = None;
        if cursor < chars.len() && chars[cursor] == '.' {
            cursor += 1;
            let mut digits = 0usize;
            while cursor < chars.len() && chars[cursor].is_ascii_digit() {
                digits = digits
                    .saturating_mul(10)
                    .saturating_add(chars[cursor].to_digit(10).unwrap_or(0) as usize)
                    .min(MAX_FORMAT_FIELD_WIDTH);
                cursor += 1;
            }
            precision = Some(digits);
        }
        let mut wide_modifier = false;
        let mut narrow_modifier = false;
        if cursor < chars.len() && matches!(chars[cursor], 'l' | 'w' | 'h') {
            wide_modifier = matches!(chars[cursor], 'l' | 'w');
            narrow_modifier = chars[cursor] == 'h';
            cursor += 1;
            if cursor < chars.len() && matches!(chars[cursor], 'l' | 'w') {
                wide_modifier = true;
                narrow_modifier = false;
                cursor += 1;
            }
        }
        let specifier = *chars.get(cursor).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                "unterminated wsprintf format specifier",
            )
        })?;
        cursor += 1;
        let raw = guest_call_arg(state, memory, arg_index)?;
        arg_index += 1;
        match specifier {
            'd' | 'i' => {
                let value = raw as u32 as i32;
                // C99 precision-zero semantics: a zero value with `.0`
                // precision produces no digits.
                let mut digits = if value == 0 && precision == Some(0) {
                    String::new()
                } else {
                    format!("{}", value.unsigned_abs())
                };
                if let Some(precision) = precision {
                    digits = pad_zeros(&digits, precision);
                }
                let sign = if value < 0 {
                    "-"
                } else if flags.contains('+') {
                    "+"
                } else if flags.contains(' ') {
                    " "
                } else {
                    ""
                };
                let mut body = digits;
                if flags.contains('0') && !flags.contains('-') && precision.is_none() {
                    let needed = width.saturating_sub(sign.len() + body.len());
                    body = format!("{}{}", "0".repeat(needed), body);
                }
                append_field(&mut rendered, format!("{sign}{body}"), &flags, width);
            }
            'u' => {
                let value = raw as u32;
                let mut digits = if value == 0 && precision == Some(0) {
                    String::new()
                } else {
                    format!("{value}")
                };
                if let Some(precision) = precision {
                    digits = pad_zeros(&digits, precision);
                }
                let mut body = digits;
                if flags.contains('0') && !flags.contains('-') && precision.is_none() {
                    let needed = width.saturating_sub(body.len());
                    body = format!("{}{}", "0".repeat(needed), body);
                }
                append_field(&mut rendered, body, &flags, width);
            }
            'o' => {
                let value = raw as u32;
                let mut digits = if value == 0 && precision == Some(0) {
                    String::new()
                } else {
                    format!("{value:o}")
                };
                if let Some(precision) = precision {
                    digits = pad_zeros(&digits, precision);
                }
                // `#` gives octal output a leading zero (C99: the output
                // always starts with 0 — including the empty `.0` zero case).
                if flags.contains('#') && (value != 0 || digits.is_empty()) {
                    if digits.is_empty() {
                        digits = "0".to_string();
                    } else {
                        digits = format!("0{digits}");
                    }
                }
                let mut body = digits;
                if flags.contains('0') && !flags.contains('-') && precision.is_none() {
                    let needed = width.saturating_sub(body.len());
                    body = format!("{}{}", "0".repeat(needed), body);
                }
                append_field(&mut rendered, body, &flags, width);
            }
            'x' | 'X' => {
                let value = raw as u32;
                let mut digits = if value == 0 && precision == Some(0) {
                    String::new()
                } else if specifier == 'x' {
                    format!("{value:x}")
                } else {
                    format!("{value:X}")
                };
                if let Some(precision) = precision {
                    digits = pad_zeros(&digits, precision);
                }
                let prefix = if flags.contains('#') && value != 0 {
                    if specifier == 'x' { "0x" } else { "0X" }
                } else {
                    ""
                };
                // The `0` flag zero-pads the digits AFTER the 0x/0X prefix
                // (`%#08x` of 0xabc → "0x000abc", like Windows).
                let mut body = digits;
                if flags.contains('0') && !flags.contains('-') && precision.is_none() {
                    let needed = width.saturating_sub(prefix.len() + body.len());
                    body = format!("{}{}", "0".repeat(needed), body);
                }
                append_field(&mut rendered, format!("{prefix}{body}"), &flags, width);
            }
            'p' => rendered.push_str(&format!("{raw:#x}")),
            'c' | 'C' => {
                let ch = char::from_u32((raw as u32) & 0xffff).unwrap_or('?');
                append_field(&mut rendered, ch.to_string(), &flags, width);
            }
            's' | 'S' => {
                let string = if raw != 0 {
                    let prefer_wide = if specifier == 's' {
                        wide_modifier || (!ansi_strings && !narrow_modifier)
                    } else {
                        wide_modifier || (ansi_strings && !narrow_modifier)
                    };
                    if prefer_wide {
                        read_utf16_string(memory, raw)?
                    } else {
                        read_c_string(memory, raw)?
                    }
                } else {
                    String::new()
                };
                let truncated = match precision {
                    Some(precision) => string.chars().take(precision).collect(),
                    None => string,
                };
                append_field(&mut rendered, truncated, &flags, width);
            }
            other => {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported wsprintf format specifier %{other}"),
                ));
            }
        }
    }
    Ok(rendered)
}

/// Zero-pad `digits` to at least `precision` characters.
pub(crate) fn pad_zeros(digits: &str, precision: usize) -> String {
    if digits.len() < precision {
        format!("{}{}", "0".repeat(precision - digits.len()), digits)
    } else {
        digits.to_string()
    }
}

/// Append `content` to `rendered`, applying the field width (left-aligned
/// with the `-` flag, right-aligned otherwise, space-padded).
pub(crate) fn append_field(rendered: &mut String, content: String, flags: &str, width: usize) {
    let padding = width.saturating_sub(content.len());
    if padding == 0 {
        rendered.push_str(&content);
        return;
    }
    if flags.contains('-') {
        rendered.push_str(&content);
        for _ in 0..padding {
            rendered.push(' ');
        }
    } else {
        for _ in 0..padding {
            rendered.push(' ');
        }
        rendered.push_str(&content);
    }
}
