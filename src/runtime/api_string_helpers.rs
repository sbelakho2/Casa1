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

/// Win32 message-box button identifiers (`winuser.h`).
pub(crate) const IDOK_: i32 = IDOK;
const IDABORT_: i32 = IDABORT;
const IDRETRY_: i32 = IDRETRY;
const IDIGNORE_: i32 = IDIGNORE;
const IDYES_: i32 = IDYES;
const IDNO_: i32 = IDNO;
const IDCANCEL_: i32 = IDCANCEL;
const IDTRYAGAIN_: i32 = IDTRYAGAIN;
const IDCONTINUE_: i32 = IDCONTINUE;

/// The button labels a message box displays for its style.
///
/// `MB_OK`, `MB_OKCANCEL`, `MB_ABORTRETRYIGNORE`, `MB_YESNOCANCEL`,
/// `MB_YESNO`, `MB_RETRYCANCEL` and `MB_CANCELTRYCONTINUE`; any other
/// low-nibble value falls back to the OK-only set.
pub(crate) fn message_box_labels(style: u32) -> &'static [&'static str] {
    match style & 0x0000_000f {
        0x0000_0001 => &["OK", "Cancel"],
        0x0000_0002 => &["Abort", "Retry", "Ignore"],
        0x0000_0003 => &["Yes", "No", "Cancel"],
        0x0000_0004 => &["Yes", "No"],
        0x0000_0005 => &["Retry", "Cancel"],
        0x0000_0006 => &["Cancel", "Try Again", "Continue"],
        _ => &["OK"],
    }
}

/// Index of the default button chosen by `MB_DEFBUTTON1..4`
/// (`0x0000_0100 << (n - 1)`), clamped to the available button count.
pub(crate) fn message_box_default_index(style: u32, buttons: usize) -> usize {
    let default = match style & 0x0000_0300 {
        0x0000_0100 => 1,
        0x0000_0200 => 2,
        0x0000_0300 => 3,
        _ => 0,
    };
    default.min(buttons.saturating_sub(1))
}

/// Map a button label to its Win32 identifier.
fn message_box_button_id(label: &str) -> Option<i32> {
    match label.to_ascii_lowercase().as_str() {
        "ok" => Some(IDOK_),
        "cancel" => Some(IDCANCEL_),
        "yes" => Some(IDYES_),
        "no" => Some(IDNO_),
        "abort" => Some(IDABORT_),
        "retry" => Some(IDRETRY_),
        "ignore" => Some(IDIGNORE_),
        "try again" => Some(IDTRYAGAIN_),
        "continue" => Some(IDCONTINUE_),
        _ => None,
    }
}

/// Parse the `button returned:` line AppleScript prints after a dialog.
///
/// Only a label that is actually part of `style`'s button set can produce a
/// non-cancel answer.  Missing/unparseable output (an `osascript` failure or
/// a dialog dismissed without a button) returns `IDCANCEL`; it never
/// fabricates `IDYES`.
pub(crate) fn parse_message_box_button(output: &str, style: u32) -> i32 {
    let labels = message_box_labels(style);
    let Some(position) = output.to_ascii_lowercase().find("button returned:") else {
        return IDCANCEL_;
    };
    let remaining = output[position + "button returned:".len()..]
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(|character| character == '"' || character == '\'')
        .trim();
    if remaining.is_empty() {
        return IDCANCEL_;
    }
    for label in labels {
        if label.eq_ignore_ascii_case(remaining)
            && let Some(id) = message_box_button_id(label)
        {
            return id;
        }
    }
    // A label outside the style's set is a malformed/hostile response:
    // refuse it instead of guessing what the user accepted.
    IDCANCEL_
}

/// Style-derived answer used when no interactive dialog is shown
/// (`MessageBoxW` in deterministic/headless mode or a direct legacy call).
pub(crate) fn default_message_box_response(style: u32) -> i32 {
    let buttons = message_box_labels(style);
    let index = message_box_default_index(style, buttons.len());
    message_box_button_id(buttons[index]).unwrap_or(IDCANCEL_)
}

/// The osascript executable.  Tests override it with a harmless program so
/// the dialog path (including spawn failure) is exercised without opening UI.
fn osascript_program() -> String {
    #[cfg(test)]
    if let Some(program) = OSASCRIPT_PROGRAM.with(|slot| slot.borrow().clone()) {
        return program;
    }
    "osascript".to_string()
}

#[cfg(test)]
thread_local! {
    static OSASCRIPT_PROGRAM: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn with_osascript_program<R>(program: &str, f: impl FnOnce() -> R) -> R {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            OSASCRIPT_PROGRAM.with(|slot| *slot.borrow_mut() = None);
        }
    }
    OSASCRIPT_PROGRAM.with(|slot| *slot.borrow_mut() = Some(program.to_string()));
    let _restore = Restore;
    f()
}

/// Show the staged message box for `style` and return the chosen button ID.
///
/// The dialog has no `giving up after` timeout, so it stays up until the
/// user presses a button.  A failure to spawn/parse `osascript` returns
/// `IDCANCEL` rather than pretending the user accepted anything.
pub(crate) fn message_box_response(style: u32) -> i32 {
    let Some((title, text, dtm)) = crate::runtime::take_pending_message_box() else {
        return default_message_box_response(style);
    };
    if dtm {
        return default_message_box_response(style);
    }
    let labels = message_box_labels(style);
    let default = message_box_default_index(style, labels.len());
    let buttons = labels
        .iter()
        .map(|label| format!("\"{label}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "display dialog {} with title {} buttons {{{buttons}}} default button {}",
        apple_script_string(&text),
        apple_script_string(&title),
        apple_script_string(labels[default]),
    );
    let output = std::process::Command::new(osascript_program())
        .arg("-e")
        .arg(script)
        .output();
    match output {
        Ok(output) if output.status.success() => {
            parse_message_box_button(&String::from_utf8_lossy(&output.stdout), style)
        }
        _ => IDCANCEL_,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_box_button_ids_never_mismatch_their_labels() {
        let cases = [
            (0x0000_0000, "OK", IDOK),
            (0x0000_0001, "Cancel", IDCANCEL),
            (0x0000_0002, "Abort", IDABORT),
            (0x0000_0002, "Retry", IDRETRY),
            (0x0000_0002, "Ignore", IDIGNORE),
            (0x0000_0003, "Yes", IDYES),
            (0x0000_0004, "No", IDNO),
            (0x0000_0005, "Retry", IDRETRY),
            (0x0000_0006, "Try Again", IDTRYAGAIN),
            (0x0000_0006, "Continue", IDCONTINUE),
        ];
        for (style, label, expected) in cases {
            assert_eq!(
                parse_message_box_button(&format!("button returned:{label}\n"), style),
                expected
            );
        }
    }

    #[test]
    fn message_box_default_button_boundary_is_clamped() {
        assert_eq!(default_message_box_response(0x0004 | 0x0100), IDNO);
        assert_eq!(default_message_box_response(0x0004 | 0x0200), IDNO);
        assert_eq!(default_message_box_response(0x0004 | 0x0300), IDNO);
        assert_eq!(message_box_default_index(0x0300, 0), 0);
        assert_eq!(message_box_default_index(0x0100, 3), 1);
    }

    #[test]
    fn message_box_malformed_output_never_fabricates_yes() {
        assert_eq!(parse_message_box_button("", 0x0004), IDCANCEL);
        assert_eq!(
            parse_message_box_button("button returned:Maybe", 0x0004),
            IDCANCEL
        );
        // A label outside the style's button set is refused.
        assert_eq!(
            parse_message_box_button("button returned:Yes", 0x0000),
            IDCANCEL
        );
        assert_eq!(parse_message_box_button("BUTTON RETURNED:no", 0x0004), IDNO);
        assert_eq!(
            parse_message_box_button("button returned:   ", 0x0004),
            IDCANCEL
        );
        assert_eq!(message_box_button_id("bogus"), None);
    }

    #[test]
    fn message_box_osascript_spawn_failure_returns_cancel() {
        crate::runtime::show_host_message_box("title", "text", false).expect("stage message box");
        let response = with_osascript_program("/nonexistent/casa1-osascript", || {
            message_box_response(0x0004)
        });
        assert_eq!(response, IDCANCEL);
    }

    #[test]
    fn message_box_osascript_success_without_button_falls_back_to_cancel() {
        crate::runtime::show_host_message_box("title", "text", false).expect("stage message box");
        let response = with_osascript_program("/bin/echo", || message_box_response(0x0004));
        assert_eq!(response, IDCANCEL);
    }

    #[test]
    fn message_box_dtm_mode_default_boundary_never_spawns() {
        crate::runtime::show_host_message_box("title", "text", true).expect("stage message box");
        assert_eq!(message_box_response(0x0004 | 0x0100), IDNO);
        // No pending payload: the legacy direct call still returns a default.
        assert_eq!(message_box_response(0x0000), IDOK);
    }
}
