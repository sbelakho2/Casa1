//! Version-info blob navigation helpers.

use super::*;

pub(crate) fn apply_ver_condition_mask(
    existing_mask: u64,
    type_mask: u32,
    condition_mask: u8,
) -> u64 {
    let mut updated_mask = existing_mask;
    let condition_bits = u64::from(condition_mask & 0x7);
    for bit in [
        VER_MINORVERSION,
        VER_MAJORVERSION,
        VER_BUILDNUMBER,
        VER_PLATFORMID,
        VER_SERVICEPACKMINOR,
        VER_SERVICEPACKMAJOR,
        VER_SUITENAME,
        VER_PRODUCT_TYPE,
    ] {
        if type_mask & bit != 0 {
            let shift = ver_condition_shift(bit).expect("known version type bit");
            updated_mask &= !(0x7_u64 << shift);
            updated_mask |= condition_bits << shift;
        }
    }
    updated_mask
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestVersionInfo {
    pub(crate) major: u32,
    pub(crate) minor: u32,
    pub(crate) build: u32,
    pub(crate) platform_id: u32,
    pub(crate) service_pack_major: u16,
    pub(crate) service_pack_minor: u16,
    pub(crate) suite_mask: u16,
    pub(crate) product_type: u8,
}

pub(crate) fn ver_condition_shift(type_bit: u32) -> Option<u32> {
    match type_bit {
        VER_MINORVERSION => Some(0),
        VER_MAJORVERSION => Some(3),
        VER_BUILDNUMBER => Some(6),
        VER_PLATFORMID => Some(9),
        VER_SERVICEPACKMINOR => Some(12),
        VER_SERVICEPACKMAJOR => Some(15),
        VER_SUITENAME => Some(18),
        VER_PRODUCT_TYPE => Some(21),
        _ => None,
    }
}

pub(crate) fn ver_condition_for_type(condition_mask: u64, type_bit: u32) -> AppResult<u8> {
    let shift = ver_condition_shift(type_bit).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported version type bit {type_bit:#x}"),
        )
    })?;
    let condition = ((condition_mask >> shift) & 0x7) as u8;
    if condition == 0 {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("missing version condition for type bit {type_bit:#x}"),
        ));
    }
    Ok(condition)
}

pub(crate) fn guest_version_info_from_profile(profile: &str) -> AppResult<GuestVersionInfo> {
    match profile {
        "win7" => Ok(GuestVersionInfo {
            major: 6,
            minor: 1,
            build: 7600,
            platform_id: VER_PLATFORM_WIN32_NT,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: VER_NT_WORKSTATION,
        }),
        "win7-sp1" => Ok(GuestVersionInfo {
            major: 6,
            minor: 1,
            build: 7601,
            platform_id: VER_PLATFORM_WIN32_NT,
            service_pack_major: 1,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: VER_NT_WORKSTATION,
        }),
        "win8" => Ok(GuestVersionInfo {
            major: 6,
            minor: 2,
            build: 9200,
            platform_id: VER_PLATFORM_WIN32_NT,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: VER_NT_WORKSTATION,
        }),
        "win8.1" => Ok(GuestVersionInfo {
            major: 6,
            minor: 3,
            build: 9600,
            platform_id: VER_PLATFORM_WIN32_NT,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: VER_NT_WORKSTATION,
        }),
        "win10-2004" => Ok(GuestVersionInfo {
            major: 10,
            minor: 0,
            build: 19041,
            platform_id: VER_PLATFORM_WIN32_NT,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: VER_NT_WORKSTATION,
        }),
        "win10-20h2" => Ok(GuestVersionInfo {
            build: 19042,
            ..guest_version_info_from_profile("win10-2004")?
        }),
        "win10-21h1" => Ok(GuestVersionInfo {
            build: 19043,
            ..guest_version_info_from_profile("win10-2004")?
        }),
        "win10-21h2" => Ok(GuestVersionInfo {
            build: 19044,
            ..guest_version_info_from_profile("win10-2004")?
        }),
        "win10-22h2" => Ok(GuestVersionInfo {
            build: 19045,
            ..guest_version_info_from_profile("win10-2004")?
        }),
        "win11-22h2" => Ok(GuestVersionInfo {
            major: 10,
            minor: 0,
            build: 22621,
            platform_id: VER_PLATFORM_WIN32_NT,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0,
            product_type: VER_NT_WORKSTATION,
        }),
        "win11-23h2" => Ok(GuestVersionInfo {
            build: 22631,
            ..guest_version_info_from_profile("win11-22h2")?
        }),
        "win11-24h2" => Ok(GuestVersionInfo {
            build: 26100,
            ..guest_version_info_from_profile("win11-22h2")?
        }),
        _ => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported GE winver profile {profile} for version APIs"),
        )),
    }
}

pub(crate) fn read_guest_version_info(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<GuestVersionInfo> {
    Ok(GuestVersionInfo {
        major: read_u32(memory, address + 4)?,
        minor: read_u32(memory, address + 8)?,
        build: read_u32(memory, address + 12)?,
        platform_id: read_u32(memory, address + 16)?,
        service_pack_major: if read_u32(memory, address)? >= OSVERSIONINFOEXW_SIZE {
            read_guest_u16(memory, address + 276)?
        } else {
            0
        },
        service_pack_minor: if read_u32(memory, address)? >= OSVERSIONINFOEXW_SIZE {
            read_guest_u16(memory, address + 278)?
        } else {
            0
        },
        suite_mask: if read_u32(memory, address)? >= OSVERSIONINFOEXW_SIZE {
            read_guest_u16(memory, address + 280)?
        } else {
            0
        },
        product_type: if read_u32(memory, address)? >= OSVERSIONINFOEXW_SIZE {
            memory.read_u8(address + 282)?
        } else {
            0
        },
    })
}

pub(crate) fn version_field_value(info: &GuestVersionInfo, type_bit: u32) -> u64 {
    match type_bit {
        VER_MAJORVERSION => u64::from(info.major),
        VER_MINORVERSION => u64::from(info.minor),
        VER_BUILDNUMBER => u64::from(info.build),
        VER_PLATFORMID => u64::from(info.platform_id),
        VER_SERVICEPACKMAJOR => u64::from(info.service_pack_major),
        VER_SERVICEPACKMINOR => u64::from(info.service_pack_minor),
        VER_SUITENAME => u64::from(info.suite_mask),
        VER_PRODUCT_TYPE => u64::from(info.product_type),
        _ => 0,
    }
}

pub(crate) fn compare_ordering(ordering: Ordering, condition: u8) -> AppResult<bool> {
    match condition {
        VER_EQUAL => Ok(ordering == Ordering::Equal),
        VER_GREATER => Ok(ordering == Ordering::Greater),
        VER_GREATER_EQUAL => Ok(matches!(ordering, Ordering::Greater | Ordering::Equal)),
        VER_LESS => Ok(ordering == Ordering::Less),
        VER_LESS_EQUAL => Ok(matches!(ordering, Ordering::Less | Ordering::Equal)),
        _ => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported version comparison condition {condition}"),
        )),
    }
}

pub(crate) fn compare_numeric_version_field(
    actual: u64,
    requested: u64,
    condition: u8,
) -> AppResult<bool> {
    compare_ordering(actual.cmp(&requested), condition)
}

pub(crate) fn compare_suite_mask(actual: u16, requested: u16, condition: u8) -> AppResult<bool> {
    match condition {
        VER_AND => Ok(actual & requested == requested),
        VER_OR => Ok(requested == 0 || actual & requested != 0),
        VER_EQUAL => Ok(actual == requested),
        _ => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported suite comparison condition {condition}"),
        )),
    }
}

pub(crate) fn compare_selected_version_fields(
    actual: &GuestVersionInfo,
    requested: &GuestVersionInfo,
    type_mask: u32,
) -> Ordering {
    for bit in [
        VER_MAJORVERSION,
        VER_MINORVERSION,
        VER_BUILDNUMBER,
        VER_SERVICEPACKMAJOR,
        VER_SERVICEPACKMINOR,
    ] {
        if type_mask & bit != 0 {
            let ordering =
                version_field_value(actual, bit).cmp(&version_field_value(requested, bit));
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
    }
    Ordering::Equal
}

pub(crate) fn verify_version_info(
    actual: &GuestVersionInfo,
    requested: &GuestVersionInfo,
    type_mask: u32,
    condition_mask: u64,
) -> AppResult<bool> {
    let ordered_bits = [
        VER_MAJORVERSION,
        VER_MINORVERSION,
        VER_BUILDNUMBER,
        VER_SERVICEPACKMAJOR,
        VER_SERVICEPACKMINOR,
    ];
    let mut shared_ordered_condition = None;
    let mut ordered_conditions_match = true;
    for bit in ordered_bits {
        if type_mask & bit == 0 {
            continue;
        }
        let condition = ver_condition_for_type(condition_mask, bit)?;
        if let Some(existing) = shared_ordered_condition {
            if existing != condition {
                ordered_conditions_match = false;
            }
        } else {
            shared_ordered_condition = Some(condition);
        }
    }
    if let Some(condition) = shared_ordered_condition {
        let ordered_match = if ordered_conditions_match {
            compare_ordering(
                compare_selected_version_fields(actual, requested, type_mask),
                condition,
            )?
        } else {
            let mut fields_match = true;
            for bit in ordered_bits {
                if type_mask & bit == 0 {
                    continue;
                }
                fields_match &= compare_numeric_version_field(
                    version_field_value(actual, bit),
                    version_field_value(requested, bit),
                    ver_condition_for_type(condition_mask, bit)?,
                )?;
            }
            fields_match
        };
        if !ordered_match {
            return Ok(false);
        }
    }
    if type_mask & VER_PLATFORMID != 0
        && !compare_numeric_version_field(
            u64::from(actual.platform_id),
            u64::from(requested.platform_id),
            ver_condition_for_type(condition_mask, VER_PLATFORMID)?,
        )?
    {
        return Ok(false);
    }
    if type_mask & VER_SUITENAME != 0
        && !compare_suite_mask(
            actual.suite_mask,
            requested.suite_mask,
            ver_condition_for_type(condition_mask, VER_SUITENAME)?,
        )?
    {
        return Ok(false);
    }
    if type_mask & VER_PRODUCT_TYPE != 0
        && !compare_numeric_version_field(
            u64::from(actual.product_type),
            u64::from(requested.product_type),
            ver_condition_for_type(condition_mask, VER_PRODUCT_TYPE)?,
        )?
    {
        return Ok(false);
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Version-info blob navigation helpers (used by GetFileVersionInfoW / VerQueryValueW)
// ---------------------------------------------------------------------------

/// Read a null-terminated UTF-16 key from a version-info block at `base + offset`.
/// Returns `(key, byte_offset_of_null_terminator + 2)` (i.e. the first byte past
/// the null terminator, before padding).
pub(crate) fn read_version_blob_key(
    blob: &[u8],
    mut offset: usize,
    limit: usize,
) -> AppResult<(String, usize)> {
    let mut code_units = Vec::new();
    loop {
        if offset + 2 > limit {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                "version key unterminated",
            ));
        }
        let lo = blob[offset];
        let hi = blob[offset + 1];
        let unit = u16::from_le_bytes([lo, hi]);
        if unit == 0 {
            return Ok((String::from_utf16_lossy(&code_units), offset + 2));
        }
        code_units.push(unit);
        offset += 2;
    }
}

/// Align `offset` up to the next 4-byte boundary.
pub(crate) fn align4_version(offset: usize) -> usize {
    (offset + 3) & !3
}

/// Find a child block with the given key inside a version-info parent block.
/// `parent_data` is the raw bytes of the parent block (starting at wLength).
/// `parent_offset_within_blob` is where this parent starts relative to `full_blob`.
///
/// Returns `Some((child_offset_in_full_blob, child_data_slice))` if found.
pub(crate) fn find_version_child_block<'a>(
    parent_data: &'a [u8],
    parent_offset_within_blob: usize,
    _full_blob: &'a [u8],
    target_key: &str,
) -> Option<(usize, &'a [u8])> {
    if parent_data.len() < 6 {
        return None;
    }
    let w_length = u16::from_le_bytes([parent_data[0], parent_data[1]]) as usize;
    if w_length > parent_data.len() || w_length < 6 {
        return None;
    }
    let w_value_length = u16::from_le_bytes([parent_data[2], parent_data[3]]) as usize;
    // Skip header (6 bytes) + key + padding
    let (_, after_key) = read_version_blob_key(parent_data, 6, w_length).ok()?;
    let mut cursor = align4_version(after_key);
    // Skip value data + padding
    cursor = align4_version(cursor + w_value_length);
    // Iterate children
    while cursor + 6 <= w_length {
        let child_len = u16::from_le_bytes([parent_data[cursor], parent_data[cursor + 1]]) as usize;
        if child_len == 0 || cursor + child_len > w_length {
            break;
        }
        let child_data = &parent_data[cursor..cursor + child_len];
        let (child_key, _) = read_version_blob_key(child_data, 6, child_len).ok()?;
        if child_key.eq_ignore_ascii_case(target_key) {
            return Some((parent_offset_within_blob + cursor, child_data));
        }
        cursor = align4_version(cursor + child_len);
    }
    None
}

/// Find a string value inside a StringFileInfo heirarchy.
/// Looks for: StringFileInfo → <lang_codepage> → <key_name>
/// Returns the value bytes (as UTF-16LE).
pub(crate) fn find_version_string_value<'a>(
    block_data: &'a [u8],
    block_offset: usize,
    full_blob: &'a [u8],
    lang_codepage: &str,
    key_name: &str,
) -> Option<&'a [u8]> {
    let (sfi_offset, string_file_info) =
        find_version_child_block(block_data, block_offset, full_blob, "StringFileInfo")?;
    let (lang_offset, lang_table) =
        find_version_child_block(string_file_info, sfi_offset, full_blob, lang_codepage)?;
    let (_, string_entry) = find_version_child_block(lang_table, lang_offset, full_blob, key_name)?;
    let w_value_length = u16::from_le_bytes([string_entry[2], string_entry[3]]) as usize;
    if w_value_length == 0 {
        return None;
    }
    // Skip header (6 bytes) + key + padding
    let (_, after_key) = read_version_blob_key(string_entry, 6, string_entry.len()).ok()?;
    let value_offset = align4_version(after_key);
    let value_end = value_offset + w_value_length * 2; // wValueLength is in WORDS
    if value_end > string_entry.len() {
        return None;
    }
    Some(&string_entry[value_offset..value_end])
}

/// Find the VS_FIXEDFILEINFO structure within a version info root block.
/// Returns `Some(offset_within_blob)` where the VS_FIXEDFILEINFO starts.
pub(crate) fn find_fixed_file_info_in_blob(blob: &[u8]) -> Option<usize> {
    if blob.len() < 6 {
        return None;
    }
    let w_value_length = u16::from_le_bytes([blob[2], blob[3]]) as usize;
    if w_value_length < 52 {
        return None; // VS_FIXEDFILEINFO is 52 bytes
    }
    let (_, after_key) = read_version_blob_key(blob, 6, blob.len()).ok()?;
    let fixed_info_offset = align4_version(after_key);
    if fixed_info_offset + 52 > blob.len() {
        return None;
    }
    // Verify signature
    let sig = u32::from_le_bytes([
        blob[fixed_info_offset],
        blob[fixed_info_offset + 1],
        blob[fixed_info_offset + 2],
        blob[fixed_info_offset + 3],
    ]);
    if sig != 0xfeef04bd {
        return None;
    }
    Some(fixed_info_offset)
}

/// Find the VarFileInfo translation array within a version info blob.
/// Returns `Some((offset_in_blob, byte_count))` of the Translation value.
pub(crate) fn find_var_translation_in_blob(blob: &[u8]) -> Option<(usize, usize)> {
    let (_, var_file_info) = find_version_child_block(blob, 0, blob, "VarFileInfo")?;
    let (_, translation_entry) = find_version_child_block(var_file_info, 0, blob, "Translation")?;
    let w_value_length = u16::from_le_bytes([translation_entry[2], translation_entry[3]]) as usize;
    if w_value_length == 0 {
        return None;
    }
    let (_, after_key) =
        read_version_blob_key(translation_entry, 6, translation_entry.len()).ok()?;
    let value_offset = align4_version(after_key);
    let value_byte_len = w_value_length * 2; // wValueLength is in WORDS
    if value_offset + value_byte_len > translation_entry.len() {
        return None;
    }
    Some((value_offset, value_byte_len))
}
