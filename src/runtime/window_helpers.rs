//! Guest window-class read/write helpers.

use super::*;

pub(crate) fn read_window(memory: &MemoryImage, address: u64, len: usize) -> AppResult<Vec<u8>> {
    let mut bytes = vec![0; len];
    memory.read_into_slice(address, &mut bytes)?;
    Ok(bytes)
}

#[allow(dead_code)] // window-match assertion helper; used by tests
pub(crate) fn read_window_matches(
    memory: &MemoryImage,
    address: u64,
    expected: &[u8],
) -> AppResult<bool> {
    let mut offset = 0_usize;
    let mut scratch = [0_u8; 64];
    while offset < expected.len() {
        let chunk_len = (expected.len() - offset).min(scratch.len());
        let chunk = &mut scratch[..chunk_len];
        memory.read_into_slice(address + offset as u64, chunk)?;
        if chunk != &expected[offset..offset + chunk_len] {
            return Ok(false);
        }
        offset += chunk_len;
    }
    Ok(true)
}

pub(crate) fn probe_read_window(memory: &MemoryImage, address: u64, len: usize) -> Option<Vec<u8>> {
    if !memory.is_range_mapped(address, len) {
        return None;
    }
    read_window(memory, address, len).ok()
}

pub(crate) fn read_i32_from_memory(memory: &MemoryImage, address: u64) -> AppResult<i32> {
    let bytes = read_window(memory, address, 4)?;
    Ok(i32::from_le_bytes(bytes.try_into().expect("disp32")))
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuestWindowClass {
    pub(crate) style: u32,
    pub(crate) wnd_proc: u64,
    pub(crate) cls_extra: i32,
    pub(crate) wnd_extra: i32,
    pub(crate) instance: u64,
    pub(crate) icon: u64,
    pub(crate) cursor: u64,
    pub(crate) background: u64,
    pub(crate) menu_name: u64,
    pub(crate) class_name_ptr: u64,
    pub(crate) icon_small: u64,
}

pub(crate) fn read_guest_window_class(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    extended: bool,
) -> AppResult<GuestWindowClass> {
    let base = if extended { 4 } else { 0 };
    Ok(match guest_arch {
        GuestArch::X86 => GuestWindowClass {
            style: read_guest_u32(memory, address + base)?,
            wnd_proc: read_guest_u32(memory, address + base + 4)? as u64,
            cls_extra: read_guest_u32(memory, address + base + 8)? as i32,
            wnd_extra: read_guest_u32(memory, address + base + 12)? as i32,
            instance: read_guest_u32(memory, address + base + 16)? as u64,
            icon: read_guest_u32(memory, address + base + 20)? as u64,
            cursor: read_guest_u32(memory, address + base + 24)? as u64,
            background: read_guest_u32(memory, address + base + 28)? as u64,
            menu_name: read_guest_u32(memory, address + base + 32)? as u64,
            class_name_ptr: read_guest_u32(memory, address + base + 36)? as u64,
            icon_small: if extended {
                read_guest_u32(memory, address + base + 40)? as u64
            } else {
                0
            },
        },
        GuestArch::X64 => GuestWindowClass {
            style: read_guest_u32(memory, address + base)?,
            wnd_proc: read_guest_pointer(memory, address + 8, guest_arch)?,
            cls_extra: read_guest_u32(memory, address + 16)? as i32,
            wnd_extra: read_guest_u32(memory, address + 20)? as i32,
            instance: read_guest_pointer(memory, address + 24, guest_arch)?,
            icon: read_guest_pointer(memory, address + 32, guest_arch)?,
            cursor: read_guest_pointer(memory, address + 40, guest_arch)?,
            background: read_guest_pointer(memory, address + 48, guest_arch)?,
            menu_name: read_guest_pointer(memory, address + 56, guest_arch)?,
            class_name_ptr: read_guest_pointer(memory, address + 64, guest_arch)?,
            icon_small: if extended {
                read_guest_pointer(memory, address + 72, guest_arch)?
            } else {
                0
            },
        },
    })
}

pub(crate) fn write_guest_window_class(
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    class_info: WindowClassInfo,
    extended: bool,
) -> AppResult<()> {
    match guest_arch {
        GuestArch::X86 => {
            let base = if extended { 4 } else { 0 };
            if extended {
                write_u32(memory, address, 48);
            }
            write_u32(memory, address + base, class_info.style);
            write_u32(memory, address + base + 4, class_info.wnd_proc as u32);
            write_u32(memory, address + base + 8, class_info.cls_extra as u32);
            write_u32(memory, address + base + 12, class_info.wnd_extra as u32);
            write_u32(memory, address + base + 16, class_info.instance as u32);
            write_u32(memory, address + base + 20, class_info.icon as u32);
            write_u32(memory, address + base + 24, class_info.cursor as u32);
            write_u32(memory, address + base + 28, class_info.background as u32);
            write_u32(memory, address + base + 32, class_info.menu_name as u32);
            write_u32(
                memory,
                address + base + 36,
                class_info.class_name_ptr as u32,
            );
            if extended {
                write_u32(memory, address + base + 40, class_info.icon_small as u32);
            }
        }
        GuestArch::X64 => {
            if extended {
                write_u32(memory, address, 80);
                write_u32(memory, address + 4, class_info.style);
                write_guest_pointer(memory, address + 8, class_info.wnd_proc, guest_arch)?;
                write_u32(memory, address + 16, class_info.cls_extra as u32);
                write_u32(memory, address + 20, class_info.wnd_extra as u32);
                write_guest_pointer(memory, address + 24, class_info.instance, guest_arch)?;
                write_guest_pointer(memory, address + 32, class_info.icon, guest_arch)?;
                write_guest_pointer(memory, address + 40, class_info.cursor, guest_arch)?;
                write_guest_pointer(memory, address + 48, class_info.background, guest_arch)?;
                write_guest_pointer(memory, address + 56, class_info.menu_name, guest_arch)?;
                write_guest_pointer(memory, address + 64, class_info.class_name_ptr, guest_arch)?;
                write_guest_pointer(memory, address + 72, class_info.icon_small, guest_arch)?;
            } else {
                write_u32(memory, address, class_info.style);
                write_u32(memory, address + 4, 0);
                write_guest_pointer(memory, address + 8, class_info.wnd_proc, guest_arch)?;
                write_u32(memory, address + 16, class_info.cls_extra as u32);
                write_u32(memory, address + 20, class_info.wnd_extra as u32);
                write_guest_pointer(memory, address + 24, class_info.instance, guest_arch)?;
                write_guest_pointer(memory, address + 32, class_info.icon, guest_arch)?;
                write_guest_pointer(memory, address + 40, class_info.cursor, guest_arch)?;
                write_guest_pointer(memory, address + 48, class_info.background, guest_arch)?;
                write_guest_pointer(memory, address + 56, class_info.menu_name, guest_arch)?;
                write_guest_pointer(memory, address + 64, class_info.class_name_ptr, guest_arch)?;
            }
        }
    }
    Ok(())
}
