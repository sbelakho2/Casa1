//! Guest MSG structure read/write helpers.

use super::*;

pub(crate) fn write_win64_msg(
    memory: &mut MemoryImage,
    address: u64,
    message: &Message,
) -> AppResult<()> {
    write_u64(memory, address, message.hwnd.unwrap_or(0) as u64);
    write_u32(memory, address + 8, message_id(message.kind));
    write_u32(memory, address + 12, 0);
    write_u64(memory, address + 16, message.wparam as u64);
    write_u64(memory, address + 24, message.lparam as u64);
    write_u32(memory, address + 32, 0);
    write_u32(memory, address + 36, 0);
    write_u32(memory, address + 40, 0);
    write_u32(memory, address + 44, 0);
    Ok(())
}

pub(crate) fn write_win32_msg(
    memory: &mut MemoryImage,
    address: u64,
    message: &Message,
) -> AppResult<()> {
    write_u32(memory, address, message.hwnd.unwrap_or(0));
    write_u32(memory, address + 4, message_id(message.kind));
    write_u32(memory, address + 8, message.wparam as u32);
    write_u32(memory, address + 12, message.lparam as u32);
    write_u32(memory, address + 16, 0);
    write_u32(memory, address + 20, 0);
    write_u32(memory, address + 24, 0);
    Ok(())
}

pub(crate) fn read_win64_msg(memory: &MemoryImage, address: u64) -> AppResult<Message> {
    Ok(Message {
        hwnd: match memory.read_u64(address)? {
            0 => None,
            hwnd => Some(hwnd as u32),
        },
        kind: message_kind(read_u32(memory, address + 8)?)?,
        wparam: memory.read_u64(address + 16)? as i64,
        lparam: memory.read_u64(address + 24)? as i64,
        translated: false,
        device_id: None,
    })
}

pub(crate) fn read_win32_msg(memory: &MemoryImage, address: u64) -> AppResult<Message> {
    Ok(Message {
        hwnd: match read_u32(memory, address)? {
            0 => None,
            hwnd => Some(hwnd),
        },
        kind: message_kind(read_u32(memory, address + 4)?)?,
        wparam: read_u32(memory, address + 8)? as i64,
        lparam: read_u32(memory, address + 12)? as i32 as i64,
        translated: false,
        device_id: None,
    })
}

pub(crate) fn message_id(kind: MessageKind) -> u32 {
    match kind {
        MessageKind::Create => 0x0001,
        MessageKind::Destroy => 0x0002,
        MessageKind::Size => 0x0005,
        MessageKind::Activate => 0x0006,
        MessageKind::SetFocus => 0x0007,
        MessageKind::KillFocus => 0x0008,
        MessageKind::Paint => 0x000f,
        MessageKind::Quit => 0x0012,
        MessageKind::ShowWindow => 0x0018,
        MessageKind::WindowPosChanging => 0x0046,
        MessageKind::InputDeviceChange => 0x00fe,
        MessageKind::Input | MessageKind::RawInput => 0x00ff,
        MessageKind::NcCreate => 0x0081,
        MessageKind::NcDestroy => 0x0082,
        MessageKind::NcCalcSize => 0x0083,
        MessageKind::KeyDown => 0x0100,
        MessageKind::KeyUp => 0x0101,
        MessageKind::Char => 0x0102,
        MessageKind::DeadChar => 0x0103,
        MessageKind::Command => 0x0111,
        MessageKind::MouseMove => 0x0200,
        MessageKind::LButtonDown => 0x0201,
        MessageKind::LButtonUp => 0x0202,
        MessageKind::LButtonDblClk => 0x0203,
        MessageKind::RButtonDown => 0x0204,
        MessageKind::RButtonUp => 0x0205,
        MessageKind::RButtonDblClk => 0x0206,
        MessageKind::MButtonDown => 0x0207,
        MessageKind::MButtonUp => 0x0208,
        MessageKind::MButtonDblClk => 0x0209,
        MessageKind::MouseWheel => 0x020a,
        MessageKind::XButtonDown => 0x020b,
        MessageKind::MouseHWheel => 0x020e,
        MessageKind::Other(message_id) => message_id,
    }
}

pub(crate) fn message_kind(message_id: u32) -> AppResult<MessageKind> {
    match message_id {
        0x0001 => Ok(MessageKind::Create),
        0x0002 => Ok(MessageKind::Destroy),
        0x0005 => Ok(MessageKind::Size),
        0x0006 => Ok(MessageKind::Activate),
        0x0007 => Ok(MessageKind::SetFocus),
        0x0008 => Ok(MessageKind::KillFocus),
        0x000f => Ok(MessageKind::Paint),
        0x0012 => Ok(MessageKind::Quit),
        0x0018 => Ok(MessageKind::ShowWindow),
        0x0046 => Ok(MessageKind::WindowPosChanging),
        0x0081 => Ok(MessageKind::NcCreate),
        0x0082 => Ok(MessageKind::NcDestroy),
        0x0083 => Ok(MessageKind::NcCalcSize),
        0x00fe => Ok(MessageKind::InputDeviceChange),
        0x00ff => Ok(MessageKind::Input),
        0x0100 => Ok(MessageKind::KeyDown),
        0x0101 => Ok(MessageKind::KeyUp),
        0x0102 => Ok(MessageKind::Char),
        0x0103 => Ok(MessageKind::DeadChar),
        0x0111 => Ok(MessageKind::Command),
        0x0200 => Ok(MessageKind::MouseMove),
        0x0201 => Ok(MessageKind::LButtonDown),
        0x0202 => Ok(MessageKind::LButtonUp),
        0x0203 => Ok(MessageKind::LButtonDblClk),
        0x0204 => Ok(MessageKind::RButtonDown),
        0x0205 => Ok(MessageKind::RButtonUp),
        0x0206 => Ok(MessageKind::RButtonDblClk),
        0x0207 => Ok(MessageKind::MButtonDown),
        0x0208 => Ok(MessageKind::MButtonUp),
        0x0209 => Ok(MessageKind::MButtonDblClk),
        0x020a => Ok(MessageKind::MouseWheel),
        0x020b => Ok(MessageKind::XButtonDown),
        0x020e => Ok(MessageKind::MouseHWheel),
        _ => Ok(MessageKind::Other(message_id)),
    }
}

/// True when `message_id` is a mouse or keyboard input message (WM_KEY*,
/// WM_CHAR/WM_DEADCHAR, WM_INPUT/WM_RAWINPUT, WM_MOUSE*).  Only these count
/// as guest input consumption when delivered to a guest window procedure.
pub(crate) fn is_guest_input_message_id(message_id: u32) -> bool {
    matches!(
        message_kind(message_id),
        Ok(MessageKind::KeyDown
            | MessageKind::KeyUp
            | MessageKind::Char
            | MessageKind::DeadChar
            | MessageKind::Input
            | MessageKind::RawInput
            | MessageKind::MouseMove
            | MessageKind::LButtonDown
            | MessageKind::LButtonUp
            | MessageKind::LButtonDblClk
            | MessageKind::RButtonDown
            | MessageKind::RButtonUp
            | MessageKind::RButtonDblClk
            | MessageKind::MButtonDown
            | MessageKind::MButtonUp
            | MessageKind::MButtonDblClk
            | MessageKind::MouseWheel
            | MessageKind::MouseHWheel
            | MessageKind::XButtonDown)
    )
}
