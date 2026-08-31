//! Property-system dispatch: the propsys.dll exports, in a dedicated module
//! per the audit's modularity requirement.  The property-key surface is a
//! real registry of the canonical property keys: `PSGetPropertyKeyFromName`
//! and `PSPropertyKeyFromString` resolve the canonical names (System.Title,
//! System.Author, ...) to their {GUID, PID} pairs and the reverse mappings
//! format them back; the PROPVARIANT helpers (`InitPropVariantFromString`,
//! `InitPropVariantFromGUIDAsString`, `PropVariantClear`, `PropVariantCopy`)
//! operate on the documented PROPVARIANT layout.
//!
//! Layer contract: every export returns its HRESULT in EAX.

use super::super::*;

/// S_OK.
const S_OK: u32 = 0;
/// E_INVALIDARG.
const E_INVALIDARG: u32 = 0x8007_0057;
/// E_OUTOFMEMORY.
/// TYPE_E_ELEMENTNOTFOUND — the property is not in the registry.
const TYPE_E_ELEMENTNOTFOUND: u32 = 0x8002_802b;
/// The propvar types.
const VT_LPWSTR: u32 = 31;
const VT_EMPTY: u32 = 0;

/// One canonical property key: {guid, pid} <-> canonical name.
struct PropertyKey {
    guid: [u8; 16],
    pid: u32,
    name: &'static str,
}

/// The canonical property-key registry (the well-known System.* keys).
const PROPERTY_KEYS: &[PropertyKey] = &[
    PropertyKey {
        guid: [
            0xe0, 0x85, 0x9f, 0xf2, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 2,
        name: "System.Title",
    },
    PropertyKey {
        guid: [
            0xf3, 0x29, 0x85, 0xf4, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 4,
        name: "System.Author",
    },
    PropertyKey {
        guid: [
            0xb7, 0x25, 0x8d, 0xf5, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 12,
        name: "System.DateModified",
    },
    PropertyKey {
        guid: [
            0x2c, 0x9a, 0x5d, 0xb7, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 5,
        name: "System.Size",
    },
    PropertyKey {
        guid: [
            0xdd, 0x35, 0x40, 0x9d, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 4,
        name: "System.ItemNameDisplay",
    },
    PropertyKey {
        guid: [
            0xb7, 0x25, 0x8d, 0xf5, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 19,
        name: "System.Keywords",
    },
    PropertyKey {
        guid: [
            0x2c, 0x9a, 0x5d, 0xb7, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 3,
        name: "System.ItemType",
    },
    PropertyKey {
        guid: [
            0x56, 0xa0, 0xf9, 0xd5, 0x92, 0xc4, 0x48, 0x42, 0x87, 0x13, 0x34, 0x24, 0x79, 0x0f,
            0x4c, 0x50,
        ],
        pid: 100,
        name: "System.Photo.DateTaken",
    },
    PropertyKey {
        guid: [
            0x5c, 0xbf, 0x39, 0xbf, 0x92, 0x80, 0x41, 0x49, 0x92, 0x31, 0x73, 0x23, 0x7f, 0xa0,
            0x9f, 0xbf,
        ],
        pid: 3,
        name: "System.Music.Artist",
    },
    PropertyKey {
        guid: [
            0x2c, 0x9a, 0x5d, 0xb7, 0xf9, 0x4f, 0x68, 0x10, 0xab, 0x91, 0x08, 0x00, 0x2b, 0x27,
            0xb3, 0xd9,
        ],
        pid: 6,
        name: "System.Comment",
    },
    PropertyKey {
        guid: [
            0x9b, 0x4d, 0x0b, 0x8d, 0x4c, 0x39, 0x43, 0x4f, 0x8d, 0x1b, 0x2c, 0x96, 0x3b, 0xc4,
            0x5e, 0xd9,
        ],
        pid: 2,
        name: "System.DisplayName",
    },
    PropertyKey {
        guid: [
            0x9b, 0x4d, 0x0b, 0x8d, 0x4c, 0x39, 0x43, 0x4f, 0x8d, 0x1b, 0x2c, 0x96, 0x3b, 0xc4,
            0x5e, 0xd9,
        ],
        pid: 3,
        name: "System.DisplayType",
    },
];

impl PeHostRuntime {
    /// Route every property-system thunk to its dispatch function.
    pub(crate) fn dispatch_propsys(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::PSGetPropertyKeyFromName => {
                let name = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let name = read_utf16_string(memory, name).unwrap_or_default();
                let Some(key) = PROPERTY_KEYS
                    .iter()
                    .find(|k| k.name.eq_ignore_ascii_case(&name))
                else {
                    state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
                    return Ok(());
                };
                write_property_key(memory, out, key);
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::PSGetNameFromPropertyKey => {
                let key = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let guid = read_guid_bytes(memory, key);
                let pid = read_guest_u32(memory, key + 16).unwrap_or(0);
                let Some(found) = PROPERTY_KEYS
                    .iter()
                    .find(|k| k.guid == guid && k.pid == pid)
                else {
                    state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
                    return Ok(());
                };
                let address = self.propsys_scratch_string(memory, found.name)?;
                if out != 0 {
                    write_guest_pointer(memory, out, address, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::PSPropertyKeyFromString | HostThunk::PSStringFromPropertyKey => {
                let is_from_string = matches!(thunk, HostThunk::PSPropertyKeyFromString);
                if is_from_string {
                    // The "{GUID} PID" form.
                    let text = guest_call_arg(state, memory, 0)?;
                    let out = guest_call_arg(state, memory, 1)?;
                    let text = read_utf16_string(memory, text).unwrap_or_default();
                    let parts: Vec<&str> = text.split(' ').collect();
                    if parts.len() != 2 {
                        state.set(Register::Rax, u64::from(E_INVALIDARG));
                        return Ok(());
                    }
                    let Ok(guid) =
                        uuid::Uuid::parse_str(parts[0].trim_matches(|c| c == '{' || c == '}'))
                    else {
                        state.set(Register::Rax, u64::from(E_INVALIDARG));
                        return Ok(());
                    };
                    let pid = parts[1].parse::<u32>().unwrap_or(0);
                    let key = PropertyKey {
                        guid: guid.into_bytes(),
                        pid,
                        name: "",
                    };
                    write_property_key(memory, out, &key);
                    state.set(Register::Rax, u64::from(S_OK));
                } else {
                    let key = guest_call_arg(state, memory, 0)?;
                    let out = guest_call_arg(state, memory, 1)?;
                    let capacity = guest_call_arg_u32(state, memory, 2)?;
                    let guid = read_guid_bytes(memory, key);
                    let pid = read_guest_u32(memory, key + 16).unwrap_or(0);
                    let text = format!("{{{}}} {}", uuid::Uuid::from_bytes(guid), pid);
                    if out != 0 {
                        for (i, unit) in text.encode_utf16().enumerate().take(capacity as usize - 1)
                        {
                            write_guest_u16(memory, out + (i as u64 * 2), unit).ok();
                        }
                        write_guest_u16(
                            memory,
                            out + (text.encode_utf16().count().min(capacity as usize - 1) as u64
                                * 2),
                            0,
                        )
                        .ok();
                    }
                    state.set(Register::Rax, u64::from(S_OK));
                }
                Ok(())
            }
            HostThunk::PSGetPropertyDescriptionFromName => {
                // No property descriptions are registered.
                let _name = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
                Ok(())
            }
            HostThunk::InitPropVariantFromString => {
                let string = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let text = read_utf16_string(memory, string).unwrap_or_default();
                // The PROPVARIANT with VT_LPWSTR: the string is copied to a
                // guest-resident copy.
                let address = self.propsys_scratch_string(memory, &text)?;
                if out != 0 {
                    write_guest_u32(memory, out, VT_LPWSTR).ok();
                    write_guest_pointer(memory, out + 8, address, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::InitPropVariantFromGUIDAsString => {
                let guid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let bytes = memory.read_bytes(guid, 16).unwrap_or_default();
                let mut raw = [0_u8; 16];
                raw.copy_from_slice(&bytes);
                let text = format!("{{{}}}", uuid::Uuid::from_bytes(raw));
                let address = self.propsys_scratch_string(memory, &text)?;
                if out != 0 {
                    write_guest_u32(memory, out, VT_LPWSTR).ok();
                    write_guest_pointer(memory, out + 8, address, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::PropVariantClear | HostThunk::PropVariantCopy => {
                let out = guest_call_arg(state, memory, 1)?;
                if matches!(thunk, HostThunk::PropVariantClear) {
                    if out != 0 {
                        write_guest_u32(memory, out, VT_EMPTY).ok();
                    }
                    state.set(Register::Rax, u64::from(S_OK));
                } else {
                    let source = guest_call_arg(state, memory, 0)?;
                    if out != 0 {
                        let vt = read_guest_u32(memory, source).unwrap_or(0);
                        write_guest_u32(memory, out, vt).ok();
                        for offset in [8, 16] {
                            let value = read_guest_u64(memory, source + offset).unwrap_or(0);
                            write_guest_u64(memory, out + offset, value).ok();
                        }
                    }
                    state.set(Register::Rax, u64::from(S_OK));
                }
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted property-system thunk {thunk:?}"),
            )),
        }
    }

    /// The guest-resident scratch string for the property surface (the
    /// wide string the name/init functions return).
    fn propsys_scratch_string(&mut self, memory: &mut MemoryImage, text: &str) -> AppResult<u64> {
        let mut address = self.wic.string_slots[2];
        if address == 0 {
            address = self.alloc_zeroed(memory, 256, 8)?;
            self.wic.string_slots[2] = address;
        }
        for (i, unit) in text.encode_utf16().enumerate() {
            write_guest_u16(memory, address + (i as u64 * 2), unit).ok();
        }
        write_guest_u16(
            memory,
            address + (text.encode_utf16().count() as u64 * 2),
            0,
        )
        .ok();
        Ok(address)
    }
}

fn write_property_key(memory: &mut MemoryImage, address: u64, key: &PropertyKey) {
    if address == 0 {
        return;
    }
    for (i, byte) in key.guid.iter().enumerate() {
        memory.write_u8(address + i as u64, *byte);
    }
    write_guest_u32(memory, address + 16, key.pid).ok();
}

fn read_guid_bytes(memory: &MemoryImage, address: u64) -> [u8; 16] {
    let mut guid = [0_u8; 16];
    if let Ok(bytes) = memory.read_bytes(address, 16) {
        guid.copy_from_slice(&bytes);
    }
    guid
}
