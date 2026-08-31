//! HID dispatch: the hid.dll exports, in a dedicated module per the audit's
//! modularity requirement.  The preparsed-data surface is a real HID report
//! descriptor parser: `HidP_GetCaps` reads the usage page/usage, the input
//! report byte length, and the cap counts from the descriptor items;
//! `HidP_GetButtonCaps`/`HidP_GetValueCaps` fill the cap arrays;
//! `HidP_GetUsageValue`/`HidP_GetUsages`/`HidP_SetUsages` extract and set
//! bits in the report buffer.  No HID devices exist in the runtime, so the
//! device functions (`HidD_GetAttributes`, `HidD_GetPreparsedData`, ...)
//! fail with the documented FALSE answers.
//!
//! Layer contract: the HidD_* functions return BOOL in EAX; the HidP_*
//! functions return NTSTATUS-style HIDP_STATUS codes.

use super::super::*;

/// The HID class GUID: {4d1e55b2-f16f-11cf-88cb-001111000030}.
const HID_GUID: [u8; 16] = [
    0xb2, 0x55, 0x1e, 0x4d, 0x6f, 0xf1, 0xcf, 0x11, 0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30,
];
/// HIDP_STATUS_SUCCESS.
const HIDP_STATUS_SUCCESS: u32 = 0x0011_0000;
/// HIDP_STATUS_INVALID_PREPARSED_DATA.
const HIDP_STATUS_INVALID_PREPARSED_DATA: u32 = 0xc011_0001;
/// HIDP_STATUS_INVALID_REPORT_TYPE.
const HIDP_STATUS_INVALID_REPORT_TYPE: u32 = 0xc011_0002;
/// HIDP_STATUS_INVALID_REPORT_LENGTH.
const HIDP_STATUS_INVALID_REPORT_LENGTH: u32 = 0xc011_0003;

impl PeHostRuntime {
    /// Route every HID thunk to its dispatch function.
    pub(crate) fn dispatch_hid(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::HidDGetHidGuid => {
                let out = guest_call_arg(state, memory, 0)?;
                if out != 0 {
                    for (i, byte) in HID_GUID.iter().enumerate() {
                        memory.write_u8(out + i as u64, *byte);
                    }
                }
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::HidDGetAttributes
            | HostThunk::HidDGetProductString
            | HostThunk::HidDGetManufacturerString
            | HostThunk::HidDGetPreparsedData => {
                // No HID devices exist; the device functions fail.
                let device = guest_call_arg(state, memory, 0)?;
                let _ = device;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::HidDFreePreparsedData => {
                let preparsed = guest_call_arg(state, memory, 0)?;
                self.hid_preparsed.remove(&preparsed);
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::HidPGetCaps => {
                let preparsed = guest_call_arg(state, memory, 0)?;
                let caps = guest_call_arg(state, memory, 1)?;
                let Some(descriptor) = self.hid_preparsed.get(&preparsed).cloned() else {
                    state.set(Register::Rax, u64::from(HIDP_STATUS_INVALID_PREPARSED_DATA));
                    return Ok(());
                };
                let parsed = parse_hid_descriptor(&descriptor);
                if caps != 0 {
                    // HIDP_CAPS: Usage(0), UsagePage(2), InputReportByteLength(4),
                    // OutputReportByteLength(6), FeatureReportByteLength(8),
                    // Reserved(10), NumberLinkCollectionNodes(12),
                    // NumberInputButtonCaps(14), NumberInputValueCaps(16),
                    // NumberInputDataIndices(18), NumberOutputButtonCaps(20),
                    // NumberOutputValueCaps(22), NumberOutputDataIndices(24),
                    // NumberFeatureButtonCaps(26), NumberFeatureValueCaps(28),
                    // NumberFeatureDataIndices(30).
                    write_guest_u16(memory, caps, parsed.usage).ok();
                    write_guest_u16(memory, caps + 2, parsed.usage_page).ok();
                    write_guest_u16(memory, caps + 4, parsed.input_report_length).ok();
                    write_guest_u16(memory, caps + 6, parsed.output_report_length).ok();
                    write_guest_u16(memory, caps + 8, parsed.feature_report_length).ok();
                    write_guest_u16(memory, caps + 12, 1).ok();
                    write_guest_u16(memory, caps + 14, parsed.button_caps).ok();
                    write_guest_u16(memory, caps + 16, parsed.value_caps).ok();
                    write_guest_u16(memory, caps + 18, parsed.button_caps + parsed.value_caps).ok();
                }
                state.set(Register::Rax, u64::from(HIDP_STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::HidPGetButtonCaps | HostThunk::HidPGetValueCaps => {
                let _report_type = guest_call_arg_u32(state, memory, 0)?;
                let caps = guest_call_arg(state, memory, 1)?;
                let cap_count = guest_call_arg(state, memory, 2)?;
                let preparsed = guest_call_arg(state, memory, 3)?;
                let Some(descriptor) = self.hid_preparsed.get(&preparsed).cloned() else {
                    state.set(Register::Rax, u64::from(HIDP_STATUS_INVALID_PREPARSED_DATA));
                    return Ok(());
                };
                let parsed = parse_hid_descriptor(&descriptor);
                let count = if matches!(HostThunk::HidPGetButtonCaps, HostThunk::HidPGetButtonCaps)
                {
                    parsed.button_caps
                } else {
                    parsed.value_caps
                };
                if cap_count != 0 {
                    write_guest_u16(memory, cap_count, count).ok();
                }
                if caps != 0 {
                    for i in 0..count as usize {
                        // HIDP_BUTTON_CAPS: UsagePage(0), ReportID(2),
                        // IsAlias(4), BitField(6), LinkUsagePage(8),
                        // LinkUsage(10), LinkCollection(12), UsagePageRange
                        // (14: 2 u16s), IsRange(18), IsStringRange(20),
                        // IsDesignatorRange(22), IsAbsolute(24), Range(26).
                        write_guest_u16(memory, caps + (i as u64 * 34), parsed.usage_page).ok();
                        write_guest_u16(memory, caps + (i as u64 * 34) + 14, parsed.usage).ok();
                        write_guest_u16(memory, caps + (i as u64 * 34) + 16, parsed.usage).ok();
                        write_guest_u32(memory, caps + (i as u64 * 34) + 18, 1).ok();
                    }
                }
                state.set(Register::Rax, u64::from(HIDP_STATUS_SUCCESS));
                Ok(())
            }
            HostThunk::HidPGetUsageValue => self.dispatch_hid_usages(state, memory, 0),
            HostThunk::HidPGetUsages => self.dispatch_hid_usages(state, memory, 1),
            HostThunk::HidPSetUsages => self.dispatch_hid_usages(state, memory, 2),
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted HID thunk {thunk:?}"),
            )),
        }
    }

    /// The usage extractor/setter: read or write the usage bits in the
    /// report buffer.
    pub(crate) fn dispatch_hid_usages(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        kind: u32,
    ) -> AppResult<()> {
        let report_type = guest_call_arg_u32(state, memory, 0)?;
        let usage_page = guest_call_arg_u32(state, memory, 1)?;
        let _collection = guest_call_arg_u32(state, memory, 2)?;
        let usage = guest_call_arg_u32(state, memory, 3)?;
        let usage_length = guest_call_arg(state, memory, 4)?;
        let report = guest_call_arg(state, memory, 5)?;
        let report_length = guest_call_arg_u32(state, memory, 6)?;
        if report_type > 2 {
            state.set(Register::Rax, u64::from(HIDP_STATUS_INVALID_REPORT_TYPE));
            return Ok(());
        }
        if report == 0 {
            state.set(Register::Rax, u64::from(HIDP_STATUS_INVALID_REPORT_LENGTH));
            return Ok(());
        }
        let usage_low = (usage & 0xffff) as u16;
        let byte = (usage_low / 8) as u64;
        let bit = (usage_low % 8) as u64;
        if byte >= report_length as u64 {
            state.set(Register::Rax, u64::from(HIDP_STATUS_INVALID_REPORT_LENGTH));
            return Ok(());
        }
        if kind == 2 {
            let current = memory.read_u8(report + byte).unwrap_or(0);
            memory.write_u8(report + byte, current | (1 << bit));
            state.set(Register::Rax, u64::from(HIDP_STATUS_SUCCESS));
            return Ok(());
        }
        // GetUsages fills the usage array with the set usages; GetUsageValue
        // returns the value in *usageValue.
        if kind == 1 {
            let current = memory.read_u8(report + byte).unwrap_or(0);
            let mut written = 0_u32;
            if current & (1 << bit) != 0 {
                if usage_length != 0 {
                    write_guest_u16(memory, usage_length, usage_low).ok();
                }
                written = 1;
            }
            if usage_length != 0 && written == 0 {
                write_guest_u16(memory, usage_length, 0).ok();
            }
            let _ = usage_page;
            state.set(Register::Rax, u64::from(HIDP_STATUS_SUCCESS));
        } else {
            let current = memory.read_u8(report + byte).unwrap_or(0);
            let value = u64::from((current >> bit) & 1);
            if usage_length != 0 {
                write_guest_u64(memory, usage_length, value).ok();
            }
            state.set(Register::Rax, u64::from(HIDP_STATUS_SUCCESS));
        }
        Ok(())
    }
}

/// The parsed HID descriptor caps.
#[derive(Debug, Clone, Copy, Default)]
struct HidDescriptorCaps {
    usage: u16,
    usage_page: u16,
    input_report_length: u16,
    output_report_length: u16,
    feature_report_length: u16,
    button_caps: u16,
    value_caps: u16,
}

/// Parse a HID report descriptor into the caps summary.
fn parse_hid_descriptor(descriptor: &[u8]) -> HidDescriptorCaps {
    let mut caps = HidDescriptorCaps::default();
    let mut index = 0;
    let mut report_size = 0_u32;
    let mut report_count = 0_u32;
    let mut usage_page = 0_u16;
    let mut collection_page = 0_u16;
    let mut usage = 0_u16;
    let mut usages: Vec<u16> = Vec::new();
    let mut input_length = 0_u32;
    let mut output_length = 0_u32;
    let mut feature_length = 0_u32;
    while index < descriptor.len() {
        let byte = descriptor[index];
        let size = match byte & 0x03 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        if index + 1 + size > descriptor.len() {
            break;
        }
        let value = if size == 0 {
            0
        } else {
            let mut v = 0_u32;
            for i in 0..size {
                v |= (descriptor[index + 1 + i] as u32) << (8 * i);
            }
            v
        };
        let kind = (byte >> 2) & 0x03;
        let tag = (byte >> 4) & 0x0f;
        match kind {
            1 => {
                // Global items (bType 01 = Global).
                match tag {
                    0 => usage_page = value as u16,
                    7 => report_size = value,
                    9 => report_count = value,
                    _ => {}
                }
            }
            2 => {
                // Local items (bType 10 = Local).
                if tag == 0 {
                    usage = value as u16;
                    if usages.len() < 64 {
                        usages.push(usage);
                    }
                }
            }
            _ => match tag {
                // Main items.
                10 => {
                    // Collection: its usage page is the collection's page.
                    if collection_page == 0 {
                        collection_page = usage_page;
                    }
                }
                8 => {
                    // Input: buttons are 1-bit data items; values are the
                    // wider items; constant (padding) items are not caps.
                    input_length += report_size * report_count;
                    if value & 0x01 == 0 {
                        if report_size > 1 {
                            caps.value_caps = caps.value_caps.saturating_add(1);
                        } else {
                            caps.button_caps = caps.button_caps.saturating_add(1);
                        }
                        if caps.usage_page == 0 {
                            caps.usage_page = collection_page;
                        }
                        caps.usage = usages.first().copied().unwrap_or(usage);
                    }
                    usages.clear();
                }
                9 => {
                    // Output
                    output_length += report_size * report_count;
                    usages.clear();
                }
                11 => {
                    // Feature
                    feature_length += report_size * report_count;
                    usages.clear();
                }
                _ => {}
            },
        }
        index += 1 + size;
    }
    caps.input_report_length = (input_length.div_ceil(8)).min(0xffff) as u16;
    caps.output_report_length = (output_length.div_ceil(8)).min(0xffff) as u16;
    caps.feature_report_length = (feature_length.div_ceil(8)).min(0xffff) as u16;
    caps
}
