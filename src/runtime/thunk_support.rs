//! Thunk support helpers.

use super::*;

pub(crate) fn unsupported_method(telemetry: &TelemetryCollector, name: &str) -> HostThunk {
    telemetry.record_unsupported_method(name);
    HostThunk::UnsupportedMethod {
        name: name.to_string(),
    }
}

pub(crate) fn align_up_u64(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let mask = align - 1;
    (value + mask) & !mask
}

pub(crate) fn minimal_synthetic_module_image(module_base: u64, guest_arch: GuestArch) -> Vec<u8> {
    let mut image = vec![0_u8; 0x1000];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");

    let machine = match guest_arch {
        GuestArch::X86 => 0x014c_u16,
        GuestArch::X64 => 0x8664_u16,
    };
    image[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    image[0x94..0x96].copy_from_slice(
        &match guest_arch {
            GuestArch::X86 => 0x00e0_u16,
            GuestArch::X64 => 0x00f0_u16,
        }
        .to_le_bytes(),
    );
    image[0x96..0x98].copy_from_slice(
        &match guest_arch {
            GuestArch::X86 => 0x2102_u16,
            GuestArch::X64 => 0x2022_u16,
        }
        .to_le_bytes(),
    );

    let optional = 0x98;
    match guest_arch {
        GuestArch::X86 => {
            image[optional..optional + 2].copy_from_slice(&0x010b_u16.to_le_bytes());
            image[optional + 0x1c..optional + 0x20]
                .copy_from_slice(&(module_base as u32).to_le_bytes());
            image[optional + 0x20..optional + 0x24].copy_from_slice(&0x1000_u32.to_le_bytes());
            image[optional + 0x24..optional + 0x28].copy_from_slice(&0x200_u32.to_le_bytes());
            image[optional + 0x38..optional + 0x3c].copy_from_slice(&0x1000_u32.to_le_bytes());
            image[optional + 0x3c..optional + 0x40].copy_from_slice(&0x200_u32.to_le_bytes());
            image[optional + 0x44..optional + 0x46].copy_from_slice(&2_u16.to_le_bytes());
            image[optional + 0x48..optional + 0x4c].copy_from_slice(&0x10_0000_u32.to_le_bytes());
            image[optional + 0x4c..optional + 0x50].copy_from_slice(&0x1000_u32.to_le_bytes());
            image[optional + 0x50..optional + 0x54].copy_from_slice(&0x10_0000_u32.to_le_bytes());
            image[optional + 0x54..optional + 0x58].copy_from_slice(&0x1000_u32.to_le_bytes());
            image[optional + 0x5c..optional + 0x60].copy_from_slice(&16_u32.to_le_bytes());
        }
        GuestArch::X64 => {
            image[optional..optional + 2].copy_from_slice(&0x020b_u16.to_le_bytes());
            image[optional + 0x18..optional + 0x20].copy_from_slice(&module_base.to_le_bytes());
            image[optional + 0x20..optional + 0x24].copy_from_slice(&0x1000_u32.to_le_bytes());
            image[optional + 0x24..optional + 0x28].copy_from_slice(&0x200_u32.to_le_bytes());
            image[optional + 0x38..optional + 0x3c].copy_from_slice(&0x1000_u32.to_le_bytes());
            image[optional + 0x3c..optional + 0x40].copy_from_slice(&0x200_u32.to_le_bytes());
            image[optional + 0x44..optional + 0x46].copy_from_slice(&2_u16.to_le_bytes());
            image[optional + 0x48..optional + 0x50].copy_from_slice(&0x10_0000_u64.to_le_bytes());
            image[optional + 0x50..optional + 0x58].copy_from_slice(&0x1000_u64.to_le_bytes());
            image[optional + 0x58..optional + 0x60].copy_from_slice(&0x10_0000_u64.to_le_bytes());
            image[optional + 0x60..optional + 0x68].copy_from_slice(&0x1000_u64.to_le_bytes());
            image[optional + 0x6c..optional + 0x70].copy_from_slice(&16_u32.to_le_bytes());
        }
    }

    image
}
