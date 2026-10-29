//! System-information and per-arch address-layout helpers.

use super::*;

pub(crate) const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
pub(crate) const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;

pub(crate) fn write_system_info(memory: &mut MemoryImage, info_ptr: u64, guest_arch: GuestArch) {
    let (arch, ptr_size) = match guest_arch {
        GuestArch::X86 => (PROCESSOR_ARCHITECTURE_INTEL, 4u64),
        GuestArch::X64 => (PROCESSOR_ARCHITECTURE_AMD64, 8),
    };
    let page_size: u32 = 4096;
    let min_address: u64 = 0x10000;
    let max_address: u64 = if ptr_size == 8 {
        0x7FFE_FFFF_FFFF
    } else {
        0x7FFF_FFFF
    };
    let active_processor_mask: u64 = 0xFF;
    let number_of_processors: u32 = 8;
    let processor_type: u32 = 0;
    let allocation_granularity: u32 = 0x10000;
    let processor_level: u16 = match arch {
        PROCESSOR_ARCHITECTURE_INTEL => 6,
        PROCESSOR_ARCHITECTURE_AMD64 => 21,
        _ => 0,
    };
    let processor_revision: u16 = 0;

    let mut offset = info_ptr;
    write_u16(memory, offset, arch);
    offset += 2;
    write_u16(memory, offset, 0);
    offset += 2;
    write_u32(memory, offset, page_size);
    offset += 4;
    write_u64(memory, offset, min_address);
    offset += ptr_size;
    write_u64(memory, offset, max_address);
    offset += ptr_size;
    write_u64(memory, offset, active_processor_mask);
    offset += ptr_size;
    write_u32(memory, offset, number_of_processors);
    offset += 4;
    write_u32(memory, offset, processor_type);
    offset += 4;
    write_u32(memory, offset, allocation_granularity);
    offset += 4;
    write_u16(memory, offset, processor_level);
    offset += 2;
    write_u16(memory, offset, processor_revision);
}

pub(crate) fn known_folder_path_from_guid(guid: &str) -> Option<String> {
    let lower = guid.to_ascii_lowercase();
    match lower.as_str() {
        "{905e63b6-c1bf-494e-b29c-65b732d3d21a}" => Some("C:\\Program Files".to_string()),
        "{7c5a40ef-a0fb-4bfc-b74b-c3f8e2f44b6e}" => Some("C:\\Program Files (x86)".to_string()),
        "{f1b32785-6fba-4fcf-9d55-7b8e7f157091}" => {
            Some("C:\\Users\\user\\AppData\\Local".to_string())
        }
        "{3eb685db-65f9-4cf6-a03a-e3ef65729f51}" => {
            Some("C:\\Users\\user\\AppData\\Roaming".to_string())
        }
        "{62ab5d82-fdc1-4dc3-a9dd-070d1d495d97}" => Some("C:\\ProgramData".to_string()),
        "{b4bfcc3a-db2c-424c-b029-7fe99a87c641}" => Some("C:\\Users\\user\\Desktop".to_string()),
        "{fdd39ad0-238f-46af-adb4-6c85480369c7}" => Some("C:\\Users\\user\\Documents".to_string()),
        "{33e28130-4e1e-4676-835a-98395c3bc3bb}" => Some("C:\\Users\\user\\Pictures".to_string()),
        "{fd228cb7-ae11-4ae3-864c-16f3910ab8fe}" => Some("C:\\Windows\\Fonts".to_string()),
        "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}" => Some("C:\\Windows\\System32".to_string()),
        "{f38bf404-1d43-42f2-9305-67de0b28fc23}" => Some("C:\\Windows".to_string()),
        "{d65231b0-b2f1-4855-a4bb-0e499e2d45ba}" => {
            Some("C:\\Users\\user\\AppData\\Local\\Temp".to_string())
        }
        "{a520a1a4-1780-4ff6-bd18-167343c5af16}" => {
            Some("C:\\Users\\user\\AppData\\LocalLow".to_string())
        }
        "{5cd7aee2-2219-4a67-b85d-6c9ce15660cb}" => {
            Some("C:\\Users\\user\\AppData\\Local\\Programs".to_string())
        }
        _ => None,
    }
}

pub(crate) fn stack_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => STACK_BASE,
        GuestArch::X86 => X86_STACK_BASE,
    }
}

pub(crate) fn thunk_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => THUNK_BASE,
        GuestArch::X86 => X86_THUNK_BASE,
    }
}

pub(crate) fn data_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => CRT_DATA_BASE,
        GuestArch::X86 => X86_CRT_DATA_BASE,
    }
}

pub(crate) fn heap_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => CRT_HEAP_BASE,
        GuestArch::X86 => X86_CRT_HEAP_BASE,
    }
}

pub(crate) fn private_pages_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => PRIVATE_PAGES_BASE,
        GuestArch::X86 => X86_PRIVATE_PAGES_BASE,
    }
}
