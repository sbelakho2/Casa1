use super::*;
use crate::casak::interrupt::{CONNECT_FULLY_SPECIFIED, CONNECT_LINE_BASED};
use crate::casak::io::STATUS_UNSUCCESSFUL;
use crate::ge::{GameEnvironment, GeArch, RegistryView};
use crate::host_thunks::ImplementationLevel;
use serde_json::json;
use tempfile::TempDir;

const TEXT_RVA: u32 = 0x1000;
const UNLOAD_RVA: u32 = 0x1100;
const RDATA_RVA: u32 = 0x2000;
const IMPORT_RVA: u32 = 0x2100;
const ILT_RVA: u32 = 0x2140;
const IAT_RVA: u32 = 0x21A0;
const DLL_NAME_RVA: u32 = 0x2200;
const DBG_FMT_RVA: u32 = 0x2380;
const WIDE_DEV_RVA: u32 = 0x23C0;
const WIDE_LINK_RVA: u32 = 0x2400;
const DBG_UNLOAD_RVA: u32 = 0x2440;
const EXPORT_RVA: u32 = 0x2480;
const DRIVER_PTR_RVA: u32 = 0x3000;
const US_DEV_RVA: u32 = 0x3008;
const US_LINK_RVA: u32 = 0x3018;
const DEV_OBJ_OUT_RVA: u32 = 0x3028;
const ENTRY_MARKER_RVA: u32 = 0x3030;
const UNLOAD_MARKER_RVA: u32 = 0x3034;

const IAT_DBG: u32 = IAT_RVA;
const IAT_RTL: u32 = IAT_RVA + 8;
const IAT_IO_CREATE: u32 = IAT_RVA + 16;
const IAT_IO_SYMLINK: u32 = IAT_RVA + 24;
const IAT_IO_DELETE: u32 = IAT_RVA + 32;
const IAT_IO_ALLOC_IRP: u32 = IAT_RVA + 40;
const IAT_IOF_COMPLETE: u32 = IAT_RVA + 56;
const IAT_EX_ALLOC: u32 = IAT_RVA + 72;
const IAT_EX_FREE: u32 = IAT_RVA + 80;

const IMPORT_NAMES: [(&str, u32); 11] = [
    ("DbgPrint", 0x2210),
    ("RtlInitUnicodeString", 0x2230),
    ("IoCreateDevice", 0x2250),
    ("IoCreateSymbolicLink", 0x2270),
    ("IoDeleteDevice", 0x2290),
    ("IoAllocateIrp", 0x22B0),
    ("IoFreeIrp", 0x22C0),
    ("IofCompleteRequest", 0x22D0),
    ("IoCompleteRequest", 0x22F0),
    ("ExAllocatePoolWithTag", 0x2310),
    ("ExFreePoolWithTag", 0x2330),
];

#[derive(Default)]
struct CodeBuilder {
    bytes: Vec<u8>,
    fixups: Vec<(usize, u32, usize)>,
}

impl CodeBuilder {
    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn disp(&mut self, target: u32) {
        self.disp_with_trailing(target, 0);
    }

    fn disp_with_trailing(&mut self, target: u32, trailing: usize) {
        let offset = self.bytes.len();
        self.bytes.extend_from_slice(&[0_u8; 4]);
        self.fixups.push((offset, target, trailing));
    }

    fn disp_imm32(&mut self, target: u32, immediate: u32) {
        self.disp_with_trailing(target, 4);
        self.raw(&immediate.to_le_bytes());
    }

    fn call_iat(&mut self, target: u32) {
        self.raw(&[0xFF, 0x15]);
        self.disp(target);
    }

    fn inc_dword(&mut self, target: u32) {
        self.raw(&[0xFF, 0x05]);
        self.disp(target);
    }

    fn finish(&mut self, rva: u32) -> Vec<u8> {
        for (offset, target, trailing) in self.fixups.drain(..) {
            let end = rva as i64 + offset as i64 + 4 + trailing as i64;
            let displacement = target as i64 - end;
            self.bytes[offset..offset + 4].copy_from_slice(&(displacement as i32).to_le_bytes());
        }
        self.bytes.clone()
    }
}

fn build_test_driver(
    entry_failure: bool,
    unresolved_import: bool,
    exercise_services: bool,
) -> Vec<u8> {
    let mut file = vec![0_u8; 0xC00];
    file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    file[0x3C..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    file[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    file[coff + 2..coff + 4].copy_from_slice(&3_u16.to_le_bytes());
    file[coff + 16..coff + 18].copy_from_slice(&0xF0_u16.to_le_bytes());
    file[coff + 18..coff + 20].copy_from_slice(&0x0022_u16.to_le_bytes());
    let optional = coff + 20;
    file[optional..optional + 2].copy_from_slice(&0x020B_u16.to_le_bytes());
    file[optional + 4..optional + 8].copy_from_slice(&0x200_u32.to_le_bytes());
    file[optional + 8..optional + 12].copy_from_slice(&0x800_u32.to_le_bytes());
    file[optional + 16..optional + 20].copy_from_slice(&TEXT_RVA.to_le_bytes());
    file[optional + 20..optional + 24].copy_from_slice(&TEXT_RVA.to_le_bytes());
    file[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    file[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    file[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
    file[optional + 48..optional + 50].copy_from_slice(&6_u16.to_le_bytes());
    file[optional + 56..optional + 60].copy_from_slice(&0x4000_u32.to_le_bytes());
    file[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    file[optional + 68..optional + 70].copy_from_slice(&1_u16.to_le_bytes());
    let directory_count = optional + 108;
    file[directory_count..directory_count + 4].copy_from_slice(&16_u32.to_le_bytes());
    let directories = optional + 112;
    file[directories..directories + 4].copy_from_slice(&EXPORT_RVA.to_le_bytes());
    file[directories + 4..directories + 8].copy_from_slice(&0x100_u32.to_le_bytes());
    let import_directory = directories + 8;
    file[import_directory..import_directory + 4].copy_from_slice(&IMPORT_RVA.to_le_bytes());
    file[import_directory + 4..import_directory + 8].copy_from_slice(&0x28_u32.to_le_bytes());

    let section_table = optional + 0xF0;
    let mut write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32| {
        let entry = section_table + index * 40;
        file[entry..entry + 8].copy_from_slice(name);
        file[entry + 8..entry + 12].copy_from_slice(&virtual_size.to_le_bytes());
        file[entry + 12..entry + 16].copy_from_slice(&rva.to_le_bytes());
        file[entry + 16..entry + 20].copy_from_slice(&raw_size.to_le_bytes());
        file[entry + 20..entry + 24].copy_from_slice(&raw.to_le_bytes());
        file[entry + 36..entry + 40].copy_from_slice(&characteristics.to_le_bytes());
    };
    write_section(
        0,
        b".text\0\0\0",
        0x200,
        TEXT_RVA,
        0x200,
        0x200,
        0x6000_0020,
    );
    write_section(
        1,
        b".rdata\0\0",
        0x600,
        RDATA_RVA,
        0x600,
        0x400,
        0x4000_0040,
    );
    write_section(2, b".data\0\0\0", 0x200, 0x3000, 0x200, 0xA00, 0xC000_0040);

    let entry = if entry_failure {
        let mut code = CodeBuilder::default();
        code.raw(&[0xC7, 0x05]);
        code.disp_imm32(ENTRY_MARKER_RVA, 0xCA5A_0001);
        code.raw(&[0xB8]);
        code.raw(&(STATUS_UNSUCCESSFUL as u32).to_le_bytes());
        code.raw(&[0xC3]);
        code.finish(TEXT_RVA)
    } else {
        let mut code = CodeBuilder::default();
        code.raw(&[0xC7, 0x05]);
        code.disp_imm32(ENTRY_MARKER_RVA, 0xCA5A_0001);
        code.raw(&[0x48, 0x89, 0x0D]);
        code.disp(DRIVER_PTR_RVA);
        code.raw(&[0x48, 0x8D, 0x0D]);
        code.disp(DBG_FMT_RVA);
        code.raw(&[0x31, 0xC0]);
        code.call_iat(IAT_DBG);
        code.raw(&[0x48, 0x8D, 0x0D]);
        code.disp(US_DEV_RVA);
        code.raw(&[0x48, 0x8D, 0x15]);
        code.disp(WIDE_DEV_RVA);
        code.call_iat(IAT_RTL);
        code.raw(&[0x48, 0x8D, 0x0D]);
        code.disp(US_LINK_RVA);
        code.raw(&[0x48, 0x8D, 0x15]);
        code.disp(WIDE_LINK_RVA);
        code.call_iat(IAT_RTL);
        code.raw(&[0x48, 0x83, 0xEC, 0x38]);
        code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
        code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
        code.raw(&[0x48, 0x8D, 0x05]);
        code.disp(DEV_OBJ_OUT_RVA);
        code.raw(&[0x48, 0x89, 0x44, 0x24, 0x30]);
        code.raw(&[0x48, 0x8B, 0x0D]);
        code.disp(DRIVER_PTR_RVA);
        code.raw(&[0x31, 0xD2]);
        code.raw(&[0x4C, 0x8D, 0x05]);
        code.disp(US_DEV_RVA);
        code.raw(&[0x41, 0xB9]);
        code.raw(&0x22_u32.to_le_bytes());
        code.call_iat(IAT_IO_CREATE);
        code.raw(&[0x48, 0x83, 0xC4, 0x38]);
        code.raw(&[0x85, 0xC0]);
        code.raw(&[0x79, 0x06]);
        code.raw(&[0xB8]);
        code.raw(&(STATUS_UNSUCCESSFUL as u32).to_le_bytes());
        code.raw(&[0xC3]);
        code.raw(&[0x48, 0x8D, 0x0D]);
        code.disp(US_LINK_RVA);
        code.raw(&[0x48, 0x8D, 0x15]);
        code.disp(US_DEV_RVA);
        code.call_iat(IAT_IO_SYMLINK);
        if exercise_services {
            code.raw(&[0xB9, 0x01, 0, 0, 0]);
            code.raw(&[0x31, 0xD2]);
            code.call_iat(IAT_IO_ALLOC_IRP);
            code.raw(&[0x48, 0x89, 0xC1]);
            code.raw(&[0x31, 0xD2]);
            code.call_iat(IAT_IOF_COMPLETE);
            code.raw(&[0x31, 0xC9]);
            code.raw(&[0xBA, 0x40, 0, 0, 0]);
            code.raw(&[0x41, 0xB8, 0x54, 0x73, 0x74, 0x31]);
            code.call_iat(IAT_EX_ALLOC);
            code.raw(&[0x48, 0x89, 0xC1]);
            code.raw(&[0xBA, 0x54, 0x73, 0x74, 0x31]);
            code.call_iat(IAT_EX_FREE);
            code.raw(&[0x31, 0xC0]);
        }
        code.raw(&[0xC3]);
        code.finish(TEXT_RVA)
    };
    assert!(entry.len() <= 0x100);

    let mut unload = CodeBuilder::default();
    unload.raw(&[0x31, 0xC0]);
    unload.raw(&[0x48, 0x8D, 0x0D]);
    unload.disp(DBG_UNLOAD_RVA);
    unload.call_iat(IAT_DBG);
    unload.raw(&[0xC7, 0x05]);
    unload.disp_imm32(UNLOAD_MARKER_RVA, 0xCA5A_0002);
    unload.raw(&[0x48, 0x8B, 0x0D]);
    unload.disp(DEV_OBJ_OUT_RVA);
    unload.raw(&[0x48, 0x85, 0xC9]);
    unload.raw(&[0x74, 0x06]);
    unload.call_iat(IAT_IO_DELETE);
    unload.raw(&[0xC3]);
    let unload = unload.finish(UNLOAD_RVA);
    assert!(unload.len() <= 0x100);

    file[0x200..0x200 + entry.len()].copy_from_slice(&entry);
    file[0x300..0x300 + unload.len()].copy_from_slice(&unload);

    let mut rdata = vec![0_u8; 0x600];
    let rva = |address: u32| (address - RDATA_RVA) as usize;
    let descriptor = rva(IMPORT_RVA);
    rdata[descriptor..descriptor + 4].copy_from_slice(&ILT_RVA.to_le_bytes());
    rdata[descriptor + 12..descriptor + 16].copy_from_slice(&DLL_NAME_RVA.to_le_bytes());
    rdata[descriptor + 16..descriptor + 20].copy_from_slice(&IAT_RVA.to_le_bytes());
    for (index, (_, hint)) in IMPORT_NAMES.iter().enumerate() {
        rdata[rva(ILT_RVA) + index * 8..rva(ILT_RVA) + index * 8 + 8]
            .copy_from_slice(&(*hint as u64).to_le_bytes());
        rdata[rva(IAT_RVA) + index * 8..rva(IAT_RVA) + index * 8 + 8]
            .copy_from_slice(&(*hint as u64).to_le_bytes());
    }
    rdata[rva(DLL_NAME_RVA)..rva(DLL_NAME_RVA) + 13].copy_from_slice(b"ntoskrnl.exe\0");
    for (index, (name, hint)) in IMPORT_NAMES.iter().enumerate() {
        let symbol = if unresolved_import && index == IMPORT_NAMES.len() - 1 {
            "PsGetCurrentProcess"
        } else {
            name
        };
        let offset = rva(*hint);
        rdata[offset..offset + 2].copy_from_slice(&0_u16.to_le_bytes());
        rdata[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
        rdata[offset + 2 + symbol.len()] = 0;
    }
    rdata[rva(DBG_FMT_RVA)..rva(DBG_FMT_RVA) + 22].copy_from_slice(b"CasaTest DriverEntry\n\0");
    write_wide(&mut rdata, rva(WIDE_DEV_RVA), "\\Device\\CasaTest");
    write_wide(&mut rdata, rva(WIDE_LINK_RVA), "\\??\\CasaTest");
    rdata[rva(DBG_UNLOAD_RVA)..rva(DBG_UNLOAD_RVA) + 23]
        .copy_from_slice(b"CasaTest DriverUnload\n\0");

    let export = rva(EXPORT_RVA);
    let export_name = 0x24F0_u32;
    let functions = 0x24B0_u32;
    let names = 0x24B8_u32;
    let ordinals = 0x24C0_u32;
    rdata[export + 12..export + 16].copy_from_slice(&export_name.to_le_bytes());
    rdata[export + 16..export + 20].copy_from_slice(&1_u32.to_le_bytes());
    rdata[export + 20..export + 24].copy_from_slice(&2_u32.to_le_bytes());
    rdata[export + 24..export + 28].copy_from_slice(&2_u32.to_le_bytes());
    rdata[export + 28..export + 32].copy_from_slice(&functions.to_le_bytes());
    rdata[export + 32..export + 36].copy_from_slice(&names.to_le_bytes());
    rdata[export + 36..export + 40].copy_from_slice(&ordinals.to_le_bytes());
    rdata[rva(functions)..rva(functions) + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
    rdata[rva(functions) + 4..rva(functions) + 8].copy_from_slice(&UNLOAD_RVA.to_le_bytes());
    rdata[rva(names)..rva(names) + 4].copy_from_slice(&0x24D0_u32.to_le_bytes());
    rdata[rva(names) + 4..rva(names) + 8].copy_from_slice(&0x24E0_u32.to_le_bytes());
    rdata[rva(ordinals)..rva(ordinals) + 2].copy_from_slice(&0_u16.to_le_bytes());
    rdata[rva(ordinals) + 2..rva(ordinals) + 4].copy_from_slice(&1_u16.to_le_bytes());
    rdata[rva(0x24D0)..rva(0x24D0) + 12].copy_from_slice(b"DriverEntry\0");
    rdata[rva(0x24E0)..rva(0x24E0) + 13].copy_from_slice(b"DriverUnload\0");
    rdata[rva(export_name)..rva(export_name) + 13].copy_from_slice(b"CasaTest.sys\0");
    file[0x400..0xA00].copy_from_slice(&rdata);
    file
}

fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(image: &mut [u8], offset: usize, value: u64) {
    image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn build_pe32_driver() -> Vec<u8> {
    const TEXT_RVA: u32 = 0x1000;
    const RDATA_RVA: u32 = 0x2000;
    const DATA_RVA: u32 = 0x3000;
    const HANDLER_RVA: u32 = 0x1200;
    const US_DEV_RVA: u32 = 0x3000;
    const DEV_OUT_RVA: u32 = 0x3010;
    const MARKER_RVA: u32 = 0x3014;
    const DRIVER_PTR_RVA: u32 = 0x3018;
    const IMAGE_BASE: u32 = 0x1000_0000;

    let mut file = vec![0_u8; 0xC00];
    file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    put_u32(&mut file, 0x3C, 0x80);
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(&mut file, coff, 0x014C);
    put_u16(&mut file, coff + 2, 3);
    put_u16(&mut file, coff + 16, 0xE0);
    put_u16(&mut file, coff + 18, 0x0102);
    let optional = coff + 20;
    put_u16(&mut file, optional, 0x010B);
    put_u32(&mut file, optional + 4, 0x400);
    put_u32(&mut file, optional + 8, 0x400);
    put_u32(&mut file, optional + 16, TEXT_RVA);
    put_u32(&mut file, optional + 20, TEXT_RVA);
    put_u32(&mut file, optional + 24, RDATA_RVA);
    put_u32(&mut file, optional + 28, 0x1000_0000);
    put_u32(&mut file, optional + 32, 0x1000);
    put_u32(&mut file, optional + 36, 0x200);
    put_u16(&mut file, optional + 48, 6);
    put_u32(&mut file, optional + 56, 0x4000);
    put_u32(&mut file, optional + 60, 0x200);
    put_u16(&mut file, optional + 68, 1);
    put_u32(&mut file, optional + 92, 16);
    let directories = optional + 96;
    put_u32(&mut file, directories + 8, 0x2100);
    put_u32(&mut file, directories + 12, 0x28);

    let section_table = optional + 0xE0;
    let mut write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32| {
        let entry = section_table + index * 40;
        file[entry..entry + 8].copy_from_slice(name);
        put_u32(&mut file, entry + 8, virtual_size);
        put_u32(&mut file, entry + 12, rva);
        put_u32(&mut file, entry + 16, raw_size);
        put_u32(&mut file, entry + 20, raw);
        put_u32(&mut file, entry + 36, characteristics);
    };
    write_section(
        0,
        b".text\0\0\0",
        0x400,
        TEXT_RVA,
        0x400,
        0x200,
        0x6000_0020,
    );
    write_section(
        1,
        b".rdata\0\0",
        0x400,
        RDATA_RVA,
        0x400,
        0x600,
        0x4000_0040,
    );
    write_section(
        2,
        b".data\0\0\0",
        0x200,
        DATA_RVA,
        0x200,
        0xA00,
        0xC000_0040,
    );

    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]); // mov eax,[esp+4]
    entry.extend_from_slice(&[0xA3]);
    entry.extend_from_slice(&(IMAGE_BASE + DRIVER_PTR_RVA).to_le_bytes());
    entry.extend_from_slice(&[0xB9]);
    entry.extend_from_slice(&(0x1000_0000u32 + HANDLER_RVA).to_le_bytes());
    for major in [14u32, 3, 4] {
        entry.extend_from_slice(&[0x89, 0x88]);
        entry.extend_from_slice(&(0x38 + major * 4).to_le_bytes());
    }
    entry.extend_from_slice(&[0xC7, 0x05]);
    entry.extend_from_slice(&(IMAGE_BASE + MARKER_RVA).to_le_bytes());
    entry.extend_from_slice(&0xCA5A_0005u32.to_le_bytes());
    entry.extend_from_slice(&[0x68]);
    entry.extend_from_slice(&(IMAGE_BASE + DEV_OUT_RVA).to_le_bytes());
    entry.extend_from_slice(&[0x6A, 0x00, 0x6A, 0x00]);
    entry.extend_from_slice(&[0x68, 0x22, 0, 0, 0]);
    entry.extend_from_slice(&[0x68]);
    entry.extend_from_slice(&(IMAGE_BASE + US_DEV_RVA).to_le_bytes());
    entry.extend_from_slice(&[0x6A, 0x00]);
    entry.extend_from_slice(&[0xFF, 0x35]);
    entry.extend_from_slice(&(IMAGE_BASE + DRIVER_PTR_RVA).to_le_bytes());
    entry.extend_from_slice(&[0xFF, 0x15]);
    entry.extend_from_slice(&(IMAGE_BASE + 0x2160).to_le_bytes());
    entry.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
    assert!(entry.len() <= 0x100);
    file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

    let mut handler = Vec::new();
    handler.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]); // mov eax,[esp+4]
    handler.extend_from_slice(&[0xC7, 0x40, 0x18, 0, 0, 0, 0]);
    handler.extend_from_slice(&[0xC7, 0x40, 0x20, 4, 0, 0, 0]);
    handler.extend_from_slice(&[0x8B, 0x48, 0x0C]); // mov ecx,[eax+0xC]
    handler.extend_from_slice(&[0xC7, 0x01]);
    handler.extend_from_slice(b"RESP");
    handler.extend_from_slice(&[0xC7, 0x05]);
    handler.extend_from_slice(&(IMAGE_BASE + MARKER_RVA).to_le_bytes());
    handler.extend_from_slice(&0xCA5A_0006u32.to_le_bytes());
    handler.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
    file[0x400..0x400 + handler.len()].copy_from_slice(&handler);

    let mut unload = vec![0x8B, 0x44, 0x24, 0x04];
    unload.extend_from_slice(&[0xFF, 0x35]);
    unload.extend_from_slice(&(IMAGE_BASE + DEV_OUT_RVA).to_le_bytes());
    unload.extend_from_slice(&[0xFF, 0x15]);
    unload.extend_from_slice(&(IMAGE_BASE + 0x2164).to_le_bytes());
    unload.extend_from_slice(&[0xC2, 0x04, 0x00]);
    file[0x480..0x480 + unload.len()].copy_from_slice(&unload);

    let rva = |address: u32| (address - RDATA_RVA) as usize;
    let descriptor = rva(0x2100);
    put_u32(&mut file, 0x600 + descriptor, 0x2140);
    put_u32(&mut file, 0x600 + descriptor + 12, 0x2180);
    put_u32(&mut file, 0x600 + descriptor + 16, 0x2160);
    for (index, hint) in [0x21A0u32, 0x21B0].iter().enumerate() {
        put_u32(&mut file, 0x600 + rva(0x2140) + index * 4, *hint);
        put_u32(&mut file, 0x600 + rva(0x2160) + index * 4, *hint);
    }
    file[0x600 + rva(0x2180)..0x600 + rva(0x2180) + 13].copy_from_slice(b"ntoskrnl.exe\0");
    for (name, hint) in [("IoCreateDevice", 0x21A0u32), ("IoDeleteDevice", 0x21B0)] {
        let offset = 0x600 + rva(hint);
        put_u16(&mut file, offset, 0);
        file[offset + 2..offset + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    write_wide(&mut file[0x600..0xA00], rva(0x2200), "\\Device\\Casa32");
    let data = 0xA00;
    put_u16(&mut file, data, 28);
    put_u16(&mut file, data + 2, 30);
    put_u32(&mut file, data + 4, IMAGE_BASE + 0x2200);
    put_u32(&mut file, data + 0x10, 0);
    put_u32(&mut file, data + 0x14, 0);
    put_u32(&mut file, data + 0x18, 0);
    file
}

fn with_delay_import(mut image: Vec<u8>, symbol: &str) -> Vec<u8> {
    let directories = 0x98 + 112;
    put_u32(&mut image, directories + 13 * 8, 0x2500);
    put_u32(&mut image, directories + 13 * 8 + 4, 0x20);
    let rva = |address: u32| 0x400 + (address - 0x2000) as usize;
    let descriptor = rva(0x2500);
    put_u32(&mut image, descriptor, 1); // attributes: RVAs
    put_u32(&mut image, descriptor + 4, 0x2540); // name
    put_u32(&mut image, descriptor + 12, 0x2570); // IAT
    put_u32(&mut image, descriptor + 16, 0x2560); // INT
    put_u32(&mut image, descriptor + 28, 0); // timestamp
    image[rva(0x2540)..rva(0x2540) + 13].copy_from_slice(b"ntoskrnl.exe\0");
    put_u64(&mut image, rva(0x2560), 0x2580);
    put_u64(&mut image, rva(0x2570), 0);
    let name = rva(0x2580);
    put_u16(&mut image, name, 0);
    image[name + 2..name + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
    image[name + 2 + symbol.len()] = 0;
    image
}

fn build_io_driver() -> Vec<u8> {
    const IO_HANDLER_RVA: u32 = 0x3100;
    const IO_MARKER_RVA: u32 = 0x3140;
    let mut file = build_test_driver(false, false, false);
    let mut code = CodeBuilder::default();
    code.raw(&[0x48, 0x8D, 0x05]);
    code.disp(IO_HANDLER_RVA);
    for major in [14u32, 3, 4] {
        code.raw(&[0x48, 0x89, 0x81]);
        code.raw(&((0x70 + major * 8) as u32).to_le_bytes());
    }
    code.raw(&[0x48, 0x89, 0x0D]);
    code.disp(DRIVER_PTR_RVA);
    code.raw(&[0x48, 0x83, 0xEC, 0x38]);
    code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
    code.raw(&[0x48, 0x8D, 0x05]);
    code.disp(DEV_OBJ_OUT_RVA);
    code.raw(&[0x48, 0x89, 0x44, 0x24, 0x30]);
    code.raw(&[0x48, 0x8B, 0x0D]);
    code.disp(DRIVER_PTR_RVA);
    code.raw(&[0x31, 0xD2]);
    code.raw(&[0x4C, 0x8D, 0x05]);
    code.disp(US_DEV_RVA);
    code.raw(&[0x41, 0xB9]);
    code.raw(&0x22_u32.to_le_bytes());
    code.call_iat(IAT_IO_CREATE);
    code.raw(&[0x48, 0x83, 0xC4, 0x38]);
    code.raw(&[0x31, 0xC0, 0xC3]);
    let entry = code.finish(TEXT_RVA);
    assert!(entry.len() <= 0x100);
    file[0x200..0x300].fill(0);
    file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

    let mut handler = CodeBuilder::default();
    handler.raw(&[0xC7, 0x41, 0x30, 0, 0, 0, 0]);
    handler.raw(&[0x48, 0xC7, 0x41, 0x40, 4, 0, 0, 0]);
    handler.raw(&[0x48, 0x8B, 0x41, 0x18]);
    handler.raw(&[0xC7, 0x00]);
    handler.raw(b"RESP");
    handler.raw(&[0xC7, 0x05]);
    handler.disp_imm32(IO_MARKER_RVA, 0xCA5A_0004);
    handler.raw(&[0x31, 0xC0, 0xC3]);
    let handler = handler.finish(IO_HANDLER_RVA);
    let offset = 0xA00 + (IO_HANDLER_RVA - 0x3000) as usize;
    file[offset..offset + handler.len()].copy_from_slice(&handler);
    put_u32(&mut file, 0xA00 + (IO_MARKER_RVA - 0x3000) as usize, 0);
    let device_name = 0xA00 + (US_DEV_RVA - 0x3000) as usize;
    put_u16(&mut file, device_name, 32);
    put_u16(&mut file, device_name + 2, 34);
    put_u64(
        &mut file,
        device_name + 8,
        0x1_4000_0000 + u64::from(WIDE_DEV_RVA),
    );
    file
}

const K_TEXT_RVA: u32 = 0x1000;
const K_ENTRY_RVA: u32 = 0x1000;
const K_EVT_ADD_RVA: u32 = 0x1100;
const K_EVT_IOCTL_RVA: u32 = 0x1300;
const K_RDATA_RVA: u32 = 0x2000;
const K_DATA_RVA: u32 = 0x3000;
const K_IMPORT_RVA: u32 = 0x2100;
const K_ILT_RVA: u32 = 0x2140;
const K_IAT_RVA: u32 = 0x21D0;
const K_DLL_RVA: u32 = 0x2260;
const K_HINT_RVA: u32 = 0x2280;
const K_US_DEV_RVA: u32 = 0x3010;
const K_WIDE_DEV_RVA: u32 = 0x3030;
const K_CONFIG_RVA: u32 = 0x3050;
const K_DRIVER_OUT_RVA: u32 = 0x3080;
const K_DEVICE_OUT_RVA: u32 = 0x3088;
const K_QUEUE_OUT_RVA: u32 = 0x3090;
const K_REQUEST_OUT_RVA: u32 = 0x3098;
const K_LOCK_OUT_RVA: u32 = 0x30A0;
const K_INIT_TMP_RVA: u32 = 0x30A8;
const K_DEVOBJ_OUT_RVA: u32 = 0x30B0;
const K_OUTBUF_PTR_RVA: u32 = 0x30B8;
const K_OUTBUF_LEN_RVA: u32 = 0x30C0;
const K_MARKER_RVA: u32 = 0x30C8;
const K_IOCTL_MARKER_RVA: u32 = 0x30CC;
const K_DELETE_MARKER_RVA: u32 = 0x30D0;
const K_QCONFIG_RVA: u32 = 0x3100;
const K_IMAGE_BASE: u64 = 0x1_4000_0000;

const KMDF_IMPORTS: [&str; 17] = [
    "WdfDriverCreate",
    "WdfDeviceInitSetDeviceType",
    "WdfDeviceInitSetIoType",
    "WdfDeviceInitAssignName",
    "WdfDeviceCreate",
    "WdfIoQueueCreate",
    "WdfRequestCreate",
    "WdfRequestFormatRequestForIoctl",
    "WdfRequestRetrieveOutputBuffer",
    "WdfRequestCompleteWithInformation",
    "WdfDeviceWdmGetDeviceObject",
    "WdfObjectGetTypedContext",
    "WdfObjectDelete",
    "WdfWaitLockCreate",
    "WdfWaitLockAcquire",
    "WdfWaitLockRelease",
    "WdfRequestRetrieveInputBuffer",
];

fn build_kmdf_driver(with_queue: bool, missing_symbol: bool, bad_callback: bool) -> Vec<u8> {
    let mut file = vec![0_u8; 0x1000];
    file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    put_u32(&mut file, 0x3C, 0x80);
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(&mut file, coff, 0x8664);
    put_u16(&mut file, coff + 2, 3);
    put_u16(&mut file, coff + 16, 0xF0);
    put_u16(&mut file, coff + 18, 0x0022);
    let optional = coff + 20;
    put_u16(&mut file, optional, 0x020B);
    put_u32(&mut file, optional + 4, 0x400);
    put_u32(&mut file, optional + 8, 0xC00);
    put_u32(&mut file, optional + 16, K_ENTRY_RVA);
    put_u32(&mut file, optional + 20, K_TEXT_RVA);
    put_u64(&mut file, optional + 24, K_IMAGE_BASE);
    put_u32(&mut file, optional + 32, 0x1000);
    put_u32(&mut file, optional + 36, 0x200);
    put_u16(&mut file, optional + 48, 6);
    put_u32(&mut file, optional + 56, 0x4000);
    put_u32(&mut file, optional + 60, 0x200);
    put_u16(&mut file, optional + 68, 1);
    put_u32(&mut file, optional + 108, 16);
    let directories = optional + 112;
    // No exports; one import descriptor (the terminator stays zero).
    put_u32(&mut file, directories + 8, K_IMPORT_RVA);
    put_u32(&mut file, directories + 12, 0x28);

    let section_table = optional + 0xF0;
    let mut write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32| {
        let entry = section_table + index * 40;
        file[entry..entry + 8].copy_from_slice(name);
        put_u32(&mut file, entry + 8, virtual_size);
        put_u32(&mut file, entry + 12, rva);
        put_u32(&mut file, entry + 16, raw_size);
        put_u32(&mut file, entry + 20, raw);
        put_u32(&mut file, entry + 36, characteristics);
    };
    write_section(
        0,
        b".text\0\0\0",
        0x400,
        K_TEXT_RVA,
        0x400,
        0x200,
        0x6000_0020,
    );
    write_section(
        1,
        b".rdata\0\0",
        0x600,
        K_RDATA_RVA,
        0x600,
        0x600,
        0x4000_0040,
    );
    write_section(
        2,
        b".data\0\0\0",
        0x400,
        K_DATA_RVA,
        0x400,
        0xC00,
        0xC000_0040,
    );

    let mut entry = CodeBuilder::default();
    entry.raw(&[0x49, 0x89, 0xD3]); // mov r11,rdx (RegistryPath)
    entry.raw(&[0x48, 0x8D, 0x05]);
    entry.disp(K_CONFIG_RVA);
    entry.raw(&[0xC7, 0x00]);
    entry.raw(&0x28_u32.to_le_bytes());
    if bad_callback {
        entry.raw(&[0xBA]);
        entry.raw(&0xDEAD_0000_u32.to_le_bytes());
    } else {
        entry.raw(&[0x48, 0x8D, 0x15]);
        entry.disp(K_EVT_ADD_RVA);
    }
    entry.raw(&[0x48, 0x89, 0x50, 0x08]); // config.EvtDriverDeviceAdd
    entry.raw(&[0x4C, 0x89, 0xDA]); // mov rdx,r11
    entry.raw(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
    entry.raw(&[0x4C, 0x8D, 0x0D]);
    entry.disp(K_CONFIG_RVA);
    entry.raw(&[0x48, 0x83, 0xEC, 0x28]);
    entry.raw(&[0x4C, 0x8D, 0x15]);
    entry.disp(K_DRIVER_OUT_RVA);
    entry.raw(&[0x4C, 0x89, 0x54, 0x24, 0x20]);
    entry.call_iat(K_IAT_RVA);
    entry.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let entry = entry.finish(K_ENTRY_RVA);
    assert!(entry.len() <= 0x100);
    file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

    let mut add = CodeBuilder::default();
    add.raw(&[0x48, 0x89, 0x15]);
    add.disp(K_INIT_TMP_RVA);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_INIT_TMP_RVA);
    add.raw(&[0xBA, 0x22, 0, 0, 0]);
    add.call_iat(K_IAT_RVA + 8);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_INIT_TMP_RVA);
    add.raw(&[0xBA, 1, 0, 0, 0]);
    add.call_iat(K_IAT_RVA + 16);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_INIT_TMP_RVA);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(K_US_DEV_RVA);
    add.call_iat(K_IAT_RVA + 24);
    add.raw(&[0x48, 0x8D, 0x0D]);
    add.disp(K_INIT_TMP_RVA);
    add.raw(&[0x31, 0xD2]);
    add.raw(&[0x4C, 0x8D, 0x05]);
    add.disp(K_DEVICE_OUT_RVA);
    add.call_iat(K_IAT_RVA + 32);
    add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
    if with_queue {
        add.raw(&[0x48, 0x8D, 0x05]);
        add.disp(K_QCONFIG_RVA);
        add.raw(&[0xC7, 0x00]);
        add.raw(&0x40_u32.to_le_bytes());
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(K_EVT_IOCTL_RVA);
        add.raw(&[0x48, 0x89, 0x50, 0x28]);
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(K_DEVICE_OUT_RVA);
        add.raw(&[0x48, 0x89, 0xC2]);
        add.raw(&[0x45, 0x31, 0xC0]);
        add.raw(&[0x4C, 0x8D, 0x0D]);
        add.disp(K_QUEUE_OUT_RVA);
        add.call_iat(K_IAT_RVA + 40);
        add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
    }
    // Exercise WdfRequestCreate + WdfRequestFormatRequestForIoctl.
    add.raw(&[0x31, 0xC9, 0x31, 0xD2]);
    add.raw(&[0x4C, 0x8D, 0x05]);
    add.disp(K_REQUEST_OUT_RVA);
    add.call_iat(K_IAT_RVA + 48);
    add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
    add.raw(&[0x48, 0x83, 0xEC, 0x48]);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_REQUEST_OUT_RVA);
    add.raw(&[0x31, 0xD2]);
    add.raw(&[0x41, 0xB8]);
    add.raw(&0x0022_0004_u32.to_le_bytes());
    add.raw(&[0x45, 0x31, 0xC9]);
    for displacement in [0x20_u8, 0x28, 0x30, 0x38] {
        add.raw(&[0x48, 0xC7, 0x44, 0x24, displacement, 0, 0, 0, 0]);
    }
    add.call_iat(K_IAT_RVA + 56);
    add.raw(&[0x48, 0x83, 0xC4, 0x48]);
    // WdfObjectDelete removes the request (and its CasaK IRP).
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_REQUEST_OUT_RVA);
    add.call_iat(K_IAT_RVA + 96);
    add.raw(&[0xC7, 0x05]);
    add.disp_imm32(K_DELETE_MARKER_RVA, 0xCA5A_0012);
    // Typed device context.
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_DEVICE_OUT_RVA);
    add.raw(&[0xBA, 1, 0, 0, 0]);
    add.call_iat(K_IAT_RVA + 88);
    add.raw(&[0x48, 0x85, 0xC0, 0x74, 0x06]);
    add.raw(&[0xC7, 0x00, 0xDE, 0xC0, 0, 0]);
    // WdfDeviceWdmGetDeviceObject.
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_DEVICE_OUT_RVA);
    add.call_iat(K_IAT_RVA + 80);
    add.raw(&[0x48, 0x89, 0x05]);
    add.disp(K_DEVOBJ_OUT_RVA);
    // Wait lock create/acquire/release.
    add.raw(&[0x31, 0xC9]);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(K_LOCK_OUT_RVA);
    add.call_iat(K_IAT_RVA + 104);
    add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_LOCK_OUT_RVA);
    add.raw(&[0x31, 0xD2]);
    add.call_iat(K_IAT_RVA + 112);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(K_LOCK_OUT_RVA);
    add.call_iat(K_IAT_RVA + 120);
    add.raw(&[0xC7, 0x05]);
    add.disp_imm32(K_MARKER_RVA, 0xCA5A_0010);
    add.raw(&[0x31, 0xC0, 0xC3]);
    let add = add.finish(K_EVT_ADD_RVA);
    assert!(
        add.len() <= 0x200,
        "device-add callback is {} bytes",
        add.len()
    );
    let add_offset = 0x200 + (K_EVT_ADD_RVA - K_TEXT_RVA) as usize;
    file[add_offset..add_offset + add.len()].copy_from_slice(&add);

    let mut ioctl = CodeBuilder::default();
    ioctl.raw(&[0x44, 0x8B, 0x54, 0x24, 0x28]); // ioctl code
    ioctl.raw(&[0x49, 0x89, 0xD3]); // request
    ioctl.raw(&[0x48, 0x83, 0xEC, 0x28]);
    ioctl.raw(&[0x4C, 0x89, 0xD9]);
    ioctl.raw(&[0xBA, 4, 0, 0, 0]);
    ioctl.raw(&[0x4C, 0x8D, 0x05]);
    ioctl.disp(K_OUTBUF_PTR_RVA);
    ioctl.raw(&[0x4C, 0x8D, 0x0D]);
    ioctl.disp(K_OUTBUF_LEN_RVA);
    ioctl.call_iat(K_IAT_RVA + 64);
    ioctl.raw(&[0x85, 0xC0]);
    ioctl.raw(&[0x0F, 0x88]);
    ioctl.disp(K_EVT_IOCTL_RVA + 0x60);
    ioctl.raw(&[0x48, 0x8B, 0x05]);
    ioctl.disp(K_OUTBUF_PTR_RVA);
    ioctl.raw(&[0x48, 0x85, 0xC0]);
    ioctl.raw(&[0x0F, 0x84]);
    ioctl.disp(K_EVT_IOCTL_RVA + 0x60);
    ioctl.raw(&[0xC7, 0x00]);
    ioctl.raw(&0x2146_4457_u32.to_le_bytes()); // "WDF!"
    ioctl.raw(&[0x44, 0x89, 0x15]);
    ioctl.disp(K_IOCTL_MARKER_RVA);
    ioctl.raw(&[0x4C, 0x89, 0xD9]);
    ioctl.raw(&[0x31, 0xD2]);
    ioctl.raw(&[0x41, 0xB8]);
    ioctl.raw(&4_u32.to_le_bytes());
    ioctl.call_iat(K_IAT_RVA + 72);
    if ioctl.bytes.len() > 0x60 {
        panic!("ioctl callback body is {} bytes", ioctl.bytes.len());
    }
    ioctl.raw(&vec![0x90; 0x60 - ioctl.bytes.len()]);
    ioctl.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let ioctl = ioctl.finish(K_EVT_IOCTL_RVA);
    assert!(ioctl.len() <= 0x200);
    let ioctl_offset = 0x200 + (K_EVT_IOCTL_RVA - K_TEXT_RVA) as usize;
    file[ioctl_offset..ioctl_offset + ioctl.len()].copy_from_slice(&ioctl);

    let data_rva = |address: u32| 0xC00 + (address - K_DATA_RVA) as usize;
    let config = data_rva(K_CONFIG_RVA);
    put_u32(&mut file, config, 0x28);
    let us = data_rva(K_US_DEV_RVA);
    put_u16(&mut file, us, 30);
    put_u16(&mut file, us + 2, 32);
    put_u64(&mut file, us + 8, K_IMAGE_BASE + u64::from(K_WIDE_DEV_RVA));
    write_wide(
        &mut file[0xC00..0x1000],
        (K_WIDE_DEV_RVA - K_DATA_RVA) as usize,
        "\\Device\\WdfCasa",
    );
    put_u32(&mut file, data_rva(K_QCONFIG_RVA), 0x40);

    let rva = |address: u32| 0x600 + (address - K_RDATA_RVA) as usize;
    let descriptor = rva(K_IMPORT_RVA);
    put_u32(&mut file, descriptor, K_ILT_RVA);
    put_u32(&mut file, descriptor + 12, K_DLL_RVA);
    put_u32(&mut file, descriptor + 16, K_IAT_RVA);
    file[rva(K_DLL_RVA)..rva(K_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
    file[rva(K_DLL_RVA) + 10] = 0;
    let mut hint_rva = K_HINT_RVA;
    for (index, symbol) in KMDF_IMPORTS.iter().enumerate() {
        put_u64(&mut file, rva(K_ILT_RVA) + index * 8, u64::from(hint_rva));
        put_u64(&mut file, rva(K_IAT_RVA) + index * 8, u64::from(hint_rva));
        let name = if missing_symbol && index == 0 {
            "WdfDriverCreatX"
        } else {
            symbol
        };
        let offset = rva(hint_rva);
        put_u16(&mut file, offset, 0);
        file[offset + 2..offset + 2 + name.len()].copy_from_slice(name.as_bytes());
        file[offset + 2 + name.len()] = 0;
        hint_rva += (2 + name.len() + 1 + 1) as u32 & !1;
    }
    assert!(
        hint_rva <= 0x2500,
        "hint/name table overruns rdata: {hint_rva:#x}"
    );
    file
}

const F_TEXT_RVA: u32 = 0x1000;
const F_ENTRY_RVA: u32 = 0x1000;
const F_ADD_RVA: u32 = 0x1180;
const F_IOCTL_RVA: u32 = 0x1400;
const F_READ_RVA: u32 = 0x1480;
const F_WRITE_RVA: u32 = 0x1500;
const F_DEFAULT_RVA: u32 = 0x1580;
const F_STOP_RVA: u32 = 0x1600;
const F_RESUME_RVA: u32 = 0x1640;
const F_CANCEL_RVA: u32 = 0x1680;
const F_CLEANUP_RVA: u32 = 0x16C0;
const F_DESTROY_RVA: u32 = 0x1700;
const F_UNLOAD_RVA: u32 = 0x1740;
const F_RDATA_RVA: u32 = 0x2000;
const F_DATA_RVA: u32 = 0x3000;
const F_IMPORT_RVA: u32 = 0x2100;
const F_ILT_RVA: u32 = 0x2140;
const F_IAT_RVA: u32 = 0x2170;
const F_DLL_RVA: u32 = 0x21C0;
const F_HINT_RVA: u32 = 0x21E0;
const F_IMAGE_BASE: u64 = 0x1_4000_0000;

const F_CONFIG: u32 = 0x3000;
const F_QCONFIG: u32 = 0x3040;
const F_Q2CONFIG: u32 = 0x30B0;
const F_US_DEVA: u32 = 0x3120;
const F_WIDEA: u32 = 0x3140;
const F_US_DEVB: u32 = 0x3160;
const F_WIDEB: u32 = 0x3180;
const F_DEVINIT: u32 = 0x31A0;
const F_DRIVER: u32 = 0x31A8;
const F_DEV_A: u32 = 0x31B0;
const F_DEV_B: u32 = 0x31B8;
const F_QUEUE_A: u32 = 0x31C0;
const F_QUEUE_B: u32 = 0x31C8;
const F_ATTRS: u32 = 0x31D0;
const F_TYPEINFO: u32 = 0x3210;
const F_OUTBUF_PTR: u32 = 0x3230;
const F_OUTBUF_LEN: u32 = 0x3238;
const F_REQ_TMP: u32 = 0x3240;
const F_IOCTL_MARKER: u32 = 0x3250;
const F_IOCTL_COUNT: u32 = 0x3254;
const F_READ_COUNT: u32 = 0x3258;
const F_WRITE_COUNT: u32 = 0x325C;
const F_WRITE_MARKER: u32 = 0x3260;
const F_DEFAULT_COUNT: u32 = 0x3264;
const F_STOP_COUNT: u32 = 0x3268;
const F_RESUME_COUNT: u32 = 0x326C;
const F_CANCEL_COUNT: u32 = 0x3270;
const F_CLEANUP_COUNT: u32 = 0x3274;
const F_DESTROY_COUNT: u32 = 0x3278;
const F_ADD_COUNT: u32 = 0x327C;
const F_UNLOAD_COUNT: u32 = 0x3280;
const F_UNLOAD_MARKER: u32 = 0x3284;

const F_IAT_DRIVER: u32 = F_IAT_RVA;
const F_IAT_ASSIGN: u32 = F_IAT_RVA + 8;
const F_IAT_DEVICE: u32 = F_IAT_RVA + 16;
const F_IAT_QUEUE: u32 = F_IAT_RVA + 24;
const F_IAT_RETRIEVE_OUT: u32 = F_IAT_RVA + 32;
const F_IAT_RETRIEVE_IN: u32 = F_IAT_RVA + 40;
const F_IAT_COMPLETE_INFO: u32 = F_IAT_RVA + 48;
const F_IAT_COMPLETE: u32 = F_IAT_RVA + 56;

const F_IMPORTS: [&str; 8] = [
    "WdfDriverCreate",
    "WdfDeviceInitAssignName",
    "WdfDeviceCreate",
    "WdfIoQueueCreate",
    "WdfRequestRetrieveOutputBuffer",
    "WdfRequestRetrieveInputBuffer",
    "WdfRequestCompleteWithInformation",
    "WdfRequestComplete",
];

fn build_kmdf_full_driver(dispatch_type: u32, with_cancel_callback: bool) -> Vec<u8> {
    let mut file = vec![0_u8; 0x1400];
    file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    put_u32(&mut file, 0x3C, 0x80);
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(&mut file, coff, 0x8664);
    put_u16(&mut file, coff + 2, 3);
    put_u16(&mut file, coff + 16, 0xF0);
    put_u16(&mut file, coff + 18, 0x0022);
    let optional = coff + 20;
    put_u16(&mut file, optional, 0x020B);
    put_u32(&mut file, optional + 4, 0x800);
    put_u32(&mut file, optional + 8, 0x1400);
    put_u32(&mut file, optional + 16, F_ENTRY_RVA);
    put_u32(&mut file, optional + 20, F_TEXT_RVA);
    put_u64(&mut file, optional + 24, F_IMAGE_BASE);
    put_u32(&mut file, optional + 32, 0x1000);
    put_u32(&mut file, optional + 36, 0x200);
    put_u16(&mut file, optional + 48, 6);
    put_u32(&mut file, optional + 56, 0x4000);
    put_u32(&mut file, optional + 60, 0x200);
    put_u16(&mut file, optional + 68, 1);
    put_u32(&mut file, optional + 108, 16);
    let directories = optional + 112;
    put_u32(&mut file, directories + 8, F_IMPORT_RVA);
    put_u32(&mut file, directories + 12, 0x28);

    let section_table = optional + 0xF0;
    let mut write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32| {
        let entry = section_table + index * 40;
        file[entry..entry + 8].copy_from_slice(name);
        put_u32(&mut file, entry + 8, virtual_size);
        put_u32(&mut file, entry + 12, rva);
        put_u32(&mut file, entry + 16, raw_size);
        put_u32(&mut file, entry + 20, raw);
        put_u32(&mut file, entry + 36, characteristics);
    };
    write_section(
        0,
        b".text\0\0\0",
        0x800,
        F_TEXT_RVA,
        0x800,
        0x200,
        0x6000_0020,
    );
    write_section(
        1,
        b".rdata\0\0",
        0x600,
        F_RDATA_RVA,
        0x600,
        0xA00,
        0x4000_0040,
    );
    write_section(
        2,
        b".data\0\0\0",
        0x400,
        F_DATA_RVA,
        0x400,
        0x1000,
        0xC000_0040,
    );

    let mut entry = CodeBuilder::default();
    entry.raw(&[0x49, 0x89, 0xCA]); // mov r10,rcx
    entry.raw(&[0x49, 0x89, 0xD3]); // mov r11,rdx
    entry.raw(&[0x48, 0x8D, 0x05]);
    entry.disp(F_CONFIG);
    entry.raw(&[0xC7, 0x00]);
    entry.raw(&0x20_u32.to_le_bytes());
    entry.raw(&[0x48, 0x8D, 0x0D]);
    entry.disp(F_ADD_RVA);
    entry.raw(&[0x48, 0x89, 0x48, 0x08]);
    entry.raw(&[0x48, 0x8D, 0x0D]);
    entry.disp(F_UNLOAD_RVA);
    entry.raw(&[0x48, 0x89, 0x48, 0x10]);
    entry.raw(&[0xC7, 0x40, 0x18]);
    entry.raw(&0x2146_4457_u32.to_le_bytes());
    entry.raw(&[0x4C, 0x89, 0xD1]); // rcx = DriverObject
    entry.raw(&[0x4C, 0x89, 0xDA]); // rdx = RegistryPath
    entry.raw(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
    entry.raw(&[0x4C, 0x8D, 0x0D]);
    entry.disp(F_CONFIG);
    entry.raw(&[0x48, 0x83, 0xEC, 0x28]);
    entry.raw(&[0x48, 0x8D, 0x05]);
    entry.disp(F_DRIVER);
    entry.raw(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    entry.call_iat(F_IAT_DRIVER);
    entry.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let entry = entry.finish(F_ENTRY_RVA);
    assert!(entry.len() <= 0x180);
    copy_code(&mut file, F_ENTRY_RVA, &entry);

    let mut add = CodeBuilder::default();
    add.raw(&[0x48, 0x89, 0x15]); // device init (second argument)
    add.disp(F_DEVINIT);
    // WDF_OBJECT_ATTRIBUTES: Size=0x38, cleanup/destroy, context 0x30.
    add.raw(&[0x48, 0x8D, 0x3D]);
    add.disp(F_ATTRS);
    add.raw(&[0xC7, 0x07]);
    add.raw(&0x38_u32.to_le_bytes());
    add.raw(&[0x48, 0x8D, 0x05]);
    add.disp(F_CLEANUP_RVA);
    add.raw(&[0x48, 0x89, 0x47, 0x08]);
    add.raw(&[0x48, 0x8D, 0x05]);
    add.disp(F_DESTROY_RVA);
    add.raw(&[0x48, 0x89, 0x47, 0x10]);
    add.raw(&[0x48, 0xC7, 0x47, 0x18, 0, 0, 0, 0]);
    add.raw(&[0x48, 0xC7, 0x47, 0x20, 0, 0, 0, 0]);
    add.raw(&[0x48, 0xC7, 0x47, 0x28, 0x30, 0, 0, 0]);
    add.raw(&[0x48, 0x8D, 0x05]);
    add.disp(F_TYPEINFO);
    add.raw(&[0x48, 0x89, 0x47, 0x30]);
    add.raw(&[0x48, 0x8D, 0x05]);
    add.disp(F_TYPEINFO);
    add.raw(&[0xC7, 0x00, 0x18, 0, 0, 0]);
    add.raw(&[0x48, 0xC7, 0x40, 0x10, 0x30, 0, 0, 0]);
    add.raw(&[0x48, 0x83, 0xEC, 0x28]);

    // Device A.
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(F_DEVINIT);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(F_US_DEVA);
    add.call_iat(F_IAT_ASSIGN);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(F_DEVINIT);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(F_ATTRS);
    add.raw(&[0x4C, 0x8D, 0x05]);
    add.disp(F_DEV_A);
    add.call_iat(F_IAT_DEVICE);

    // Device B reuses the init handle after renaming it.
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(F_DEVINIT);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(F_US_DEVB);
    add.call_iat(F_IAT_ASSIGN);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(F_DEVINIT);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(F_ATTRS);
    add.raw(&[0x4C, 0x8D, 0x05]);
    add.disp(F_DEV_B);
    add.call_iat(F_IAT_DEVICE);

    for (config_rva, default_queue, queue_type, device_out, queue_out) in [
        (F_QCONFIG, 1u8, dispatch_type, F_DEV_A, F_QUEUE_A),
        (F_Q2CONFIG, 0u8, 1u32, F_DEV_B, F_QUEUE_B),
    ] {
        add.raw(&[0x48, 0x8D, 0x05]);
        add.disp(config_rva);
        add.raw(&[0xC7, 0x00]);
        add.raw(&0x50_u32.to_le_bytes());
        add.raw(&[0xC7, 0x40, 0x04]);
        add.raw(&queue_type.to_le_bytes());
        add.raw(&[0xC7, 0x40, 0x08, 0, 0, 0, 0]);
        add.raw(&[0xC6, 0x40, 0x0C, 0]);
        add.raw(&[0xC6, 0x40, 0x0D, default_queue]);
        add.raw(&[0x48, 0x8D, 0x0D]);
        add.disp(F_DEFAULT_RVA);
        add.raw(&[0x48, 0x89, 0x48, 0x10]);
        add.raw(&[0x48, 0x8D, 0x0D]);
        add.disp(F_READ_RVA);
        add.raw(&[0x48, 0x89, 0x48, 0x18]);
        add.raw(&[0x48, 0x8D, 0x0D]);
        add.disp(F_WRITE_RVA);
        add.raw(&[0x48, 0x89, 0x48, 0x20]);
        add.raw(&[0x48, 0x8D, 0x0D]);
        add.disp(F_IOCTL_RVA);
        add.raw(&[0x48, 0x89, 0x48, 0x28]);
        add.raw(&[0x48, 0xC7, 0x40, 0x30, 0, 0, 0, 0]);
        add.raw(&[0x48, 0x8D, 0x0D]);
        add.disp(F_STOP_RVA);
        add.raw(&[0x48, 0x89, 0x48, 0x38]);
        add.raw(&[0x48, 0x8D, 0x0D]);
        add.disp(F_RESUME_RVA);
        add.raw(&[0x48, 0x89, 0x48, 0x40]);
        if with_cancel_callback {
            add.raw(&[0x48, 0x8D, 0x0D]);
            add.disp(F_CANCEL_RVA);
            add.raw(&[0x48, 0x89, 0x48, 0x48]);
        } else {
            add.raw(&[0x48, 0xC7, 0x40, 0x48, 0, 0, 0, 0]);
        }
        add.raw(&[0x48, 0x8B, 0x0D]);
        add.disp(device_out);
        add.raw(&[0x48, 0x8D, 0x15]);
        add.disp(config_rva);
        add.raw(&[0x4C, 0x8D, 0x05]);
        add.disp(F_ATTRS);
        add.raw(&[0x4C, 0x8D, 0x0D]);
        add.disp(queue_out);
        add.call_iat(F_IAT_QUEUE);
    }
    add.raw(&[0x48, 0x83, 0xC4, 0x28]);
    add.inc_dword(F_ADD_COUNT);
    add.raw(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
    let add = add.finish(F_ADD_RVA);
    assert!(add.len() <= 0x280, "device add is {} bytes", add.len());
    copy_code(&mut file, F_ADD_RVA, &add);

    let mut ioctl = CodeBuilder::default();
    ioctl.raw(&[0x48, 0x89, 0x15]);
    ioctl.disp(F_REQ_TMP);
    ioctl.raw(&[0x44, 0x8B, 0x54, 0x24, 0x28]);
    ioctl.raw(&[0x44, 0x89, 0x15]);
    ioctl.disp(F_IOCTL_MARKER);
    ioctl.inc_dword(F_IOCTL_COUNT);
    ioctl.raw(&[0x48, 0x83, 0xEC, 0x28]);
    ioctl.raw(&[0x48, 0x8B, 0x0D]);
    ioctl.disp(F_REQ_TMP);
    ioctl.raw(&[0xBA, 4, 0, 0, 0]);
    ioctl.raw(&[0x4C, 0x8D, 0x05]);
    ioctl.disp(F_OUTBUF_PTR);
    ioctl.raw(&[0x4C, 0x8D, 0x0D]);
    ioctl.disp(F_OUTBUF_LEN);
    ioctl.call_iat(F_IAT_RETRIEVE_OUT);
    ioctl.raw(&[0x48, 0x8B, 0x05]);
    ioctl.disp(F_OUTBUF_PTR);
    ioctl.raw(&[0xC7, 0x00]);
    ioctl.raw(&0x46444D4B_u32.to_le_bytes()); // "KMDF"
    ioctl.raw(&[0x48, 0x8B, 0x0D]);
    ioctl.disp(F_REQ_TMP);
    ioctl.raw(&[0x31, 0xD2]);
    ioctl.raw(&[0x41, 0xB8, 4, 0, 0, 0]);
    ioctl.call_iat(F_IAT_COMPLETE_INFO);
    ioctl.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let ioctl = ioctl.finish(F_IOCTL_RVA);
    assert!(ioctl.len() <= 0x80);
    copy_code(&mut file, F_IOCTL_RVA, &ioctl);

    let mut read = CodeBuilder::default();
    read.raw(&[0x48, 0x89, 0x15]);
    read.disp(F_REQ_TMP);
    read.inc_dword(F_READ_COUNT);
    read.raw(&[0x48, 0x83, 0xEC, 0x28]);
    read.raw(&[0x48, 0x8B, 0x0D]);
    read.disp(F_REQ_TMP);
    read.raw(&[0xBA, 4, 0, 0, 0]);
    read.raw(&[0x4C, 0x8D, 0x05]);
    read.disp(F_OUTBUF_PTR);
    read.raw(&[0x4C, 0x8D, 0x0D]);
    read.disp(F_OUTBUF_LEN);
    read.call_iat(F_IAT_RETRIEVE_OUT);
    read.raw(&[0x48, 0x8B, 0x05]);
    read.disp(F_OUTBUF_PTR);
    read.raw(&[0xC7, 0x00]);
    read.raw(&0x31304452_u32.to_le_bytes()); // "RD01"
    read.raw(&[0x48, 0x8B, 0x0D]);
    read.disp(F_REQ_TMP);
    read.raw(&[0x31, 0xD2]);
    read.raw(&[0x41, 0xB8, 4, 0, 0, 0]);
    read.call_iat(F_IAT_COMPLETE_INFO);
    read.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let read = read.finish(F_READ_RVA);
    assert!(read.len() <= 0x80);
    copy_code(&mut file, F_READ_RVA, &read);

    let mut write = CodeBuilder::default();
    write.raw(&[0x48, 0x89, 0x15]);
    write.disp(F_REQ_TMP);
    write.inc_dword(F_WRITE_COUNT);
    write.raw(&[0x48, 0x83, 0xEC, 0x28]);
    write.raw(&[0x48, 0x8B, 0x0D]);
    write.disp(F_REQ_TMP);
    write.raw(&[0x31, 0xD2]);
    write.raw(&[0x4C, 0x8D, 0x05]);
    write.disp(F_OUTBUF_PTR);
    write.raw(&[0x4C, 0x8D, 0x0D]);
    write.disp(F_OUTBUF_LEN);
    write.call_iat(F_IAT_RETRIEVE_IN);
    write.raw(&[0x48, 0x8B, 0x05]);
    write.disp(F_OUTBUF_PTR);
    write.raw(&[0x8B, 0x08]);
    write.raw(&[0x89, 0x0D]);
    write.disp(F_WRITE_MARKER);
    write.raw(&[0x48, 0x8B, 0x0D]);
    write.disp(F_REQ_TMP);
    write.raw(&[0x31, 0xD2]);
    write.raw(&[0x41, 0xB8, 4, 0, 0, 0]);
    write.call_iat(F_IAT_COMPLETE_INFO);
    write.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let write = write.finish(F_WRITE_RVA);
    assert!(write.len() <= 0x80);
    copy_code(&mut file, F_WRITE_RVA, &write);

    let mut default = CodeBuilder::default();
    default.raw(&[0x48, 0x89, 0x15]);
    default.disp(F_REQ_TMP);
    default.inc_dword(F_DEFAULT_COUNT);
    default.raw(&[0x48, 0x83, 0xEC, 0x28]);
    default.raw(&[0x48, 0x8B, 0x0D]);
    default.disp(F_REQ_TMP);
    default.raw(&[0x31, 0xD2, 0x45, 0x31, 0xC0]);
    default.call_iat(F_IAT_COMPLETE);
    default.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let default = default.finish(F_DEFAULT_RVA);
    copy_code(&mut file, F_DEFAULT_RVA, &default);

    for (rva, marker) in [
        (F_STOP_RVA, F_STOP_COUNT),
        (F_RESUME_RVA, F_RESUME_COUNT),
        (F_CLEANUP_RVA, F_CLEANUP_COUNT),
        (F_DESTROY_RVA, F_DESTROY_COUNT),
    ] {
        let mut callback = CodeBuilder::default();
        callback.inc_dword(marker);
        callback.raw(&[0xC3]);
        let callback = callback.finish(rva);
        copy_code(&mut file, rva, &callback);
    }

    let mut cancel = CodeBuilder::default();
    cancel.raw(&[0x48, 0x89, 0x15]);
    cancel.disp(F_REQ_TMP);
    cancel.inc_dword(F_CANCEL_COUNT);
    cancel.raw(&[0x48, 0x8B, 0x0D]);
    cancel.disp(F_REQ_TMP);
    cancel.raw(&[0xBA]);
    cancel.raw(&STATUS_CANCELLED_u32());
    cancel.call_iat(F_IAT_COMPLETE);
    cancel.raw(&[0xC3]);
    let cancel = cancel.finish(F_CANCEL_RVA);
    copy_code(&mut file, F_CANCEL_RVA, &cancel);

    let mut unload = CodeBuilder::default();
    unload.inc_dword(F_UNLOAD_COUNT);
    unload.raw(&[0xC7, 0x05]);
    unload.disp_imm32(F_UNLOAD_MARKER, 0xCA5A_0200);
    unload.raw(&[0xC3]);
    let unload = unload.finish(F_UNLOAD_RVA);
    copy_code(&mut file, F_UNLOAD_RVA, &unload);

    let data_rva = |address: u32| 0x1000 + (address - F_DATA_RVA) as usize;
    let config = data_rva(F_CONFIG);
    put_u32(&mut file, config, 0x20);
    put_u64(&mut file, config + 8, F_IMAGE_BASE + u64::from(F_ADD_RVA));
    put_u64(
        &mut file,
        config + 0x10,
        F_IMAGE_BASE + u64::from(F_UNLOAD_RVA),
    );
    put_u32(&mut file, config + 0x18, 0x2146_4457);
    put_u32(&mut file, config + 0x1C, 0);
    for (us, wide, name) in [
        (F_US_DEVA, F_WIDEA, "\\Device\\WdfA"),
        (F_US_DEVB, F_WIDEB, "\\Device\\WdfB"),
    ] {
        let units = name.encode_utf16().count();
        let us_offset = data_rva(us);
        put_u16(&mut file, us_offset, (units * 2) as u16);
        put_u16(&mut file, us_offset + 2, ((units + 1) * 2) as u16);
        put_u64(&mut file, us_offset + 8, F_IMAGE_BASE + u64::from(wide));
        write_wide(
            &mut file[0x1000..0x1400],
            (wide - F_DATA_RVA) as usize,
            name,
        );
    }
    let attrs = data_rva(F_ATTRS);
    put_u32(&mut file, attrs, 0x38);
    put_u64(
        &mut file,
        attrs + 8,
        F_IMAGE_BASE + u64::from(F_CLEANUP_RVA),
    );
    put_u64(
        &mut file,
        attrs + 0x10,
        F_IMAGE_BASE + u64::from(F_DESTROY_RVA),
    );
    put_u64(&mut file, attrs + 0x28, 0x30);
    put_u64(
        &mut file,
        attrs + 0x30,
        F_IMAGE_BASE + u64::from(F_TYPEINFO),
    );
    let type_info = data_rva(F_TYPEINFO);
    put_u32(&mut file, type_info, 0x18);
    put_u64(&mut file, type_info + 0x10, 0x30);

    let rva = |address: u32| 0xA00 + (address - F_RDATA_RVA) as usize;
    let descriptor = rva(F_IMPORT_RVA);
    put_u32(&mut file, descriptor, F_ILT_RVA);
    put_u32(&mut file, descriptor + 12, F_DLL_RVA);
    put_u32(&mut file, descriptor + 16, F_IAT_RVA);
    file[rva(F_DLL_RVA)..rva(F_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
    file[rva(F_DLL_RVA) + 10] = 0;
    let mut hint_rva = F_HINT_RVA;
    for (index, symbol) in F_IMPORTS.iter().enumerate() {
        put_u64(&mut file, rva(F_ILT_RVA) + index * 8, u64::from(hint_rva));
        put_u64(&mut file, rva(F_IAT_RVA) + index * 8, u64::from(hint_rva));
        let offset = rva(hint_rva);
        put_u16(&mut file, offset, 0);
        file[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
        file[offset + 2 + symbol.len()] = 0;
        hint_rva += (2 + symbol.len() + 1 + 1) as u32 & !1;
    }
    assert!(hint_rva <= 0x2500, "hint table overruns: {hint_rva:#x}");
    file
}

// ---- PnP/power KMDF fixture -------------------------------------------
//
// A single-device KMDF image whose EvtDriverDeviceAdd registers
// WDF_PNPPOWER_EVENT_CALLBACKS and WDF_FILEOBJECT_CONFIG.  Every callback
// increments a guest counter; status callbacks return P_FAIL_STATUS when
// their bit is set in P_FAIL_MASK, so tests can inject failures at each
// transition step.

const P_TEXT_RVA: u32 = 0x1000;
const P_ENTRY_RVA: u32 = 0x1000;
const P_ADD_RVA: u32 = 0x1100;
const P_PREPARE_RVA: u32 = 0x1200;
const P_RELEASE_RVA: u32 = 0x1240;
const P_D0ENTRY_RVA: u32 = 0x1280;
const P_D0EXIT_RVA: u32 = 0x12C0;
const P_SELFINIT_RVA: u32 = 0x1300;
const P_SELFFINI_RVA: u32 = 0x1340;
const P_SUSPEND_RVA: u32 = 0x1380;
const P_RESTART_RVA: u32 = 0x13C0;
const P_CLEANUP_RVA: u32 = 0x1400;
const P_DESTROY_RVA: u32 = 0x1440;
const P_FCLEANUP_RVA: u32 = 0x1480;
const P_FCLOSE_RVA: u32 = 0x14C0;
const P_RDATA_RVA: u32 = 0x2000;
const P_DATA_RVA: u32 = 0x3000;
const P_IMPORT_RVA: u32 = 0x2100;
const P_ILT_RVA: u32 = 0x2140;
const P_IAT_RVA: u32 = 0x2180;
const P_DLL_RVA: u32 = 0x21C0;
const P_HINT_RVA: u32 = 0x21E0;
const P_IMAGE_BASE: u64 = 0x1_4000_0000;

const P_PNP_CONFIG: u32 = 0x3070;
const P_FILE_CONFIG: u32 = 0x30D0;
const P_DEV_ATTRS: u32 = 0x3100;
const P_FAIL_MASK: u32 = 0x3160;
const P_FAIL_STATUS: u32 = 0x3164;
const P_PREPARE_COUNT: u32 = 0x3168;
const P_RELEASE_COUNT: u32 = 0x316C;
const P_D0ENTRY_COUNT: u32 = 0x3170;
const P_D0EXIT_COUNT: u32 = 0x3174;
const P_SELFINIT_COUNT: u32 = 0x3178;
const P_SELFFINI_COUNT: u32 = 0x317C;
const P_SUSPEND_COUNT: u32 = 0x3180;
const P_RESTART_COUNT: u32 = 0x3184;
const P_CLEANUP_COUNT: u32 = 0x3188;
const P_DESTROY_COUNT: u32 = 0x318C;
const P_FCLEANUP_COUNT: u32 = 0x3190;
const P_FCLOSE_COUNT: u32 = 0x3194;
const P_LAST_PREV: u32 = 0x3198;
const P_LAST_TARGET: u32 = 0x319C;
const P_CLEANUP_AFTER_DESTROY: u32 = 0x31A0;
const P_DESTROY_AFTER_CLEANUP: u32 = 0x31A4;
const P_DEVICE_OUT: u32 = 0x31A8;
const P_DRIVER_OUT: u32 = 0x31B0;
const P_DEVINIT: u32 = 0x31B8;
const P_DRIVER_CONFIG: u32 = 0x31C0;

const P_IAT_DRIVER: u32 = P_IAT_RVA;
const P_IAT_SET_PNP: u32 = P_IAT_RVA + 8;
const P_IAT_SET_FILE: u32 = P_IAT_RVA + 16;
const P_IAT_DEVICE: u32 = P_IAT_RVA + 24;
const P_IMPORTS: [&str; 4] = [
    "WdfDriverCreate",
    "WdfDeviceInitSetPnpPowerEventCallbacks",
    "WdfDeviceInitSetFileObjectConfig",
    "WdfDeviceCreate",
];

fn pnp_data_rva(address: u32) -> usize {
    0x1C00 + (address - P_DATA_RVA) as usize
}

fn pnp_copy(file: &mut [u8], rva: u32, code: &[u8]) {
    let offset = 0x400 + (rva - P_TEXT_RVA) as usize;
    file[offset..offset + code.len()].copy_from_slice(code);
}

fn pnp_status_callback(count: u32, fail_bit: u32, store_arg: Option<u32>, rva: u32) -> Vec<u8> {
    let mut code = CodeBuilder::default();
    if let Some(target) = store_arg {
        code.raw(&[0x89, 0x15]);
        code.disp(target);
    }
    code.inc_dword(count);
    code.raw(&[0x8B, 0x05]);
    code.disp(P_FAIL_MASK);
    code.raw(&[0xA9]);
    code.raw(&fail_bit.to_le_bytes());
    code.raw(&[0x74, 0x07]);
    code.raw(&[0x8B, 0x05]);
    code.disp(P_FAIL_STATUS);
    code.raw(&[0xC3]);
    code.raw(&[0x31, 0xC0, 0xC3]);
    code.finish(rva)
}

fn pnp_void_callback(count: u32, rva: u32) -> Vec<u8> {
    let mut code = CodeBuilder::default();
    code.inc_dword(count);
    code.raw(&[0xC3]);
    code.finish(rva)
}

/// Cleanup/destroy stubs that record the other callback's counter, so the
/// test can pin the post-order cascade exactly.
fn pnp_order_callback(other_count: u32, flag: u32, count: u32, rva: u32) -> Vec<u8> {
    let mut code = CodeBuilder::default();
    code.raw(&[0x8B, 0x05]);
    code.disp(other_count);
    code.raw(&[0x89, 0x05]);
    code.disp(flag);
    code.inc_dword(count);
    code.raw(&[0xC3]);
    code.finish(rva)
}

fn build_kmdf_pnp_driver() -> Vec<u8> {
    let mut file = vec![0_u8; 0x2C00];
    file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    put_u32(&mut file, 0x3C, 0x80);
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(&mut file, coff, 0x8664);
    put_u16(&mut file, coff + 2, 3);
    put_u16(&mut file, coff + 16, 0xF0);
    put_u16(&mut file, coff + 18, 0x0022);
    let optional = coff + 20;
    put_u16(&mut file, optional, 0x020B);
    put_u32(&mut file, optional + 4, 0x1000);
    put_u32(&mut file, optional + 8, 0x1800);
    put_u32(&mut file, optional + 16, P_ENTRY_RVA);
    put_u32(&mut file, optional + 20, P_TEXT_RVA);
    put_u64(&mut file, optional + 24, P_IMAGE_BASE);
    put_u32(&mut file, optional + 32, 0x1000);
    put_u32(&mut file, optional + 36, 0x200);
    put_u16(&mut file, optional + 48, 6);
    put_u32(&mut file, optional + 56, 0x4000);
    put_u32(&mut file, optional + 60, 0x400);
    put_u16(&mut file, optional + 68, 1);
    put_u32(&mut file, optional + 108, 16);
    let directories = optional + 112;
    put_u32(&mut file, directories + 8, P_IMPORT_RVA);
    put_u32(&mut file, directories + 12, 0x28);

    let section_table = optional + 0xF0;
    let mut write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32| {
        let entry = section_table + index * 40;
        file[entry..entry + 8].copy_from_slice(name);
        put_u32(&mut file, entry + 8, virtual_size);
        put_u32(&mut file, entry + 12, rva);
        put_u32(&mut file, entry + 16, raw_size);
        put_u32(&mut file, entry + 20, raw);
        put_u32(&mut file, entry + 36, characteristics);
    };
    write_section(
        0,
        b".text\0\0\0",
        0x1000,
        P_TEXT_RVA,
        0x1000,
        0x400,
        0x6000_0020,
    );
    write_section(
        1,
        b".rdata\0\0",
        0x800,
        P_RDATA_RVA,
        0x800,
        0x1400,
        0x4000_0040,
    );
    write_section(
        2,
        b".data\0\0\0",
        0x1000,
        P_DATA_RVA,
        0x1000,
        0x1C00,
        0xC000_0040,
    );

    let mut entry = CodeBuilder::default();
    entry.raw(&[0x49, 0x89, 0xD3]); // mov r11,rdx (RegistryPath)
    entry.raw(&[0x48, 0x8D, 0x05]);
    entry.disp(P_DRIVER_CONFIG);
    entry.raw(&[0xC7, 0x00]);
    entry.raw(&0x28_u32.to_le_bytes());
    entry.raw(&[0x48, 0x8D, 0x15]);
    entry.disp(P_ADD_RVA);
    entry.raw(&[0x48, 0x89, 0x50, 0x08]);
    entry.raw(&[0x4C, 0x89, 0xDA]); // rdx = RegistryPath
    entry.raw(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
    entry.raw(&[0x4C, 0x8D, 0x0D]);
    entry.disp(P_DRIVER_CONFIG);
    entry.raw(&[0x48, 0x83, 0xEC, 0x28]);
    entry.raw(&[0x48, 0x8D, 0x05]);
    entry.disp(P_DRIVER_OUT);
    entry.raw(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    entry.call_iat(P_IAT_DRIVER);
    entry.raw(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    let entry = entry.finish(P_ENTRY_RVA);
    pnp_copy(&mut file, P_ENTRY_RVA, &entry);

    let mut add = CodeBuilder::default();
    add.raw(&[0x48, 0x89, 0x15]); // mov [rip+disp], rdx (DeviceInit)
    add.disp(P_DEVINIT);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(P_DEVINIT);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(P_PNP_CONFIG);
    add.call_iat(P_IAT_SET_PNP);
    add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(P_DEVINIT);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(P_FILE_CONFIG);
    add.raw(&[0x45, 0x31, 0xC0]);
    add.call_iat(P_IAT_SET_FILE);
    add.raw(&[0x85, 0xC0, 0x79, 0x01, 0xC3]);
    add.raw(&[0x48, 0x8B, 0x0D]);
    add.disp(P_DEVINIT);
    add.raw(&[0x48, 0x8D, 0x15]);
    add.disp(P_DEV_ATTRS);
    add.raw(&[0x4C, 0x8D, 0x05]);
    add.disp(P_DEVICE_OUT);
    add.call_iat(P_IAT_DEVICE);
    add.raw(&[0xC3]);
    let add = add.finish(P_ADD_RVA);
    assert!(add.len() <= 0x80, "pnp device add is {} bytes", add.len());
    pnp_copy(&mut file, P_ADD_RVA, &add);

    for (count, bit, store, rva) in [
        (P_PREPARE_COUNT, 1, None, P_PREPARE_RVA),
        (P_RELEASE_COUNT, 16, None, P_RELEASE_RVA),
        (P_D0ENTRY_COUNT, 2, Some(P_LAST_PREV), P_D0ENTRY_RVA),
        (P_D0EXIT_COUNT, 8, Some(P_LAST_TARGET), P_D0EXIT_RVA),
        (P_SELFINIT_COUNT, 4, None, P_SELFINIT_RVA),
        (P_SUSPEND_COUNT, 32, None, P_SUSPEND_RVA),
        (P_RESTART_COUNT, 64, None, P_RESTART_RVA),
    ] {
        let code = pnp_status_callback(count, bit, store, rva);
        pnp_copy(&mut file, rva, &code);
    }
    for (count, rva) in [
        (P_SELFFINI_COUNT, P_SELFFINI_RVA),
        (P_FCLEANUP_COUNT, P_FCLEANUP_RVA),
        (P_FCLOSE_COUNT, P_FCLOSE_RVA),
    ] {
        let code = pnp_void_callback(count, rva);
        pnp_copy(&mut file, rva, &code);
    }
    let code = pnp_order_callback(
        P_DESTROY_COUNT,
        P_CLEANUP_AFTER_DESTROY,
        P_CLEANUP_COUNT,
        P_CLEANUP_RVA,
    );
    pnp_copy(&mut file, P_CLEANUP_RVA, &code);
    let code = pnp_order_callback(
        P_CLEANUP_COUNT,
        P_DESTROY_AFTER_CLEANUP,
        P_DESTROY_COUNT,
        P_DESTROY_RVA,
    );
    pnp_copy(&mut file, P_DESTROY_RVA, &code);

    let data = |address: u32| pnp_data_rva(address);
    put_u32(&mut file, data(P_PNP_CONFIG), 0x58);
    for (offset, rva) in [
        (0x08u32, P_PREPARE_RVA),
        (0x10, P_RELEASE_RVA),
        (0x18, P_D0ENTRY_RVA),
        (0x20, P_D0EXIT_RVA),
        (0x28, P_SELFINIT_RVA),
        (0x30, P_SUSPEND_RVA),
        (0x38, P_RESTART_RVA),
        (0x48, P_SELFFINI_RVA),
    ] {
        put_u64(
            &mut file,
            data(P_PNP_CONFIG) + offset as usize,
            P_IMAGE_BASE + u64::from(rva),
        );
    }
    put_u32(&mut file, data(P_FILE_CONFIG), 0x20);
    put_u64(
        &mut file,
        data(P_FILE_CONFIG) + 0x10,
        P_IMAGE_BASE + u64::from(P_FCLOSE_RVA),
    );
    put_u64(
        &mut file,
        data(P_FILE_CONFIG) + 0x18,
        P_IMAGE_BASE + u64::from(P_FCLEANUP_RVA),
    );
    put_u32(&mut file, data(P_DEV_ATTRS), 0x38);
    put_u64(
        &mut file,
        data(P_DEV_ATTRS) + 0x08,
        P_IMAGE_BASE + u64::from(P_CLEANUP_RVA),
    );
    put_u64(
        &mut file,
        data(P_DEV_ATTRS) + 0x10,
        P_IMAGE_BASE + u64::from(P_DESTROY_RVA),
    );

    let rva = |address: u32| 0x1400 + (address - P_RDATA_RVA) as usize;
    let descriptor = rva(P_IMPORT_RVA);
    put_u32(&mut file, descriptor, P_ILT_RVA);
    put_u32(&mut file, descriptor + 12, P_DLL_RVA);
    put_u32(&mut file, descriptor + 16, P_IAT_RVA);
    file[rva(P_DLL_RVA)..rva(P_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
    file[rva(P_DLL_RVA) + 10] = 0;
    let mut hint_rva = P_HINT_RVA;
    for (index, symbol) in P_IMPORTS.iter().enumerate() {
        put_u64(&mut file, rva(P_ILT_RVA) + index * 8, u64::from(hint_rva));
        put_u64(&mut file, rva(P_IAT_RVA) + index * 8, u64::from(hint_rva));
        let offset = rva(hint_rva);
        put_u16(&mut file, offset, 0);
        file[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
        file[offset + 2 + symbol.len()] = 0;
        hint_rva += (2 + symbol.len() + 1 + 1) as u32 & !1;
    }
    assert!(hint_rva <= 0x2400, "pnp hint table overruns: {hint_rva:#x}");
    file
}

const X86K_ENTRY_RVA: u32 = 0x1000;
const X86K_ADD_RVA: u32 = 0x1100;
const X86K_UNLOAD_RVA: u32 = 0x1180;
const X86K_TEXT_RVA: u32 = 0x1000;
const X86K_RDATA_RVA: u32 = 0x2000;
const X86K_DATA_RVA: u32 = 0x3000;
const X86K_IMPORT_RVA: u32 = 0x2100;
const X86K_ILT_RVA: u32 = 0x2140;
const X86K_IAT_RVA: u32 = 0x2160;
const X86K_DLL_RVA: u32 = 0x2180;
const X86K_HINT_RVA: u32 = 0x21A0;
const X86K_IMAGE_BASE: u32 = 0x1000_0000;
const X86K_CONFIG: u32 = 0x3000;
const X86K_DRIVER_PTR: u32 = 0x3018;
const X86K_REG_PATH: u32 = 0x301C;
const X86K_DRIVER_OUT: u32 = 0x3020;
const X86K_DEVINIT: u32 = 0x3024;
const X86K_DEVICE_OUT: u32 = 0x3028;
const X86K_US_DEV: u32 = 0x3030;
const X86K_WIDE_DEV: u32 = 0x3050;
const X86K_ADD_MARKER: u32 = 0x3070;
const X86K_UNLOAD_MARKER: u32 = 0x3074;
const X86K_IAT_DRIVER: u32 = X86K_IAT_RVA;
const X86K_IAT_ASSIGN: u32 = X86K_IAT_RVA + 4;
const X86K_IAT_DEVICE: u32 = X86K_IAT_RVA + 8;
const X86K_IMPORTS: [&str; 3] = [
    "WdfDriverCreate",
    "WdfDeviceInitAssignName",
    "WdfDeviceCreate",
];

fn build_kmdf_driver_pe32() -> Vec<u8> {
    let mut file = vec![0_u8; 0xC00];
    file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    put_u32(&mut file, 0x3C, 0x80);
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put_u16(&mut file, coff, 0x014C);
    put_u16(&mut file, coff + 2, 3);
    put_u16(&mut file, coff + 16, 0xE0);
    put_u16(&mut file, coff + 18, 0x0102);
    let optional = coff + 20;
    put_u16(&mut file, optional, 0x010B);
    put_u32(&mut file, optional + 4, 0x400);
    put_u32(&mut file, optional + 8, 0xC00);
    put_u32(&mut file, optional + 16, X86K_ENTRY_RVA);
    put_u32(&mut file, optional + 20, X86K_TEXT_RVA);
    put_u32(&mut file, optional + 24, X86K_RDATA_RVA);
    put_u32(&mut file, optional + 28, X86K_IMAGE_BASE);
    put_u32(&mut file, optional + 32, 0x1000);
    put_u32(&mut file, optional + 36, 0x200);
    put_u16(&mut file, optional + 48, 6);
    put_u32(&mut file, optional + 56, 0x4000);
    put_u32(&mut file, optional + 60, 0x200);
    put_u16(&mut file, optional + 68, 1);
    put_u32(&mut file, optional + 92, 16);
    let directories = optional + 96;
    put_u32(&mut file, directories + 8, X86K_IMPORT_RVA);
    put_u32(&mut file, directories + 12, 0x28);

    let section_table = optional + 0xE0;
    let mut write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32| {
        let entry = section_table + index * 40;
        file[entry..entry + 8].copy_from_slice(name);
        put_u32(&mut file, entry + 8, virtual_size);
        put_u32(&mut file, entry + 12, rva);
        put_u32(&mut file, entry + 16, raw_size);
        put_u32(&mut file, entry + 20, raw);
        put_u32(&mut file, entry + 36, characteristics);
    };
    write_section(
        0,
        b".text\0\0\0",
        0x400,
        X86K_TEXT_RVA,
        0x400,
        0x200,
        0x6000_0020,
    );
    write_section(
        1,
        b".rdata\0\0",
        0x400,
        X86K_RDATA_RVA,
        0x400,
        0x600,
        0x4000_0040,
    );
    write_section(
        2,
        b".data\0\0\0",
        0x200,
        X86K_DATA_RVA,
        0x200,
        0xA00,
        0xC000_0040,
    );

    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x8B, 0x44, 0x24, 0x04]); // DriverObject
    entry.extend_from_slice(&[0xA3]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DRIVER_PTR).to_le_bytes());
    entry.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08]); // RegistryPath
    entry.extend_from_slice(&[0xA3]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_REG_PATH).to_le_bytes());
    entry.extend_from_slice(&[0xC7, 0x05]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG).to_le_bytes());
    entry.extend_from_slice(&0x14_u32.to_le_bytes());
    entry.extend_from_slice(&[0xC7, 0x05]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 4).to_le_bytes());
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_ADD_RVA).to_le_bytes());
    entry.extend_from_slice(&[0xC7, 0x05]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 8).to_le_bytes());
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_UNLOAD_RVA).to_le_bytes());
    entry.extend_from_slice(&[0xC7, 0x05]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 0xC).to_le_bytes());
    entry.extend_from_slice(&0x2146_4457_u32.to_le_bytes());
    entry.extend_from_slice(&[0xC7, 0x05]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG + 0x10).to_le_bytes());
    entry.extend_from_slice(&0_u32.to_le_bytes());
    entry.extend_from_slice(&[0x68]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DRIVER_OUT).to_le_bytes());
    entry.extend_from_slice(&[0x68]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_CONFIG).to_le_bytes());
    entry.extend_from_slice(&[0x6A, 0x00]);
    entry.extend_from_slice(&[0xFF, 0x35]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_REG_PATH).to_le_bytes());
    entry.extend_from_slice(&[0xFF, 0x35]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DRIVER_PTR).to_le_bytes());
    entry.extend_from_slice(&[0xFF, 0x15]);
    entry.extend_from_slice(&(X86K_IMAGE_BASE + X86K_IAT_DRIVER).to_le_bytes());
    entry.extend_from_slice(&[0xC2, 0x08, 0x00]);
    assert!(entry.len() <= 0x100);
    file[0x200..0x200 + entry.len()].copy_from_slice(&entry);

    let mut add = Vec::new();
    add.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08]); // DeviceInit
    add.extend_from_slice(&[0xA3]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVINIT).to_le_bytes());
    add.extend_from_slice(&[0x68]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_US_DEV).to_le_bytes());
    add.extend_from_slice(&[0xFF, 0x35]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVINIT).to_le_bytes());
    add.extend_from_slice(&[0xFF, 0x15]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_IAT_ASSIGN).to_le_bytes());
    add.extend_from_slice(&[0x68]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVICE_OUT).to_le_bytes());
    add.extend_from_slice(&[0x6A, 0x00]);
    add.extend_from_slice(&[0x68]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_DEVINIT).to_le_bytes());
    add.extend_from_slice(&[0xFF, 0x15]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_IAT_DEVICE).to_le_bytes());
    add.extend_from_slice(&[0xC7, 0x05]);
    add.extend_from_slice(&(X86K_IMAGE_BASE + X86K_ADD_MARKER).to_le_bytes());
    add.extend_from_slice(&0xCA5A_0031_u32.to_le_bytes());
    add.extend_from_slice(&[0x31, 0xC0, 0xC2, 0x08, 0x00]);
    assert!(add.len() <= 0x80);
    file[0x300..0x300 + add.len()].copy_from_slice(&add);

    let mut unload = Vec::new();
    unload.extend_from_slice(&[0xC7, 0x05]);
    unload.extend_from_slice(&(X86K_IMAGE_BASE + X86K_UNLOAD_MARKER).to_le_bytes());
    unload.extend_from_slice(&0xCA5A_0032_u32.to_le_bytes());
    unload.extend_from_slice(&[0xC2, 0x04, 0x00]);
    file[0x380..0x380 + unload.len()].copy_from_slice(&unload);

    let rva = |address: u32| 0x600 + (address - X86K_RDATA_RVA) as usize;
    let descriptor = rva(X86K_IMPORT_RVA);
    put_u32(&mut file, descriptor, X86K_ILT_RVA);
    put_u32(&mut file, descriptor + 12, X86K_DLL_RVA);
    put_u32(&mut file, descriptor + 16, X86K_IAT_RVA);
    file[rva(X86K_DLL_RVA)..rva(X86K_DLL_RVA) + 10].copy_from_slice(b"WdfLdr.sys");
    file[rva(X86K_DLL_RVA) + 10] = 0;
    let mut hint_rva = X86K_HINT_RVA;
    for (index, symbol) in X86K_IMPORTS.iter().enumerate() {
        put_u32(&mut file, rva(X86K_ILT_RVA) + index * 4, hint_rva);
        put_u32(&mut file, rva(X86K_IAT_RVA) + index * 4, hint_rva);
        let offset = rva(hint_rva);
        put_u16(&mut file, offset, 0);
        file[offset + 2..offset + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
        file[offset + 2 + symbol.len()] = 0;
        hint_rva += (2 + symbol.len() + 1 + 1) as u32 & !1;
    }
    let data = 0xA00;
    put_u32(&mut file, data, 0x14);
    put_u32(&mut file, data + 4, X86K_IMAGE_BASE + X86K_ADD_RVA);
    put_u32(&mut file, data + 8, X86K_IMAGE_BASE + X86K_UNLOAD_RVA);
    put_u32(&mut file, data + 0xC, 0x2146_4457);
    put_u32(&mut file, data + 0x10, 0);
    let us = 0xA00 + (X86K_US_DEV - X86K_DATA_RVA) as usize;
    put_u16(&mut file, us, 26);
    put_u16(&mut file, us + 2, 28);
    put_u32(&mut file, us + 4, X86K_IMAGE_BASE + X86K_WIDE_DEV);
    write_wide(
        &mut file[0xA00..0xC00],
        (X86K_WIDE_DEV - X86K_DATA_RVA) as usize,
        "\\Device\\Wdf32",
    );
    file
}

fn copy_code(file: &mut [u8], rva: u32, code: &[u8]) {
    let offset = 0x200 + (rva - F_TEXT_RVA) as usize;
    file[offset..offset + code.len()].copy_from_slice(code);
}

fn STATUS_CANCELLED_u32() -> [u8; 4] {
    (STATUS_CANCELLED as u32).to_le_bytes()
}

fn write_wide(rdata: &mut [u8], offset: usize, text: &str) {
    for (index, unit) in text.encode_utf16().chain([0]).enumerate() {
        rdata[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

fn test_runtime() -> (PeHostRuntime, TempDir) {
    test_runtime_with_ge(|_| {})
}

fn test_runtime_with_ge<F: FnOnce(&mut GameEnvironment)>(configure: F) -> (PeHostRuntime, TempDir) {
    let directory = TempDir::new().expect("temp dir");
    let mut ge =
        GameEnvironment::create_in(directory.path(), "driver-island", GeArch::X64, "win11-23h2")
            .expect("create ge");
    configure(&mut ge);
    let runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
    reset_runtime_registry(&runtime);
    (runtime, directory)
}

fn stage_service(ge: &mut GameEnvironment, service: &str, image_path: &str, image: &[u8]) {
    let key = format!("SYSTEM\\CurrentControlSet\\Services\\{service}");
    ge.registry_create_key("HKLM", &key, RegistryView::Native)
        .expect("create service key");
    ge.registry_set_value(
        "HKLM",
        &key,
        "ImagePath",
        "REG_SZ",
        json!(image_path),
        RegistryView::Native,
    )
    .expect("write ImagePath");
    ge.create_directory("C:\\Windows\\System32\\drivers", true)
        .expect("create driver directory");
    ge.write_file(DRIVER_IMAGE_PATH, image, true)
        .expect("write driver image");
}

const DRIVER_IMAGE_PATH: &str = "C:\\Windows\\System32\\drivers\\casa_nt.sys";

fn guest_unicode_string(memory: &mut MemoryImage, header: u64, text: &str) -> u64 {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let buffer = header + 0x100;
    memory.map_bytes(header, &[0_u8; 16]);
    memory.map_bytes(buffer, &vec![0_u8; (units.len() + 1) * 2]);
    memory.write_u16(header, (units.len() * 2) as u16);
    memory.write_u16(header + 2, ((units.len() + 1) * 2) as u16);
    memory.write_u64(header + 8, buffer);
    for (index, unit) in units.iter().enumerate() {
        memory.write_u16(buffer + index as u64 * 2, *unit);
    }
    header
}

fn prepare_guest_memory(runtime: &mut PeHostRuntime, memory: &mut MemoryImage) {
    let vm = runtime.win32.address_space_mut();
    vm.register(STACK_BASE, STACK_SIZE, VmRegionKind::Stack);
    vm.commit(STACK_BASE, STACK_SIZE, VmProtection::READ_WRITE, false);
    vm.register(0x40_000, 0x20_000, VmRegionKind::Private);
    vm.commit(0x40_000, 0x20_000, VmProtection::READ_WRITE, false);
    memory.set_vm(vm);
}

fn test_runtime_x86() -> (PeHostRuntime, TempDir) {
    let (mut runtime, directory) = test_runtime();
    runtime.guest_arch = GuestArch::X86;
    runtime.next_thunk_address = 0x7100_0000;
    (runtime, directory)
}

fn test_runtime_x86_with_ge<F: FnOnce(&mut GameEnvironment)>(
    configure: F,
) -> (PeHostRuntime, TempDir) {
    let directory = TempDir::new().expect("temp dir");
    let mut ge = GameEnvironment::create_in(
        directory.path(),
        "driver-island-x86",
        GeArch::X86,
        "win11-23h2",
    )
    .expect("create ge");
    configure(&mut ge);
    let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
    runtime.guest_arch = GuestArch::X86;
    runtime.next_thunk_address = 0x7100_0000;
    reset_runtime_registry(&runtime);
    (runtime, directory)
}

fn guest_unicode_string_x86(memory: &mut MemoryImage, header: u64, text: &str) -> u64 {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let buffer = header + 0x100;
    memory.map_bytes(header, &[0_u8; 8]);
    memory.map_bytes(buffer, &vec![0_u8; (units.len() + 1) * 2]);
    memory.write_u16(header, (units.len() * 2) as u16);
    memory.write_u16(header + 2, ((units.len() + 1) * 2) as u16);
    memory.write_u32(header + 4, buffer as u32);
    for (index, unit) in units.iter().enumerate() {
        memory.write_u16(buffer + index as u64 * 2, *unit);
    }
    header
}

fn write_object_attributes(memory: &mut MemoryImage, address: u64, name: u64, arch: GuestArch) {
    let size = 48;
    memory.map_bytes(address, &[0_u8; 48]);
    match arch {
        GuestArch::X64 => {
            memory.write_u32(address, 48);
            memory.write_u64(address + 16, name);
        }
        GuestArch::X86 => {
            memory.write_u32(address, 24);
            memory.write_u32(address + 8, name as u32);
            let _ = size;
        }
    }
}

fn create_device_file(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    path: &str,
    base: u64,
) -> (u32, i32) {
    let arch = runtime.guest_arch;
    let name = match arch {
        GuestArch::X64 => guest_unicode_string(memory, base, path),
        GuestArch::X86 => guest_unicode_string_x86(memory, base, path),
    };
    let attributes = base + 0x1000;
    write_object_attributes(memory, attributes, name, arch);
    let handle_ptr = base + 0x2000;
    let iosb = base + 0x2100;
    memory.map_bytes(handle_ptr, &[0_u8; 4]);
    memory.map_bytes(iosb, &[0_u8; 24]);
    let status = dispatch_nt_thunk(
        runtime,
        memory,
        HostThunk::NtCreateFile,
        &[
            handle_ptr,
            0x0012_0000,
            attributes,
            iosb,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
        ],
    );
    (memory.read_u32(handle_ptr).unwrap_or(0), status)
}

fn open_directory_object(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    path: &str,
    base: u64,
) -> (u32, i32) {
    let arch = runtime.guest_arch;
    let name = match arch {
        GuestArch::X64 => guest_unicode_string(memory, base, path),
        GuestArch::X86 => guest_unicode_string_x86(memory, base, path),
    };
    let attributes = base + 0x1000;
    write_object_attributes(memory, attributes, name, arch);
    let handle_ptr = base + 0x2000;
    memory.map_bytes(handle_ptr, &[0_u8; 8]);
    let status = dispatch_nt_thunk(
        runtime,
        memory,
        HostThunk::NtOpenDirectoryObject,
        &[handle_ptr, 0x0001, attributes],
    );
    let handle = match arch {
        GuestArch::X64 => memory.read_u64(handle_ptr).unwrap_or(0) as u32,
        GuestArch::X86 => memory.read_u32(handle_ptr).unwrap_or(0),
    };
    (handle, status)
}

fn query_directory_object(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    handle: u32,
    index: u32,
    buffer: u64,
    length: u32,
) -> (i32, Vec<(String, String)>, u32) {
    let context = 0x46_000u64;
    let return_length = 0x46_100u64;
    memory.map_bytes(context, &index.to_le_bytes());
    memory.map_bytes(return_length, &[0_u8; 4]);
    let status = dispatch_nt_thunk(
        runtime,
        memory,
        HostThunk::NtQueryDirectoryObject,
        &[
            u64::from(handle),
            buffer,
            u64::from(length),
            1,
            0,
            context,
            return_length,
        ],
    );
    let context_after = memory.read_u32(context).unwrap_or(0);
    if status != STATUS_SUCCESS {
        return (status, Vec::new(), context_after);
    }
    let used = memory.read_u32(return_length).unwrap_or(0) as usize;
    let bytes = memory.read_bytes(buffer, used).unwrap_or_default();
    let (header, wide_width) = match runtime.guest_arch {
        GuestArch::X64 => (32_usize, 8_usize),
        GuestArch::X86 => (16_usize, 4_usize),
    };
    let read_string = |header_offset: usize| -> String {
        let name_len =
            u16::from_le_bytes([bytes[header_offset], bytes[header_offset + 1]]) as usize;
        let ptr_offset = header_offset + wide_width;
        let ptr = if wide_width == 8 {
            u64::from_le_bytes(
                bytes[ptr_offset..ptr_offset + 8]
                    .try_into()
                    .expect("pointer"),
            )
        } else {
            u32::from_le_bytes(
                bytes[ptr_offset..ptr_offset + 4]
                    .try_into()
                    .expect("pointer"),
            ) as u64
        };
        let local = (ptr - buffer) as usize;
        let units: Vec<u16> = bytes[local..local + name_len]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&units).expect("utf16")
    };
    let name = read_string(0);
    let kind = read_string(header / 2);
    (status, vec![(name, kind)], context_after)
}

fn dispatch_nt_thunk(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: HostThunk,
    args: &[u64],
) -> i32 {
    dispatch_nt_thunk_on_thread(
        runtime,
        memory,
        thunk,
        args,
        STACK_BASE + STACK_SIZE - 0x100,
    )
}

fn dispatch_nt_thunk_on_thread(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: HostThunk,
    args: &[u64],
    stack_pointer: u64,
) -> i32 {
    let thunk_address = runtime.next_thunk_address;
    runtime.next_thunk_address += 0x10;
    runtime.host_thunks.insert(thunk_address, thunk);
    memory.map_bytes(STACK_BASE, &vec![0_u8; STACK_SIZE as usize]);
    let mut cpu = CpuState::new(runtime.guest_arch);
    cpu.set(Register::Rsp, stack_pointer);
    runtime
        .execute_guest_callback(&mut cpu, memory, thunk_address, args, "NtDispatch")
        .expect("guest thunk dispatch") as u32 as i32
}

fn with_big_stack<F: FnOnce() + Send + 'static>(body: F) {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(body)
        .expect("spawn test thread")
        .join()
        .expect("test thread");
}

#[test]
fn executes_driver_entry_for_real() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = build_test_driver(false, false, false);
        let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
            .expect("DriverEntry must execute");

        assert_eq!(island.status(), STATUS_SUCCESS);
        assert!(island.is_loaded());
        assert_eq!(island.driver_name(), "CasaDriver");
        assert!(island.registry_path().ends_with("\\Services\\CasaDriver"));
        assert_eq!(island.device_count(), 1);
        assert_eq!(island.casak_device_names(), vec!["CasaTest".to_string()]);

        let devices = island.created_devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "\\Device\\CasaTest");
        assert!(!devices[0].deleted);
        let device = devices[0].guest_pointer;
        assert_ne!(device, 0);

        let driver_object = island.driver_object_pointer();
        assert_eq!(memory.read_u16(driver_object).unwrap(), DRIVER_OBJECT_TYPE);
        assert_eq!(
            memory.read_u64(driver_object + 0x08).unwrap(),
            device,
            "DRIVER_OBJECT.DeviceObject points at the guest device"
        );
        assert_eq!(memory.read_u16(device).unwrap(), DEVICE_OBJECT_TYPE);
        assert_eq!(
            memory.read_u64(device + 0x08).unwrap(),
            driver_object,
            "DEVICE_OBJECT.DriverObject points back at the driver"
        );
        for index in 0..MAJOR_FUNCTION_COUNT {
            assert_ne!(
                memory
                    .read_u64(driver_object + 0x70 + index as u64 * 8)
                    .unwrap(),
                0,
                "MajorFunction[{index}] is populated"
            );
        }
        assert_eq!(
            memory
                .read_u32(island.image_base() + ENTRY_MARKER_RVA as u64)
                .unwrap(),
            0xCA5A_0001,
            "guest code executed its own store"
        );

        assert_eq!(
            island.dbg_print_log(),
            vec!["CasaTest DriverEntry\n".to_string()]
        );
        assert!(runtime.trace_events.iter().any(|event| {
            event.call_id == "DbgPrint"
                && event
                    .parameters
                    .get("message")
                    .and_then(|value| value.as_str())
                    == Some("CasaTest DriverEntry\n")
        }));
        assert_eq!(
            island.symbolic_links(),
            vec![(
                "\\??\\CasaTest".to_string(),
                "\\Device\\CasaTest".to_string()
            )]
        );
        let imports = island.imports();
        assert!(imports.unresolved.is_empty());
        assert_eq!(imports.resolved.len(), IMPORT_NAMES.len());
    });
}

#[test]
fn service_shims_allocate_irps_and_tagged_pool() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = build_test_driver(false, false, true);
        let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
            .expect("service-shim driver must execute");
        assert_eq!(island.status(), STATUS_SUCCESS);
        assert_eq!(
            island.completed_irp_count(),
            1,
            "IoAllocateIrp + IofCompleteRequest completed a CasaK IRP"
        );
        assert_eq!(
            island.pool_allocation_count(),
            1,
            "ExAllocatePoolWithTag allocated a tagged CasaK block"
        );
        assert_eq!(
            island.pool_free_count(),
            1,
            "ExFreePoolWithTag freed the tagged block"
        );
        assert_eq!(island.pool_used_bytes(), 0);
    });
}

#[test]
fn rejects_a_bad_image() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let error = match DriverIsland::load_and_start(b"not a driver", &mut runtime, &mut memory) {
            Ok(_) => panic!("a non-PE must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
    });
}

#[test]
fn reports_unresolved_imports_without_executing() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = build_test_driver(false, true, false);
        let error = match DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory) {
            Ok(_) => panic!("unresolved imports must reject the load"),
            Err(error) => error,
        };
        assert_eq!(error.code, ReasonCode::RcImportMissing);
        assert!(
            error.message.contains("PsGetCurrentProcess"),
            "error names the unresolved import: {}",
            error.message
        );
    });
}

#[test]
fn surfaces_driver_entry_failure_status() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = build_test_driver(true, false, false);
        let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
            .expect("the entry bytes execute even when they fail");
        assert_eq!(island.status(), STATUS_UNSUCCESSFUL);
        assert!(!island.is_loaded());
        assert_eq!(island.device_count(), 0);
        assert!(island.created_devices().is_empty());
        assert_eq!(
            memory
                .read_u32(island.image_base() + ENTRY_MARKER_RVA as u64)
                .unwrap(),
            0xCA5A_0001,
            "the failing entry still ran"
        );
    });
}

#[test]
fn directory_object_enumeration_matches_loaded_and_removed_island_devices() {
    with_big_stack(|| {
        let bytes = build_test_driver(false, false, false);
        let (mut runtime, _directory) =
            test_runtime_with_ge(|ge| stage_service(ge, "CasaDriver", DRIVER_IMAGE_PATH, &bytes));
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x48_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaDriver",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path]
            ),
            STATUS_SUCCESS
        );

        let (device_dir, status) =
            open_directory_object(&mut runtime, &mut memory, "\\Device", 0x40_000);
        assert_eq!(status, STATUS_SUCCESS);
        assert_ne!(device_dir, 0);

        let (out, status) =
            open_directory_object(&mut runtime, &mut memory, "\\Device\\", 0x4A_000);
        assert_eq!(status, STATUS_SUCCESS, "a trailing separator is accepted");
        assert_ne!(out, 0);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(out)]
            ),
            STATUS_SUCCESS
        );
        let (empty, status) = open_directory_object(&mut runtime, &mut memory, "", 0x49_000);
        assert_eq!(empty, 0);
        assert_eq!(status, 0xC000_0033_u32 as i32, "empty object name");
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtOpenDirectoryObject,
                &[0, 1, 0x49_000]
            ),
            0xC000_000D_u32 as i32,
            "a null output handle is invalid"
        );
        // A malformed OBJECT_ATTRIBUTES name (odd byte length) is
        // STATUS_OBJECT_NAME_INVALID.
        let bad_attrs = 0x4B_000u64;
        let bad_name = 0x4B_100u64;
        memory.map_bytes(bad_attrs, &[0u8; 48]);
        memory.map_bytes(bad_name, &[0u8; 16]);
        memory.write_u32(bad_attrs, 48);
        memory.write_u64(bad_attrs + 16, bad_name);
        memory.write_u16(bad_name, 3);
        memory.write_u16(bad_name + 2, 4);
        let bad_handle = 0x4B_200u64;
        memory.map_bytes(bad_handle, &[0u8; 8]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtOpenDirectoryObject,
                &[bad_handle, 1, bad_attrs]
            ),
            0xC000_0033_u32 as i32
        );
        let (status, entries, next) =
            query_directory_object(&mut runtime, &mut memory, device_dir, 0, 0x50_000, 0x400);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            entries,
            vec![("CasaTest".to_string(), "Device".to_string())],
            "the live device the island created is enumerated"
        );
        assert_eq!(next, 1, "the context advances past the returned entry");
        let (status, entries, _) =
            query_directory_object(&mut runtime, &mut memory, device_dir, next, 0x50_000, 0x400);
        assert_eq!(status, STATUS_NO_MORE_ENTRIES);
        assert!(entries.is_empty());

        // Invalid handle, missing context, null buffer and short output
        // are exact refusals.
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtQueryDirectoryObject,
                &[0x1234, 0x50_000, 0x400, 1, 0, 0x46_000, 0x46_100],
            ),
            0xC000_0008_u32 as i32
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtQueryDirectoryObject,
                &[u64::from(device_dir), 0x50_000, 0x400, 1, 0, 0, 0x46_100],
            ),
            0xC000_000D_u32 as i32
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtQueryDirectoryObject,
                &[u64::from(device_dir), 0, 0x400, 1, 0, 0x46_000, 0x46_100],
            ),
            0xC000_000D_u32 as i32
        );
        memory.map_bytes(0x46_000, &0_u32.to_le_bytes());
        memory.map_bytes(0x46_100, &[0_u8; 4]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtQueryDirectoryObject,
                &[
                    u64::from(device_dir),
                    0x50_000,
                    0x20,
                    1,
                    0,
                    0x46_000,
                    0x46_100
                ],
            ),
            0xC000_0023_u32 as i32,
            "a buffer too small for one entry is STATUS_BUFFER_TOO_SMALL"
        );
        assert_eq!(
            memory.read_u32(0x46_100).expect("required"),
            0x20 + "CasaTest".len() as u32 * 2 + "Device".len() as u32 * 2
        );
        // RestartScan ignores the context value and ignores a null
        // context pointer, restarting from the first entry.
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtQueryDirectoryObject,
                &[u64::from(device_dir), 0x50_000, 0x400, 1, 1, 0, 0x46_100],
            ),
            STATUS_SUCCESS
        );

        let (driver_dir, status) =
            open_directory_object(&mut runtime, &mut memory, "\\Driver", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let (status, entries, _) =
            query_directory_object(&mut runtime, &mut memory, driver_dir, 0, 0x50_000, 0x400);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            entries,
            vec![("CasaDriver".to_string(), "Driver".to_string())]
        );

        // The root object directory and the per-object subtrees are real
        // namespaces, not four flat roots.
        let (root_dir, status) = open_directory_object(&mut runtime, &mut memory, "\\", 0x4C_000);
        assert_eq!(status, STATUS_SUCCESS);
        let (status, entries, next) =
            query_directory_object(&mut runtime, &mut memory, root_dir, 0, 0x50_000, 0x400);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            entries,
            vec![("??".to_string(), "SymbolicLink".to_string())]
        );
        assert_eq!(next, 1);

        let (nested_device, status) =
            open_directory_object(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x4D_000);
        assert_eq!(status, STATUS_SUCCESS);
        let (status, entries, _) =
            query_directory_object(&mut runtime, &mut memory, nested_device, 0, 0x50_000, 0x400);
        assert_eq!(status, STATUS_NO_MORE_ENTRIES);
        assert!(entries.is_empty(), "the leaf device has no child objects");

        let (nested_driver, status) =
            open_directory_object(&mut runtime, &mut memory, "\\Driver\\casadriver", 0x4E_000);
        assert_eq!(status, STATUS_SUCCESS, "driver names are case-insensitive");
        let (status, entries, _) =
            query_directory_object(&mut runtime, &mut memory, nested_driver, 0, 0x50_000, 0x400);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            entries,
            vec![("CasaTest".to_string(), "Device".to_string())],
            "the per-driver subtree enumerates the live device it created"
        );

        // Nested misses keep the exact NAME/PATH distinction.
        let (_, status) = open_directory_object(
            &mut runtime,
            &mut memory,
            "\\Device\\CasaTest\\Missing",
            0x4F_000,
        );
        assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);
        let (_, status) = open_directory_object(
            &mut runtime,
            &mut memory,
            "\\Device\\Missing\\Child",
            0x4F_800,
        );
        assert_eq!(status, 0xC000_003A_u32 as i32);

        for directory in ["\\??", "\\GLOBAL??"] {
            let (handle, status) = match directory {
                "\\??" => open_directory_object(&mut runtime, &mut memory, directory, 0x42_000),
                _ => open_directory_object(&mut runtime, &mut memory, directory, 0x43_000),
            };
            assert_eq!(status, STATUS_SUCCESS);
            let (status, entries, _) =
                query_directory_object(&mut runtime, &mut memory, handle, 0, 0x50_000, 0x400);
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(
                entries,
                vec![("CasaTest".to_string(), "SymbolicLink".to_string())],
                "{directory} enumerates the island's real symbolic link"
            );
        }

        let (_, status) = open_directory_object(
            &mut runtime,
            &mut memory,
            "\\Device\\MissingDevice",
            0x44_000,
        );
        assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);
        let (_, status) =
            open_directory_object(&mut runtime, &mut memory, "\\Missing\\Child", 0x45_000);
        assert_eq!(status, 0xC000_003A_u32 as i32);

        // Unloading removes the devices and drivers from the live
        // namespace; the already-open \Device handle now enumerates
        // nothing (it is not a stale handle).
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path]
            ),
            STATUS_SUCCESS
        );
        let (status, entries, _) =
            query_directory_object(&mut runtime, &mut memory, device_dir, 0, 0x50_000, 0x400);
        assert_eq!(status, STATUS_NO_MORE_ENTRIES);
        assert!(entries.is_empty());
        let (status, entries, _) =
            query_directory_object(&mut runtime, &mut memory, nested_device, 0, 0x50_000, 0x400);
        assert_eq!(status, STATUS_NO_MORE_ENTRIES);
        assert!(entries.is_empty());

        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(device_dir)]
            ),
            STATUS_SUCCESS
        );
        let (status, _, _) =
            query_directory_object(&mut runtime, &mut memory, device_dir, 0, 0x50_000, 0x400);
        assert_eq!(status, 0xC000_0008_u32 as i32, "closed directory handle");
    });
}

#[test]
fn nested_directory_entries_track_live_children_and_reject_stale_paths() {
    let mut namespace = IslandNamespace {
        drivers: vec!["CasaDriver".to_string(), "Other".to_string()],
        devices: vec![
            "\\Device\\CasaTest".to_string(),
            "\\Device\\CasaTest\\Child".to_string(),
            "\\Device\\OtherDev".to_string(),
            "\\Device\\Tree\\Leaf".to_string(),
        ],
        device_drivers: vec![
            ("\\Device\\CasaTest".to_string(), "CasaDriver".to_string()),
            (
                "\\Device\\CasaTest\\Child".to_string(),
                "CasaDriver".to_string(),
            ),
            ("\\Device\\OtherDev".to_string(), "Other".to_string()),
        ],
        symbolic_links: vec![(
            "\\??\\CasaLink".to_string(),
            "\\Device\\CasaTest".to_string(),
        )],
    };

    assert_eq!(
        canonical_directory_name(&namespace, "\\").as_deref(),
        Some("\\")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\device\\casatest").as_deref(),
        Some("\\Device\\CasaTest")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Device\\CasaTest\\Child").as_deref(),
        Some("\\Device\\CasaTest\\Child")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Device\\CasaTest\\Missing"),
        None
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Driver\\casadriver").as_deref(),
        Some("\\Driver\\CasaDriver")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Driver\\Unknown"),
        None
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Device").as_deref(),
        Some("\\Device")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Device\\").as_deref(),
        Some("\\Device")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Driver").as_deref(),
        Some("\\Driver")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Driver\\").as_deref(),
        Some("\\Driver")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Global??").as_deref(),
        Some("\\GLOBAL??")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\??").as_deref(),
        Some("\\??")
    );
    assert_eq!(
        canonical_directory_name(&namespace, "\\Device\\Tree").as_deref(),
        Some("\\Device\\Tree")
    );
    assert_eq!(direct_child_name("\\Device", "\\Device\\"), None);
    assert_eq!(canonical_directory_name(&namespace, "\\Other"), None);

    assert_eq!(
        directory_entries(&namespace, "\\"),
        vec![
            ("??".to_string(), "SymbolicLink".to_string()),
            ("Device".to_string(), "Directory".to_string()),
            ("Driver".to_string(), "Directory".to_string()),
            ("GLOBAL??".to_string(), "Directory".to_string()),
        ]
    );
    assert_eq!(
        directory_entries(&namespace, "\\Device"),
        vec![
            ("CasaTest".to_string(), "Device".to_string()),
            ("OtherDev".to_string(), "Device".to_string()),
            ("Tree".to_string(), "Device".to_string()),
        ]
    );
    assert_eq!(
        directory_entries(&namespace, "\\Device\\CasaTest"),
        vec![("Child".to_string(), "Device".to_string())]
    );
    assert!(directory_entries(&namespace, "\\Device\\CasaTest\\Child").is_empty());
    assert_eq!(
        directory_entries(&namespace, "\\Driver\\CasaDriver"),
        vec![("CasaTest".to_string(), "Device".to_string())],
        "the per-driver subtree reports the direct device it created"
    );
    assert_eq!(
        directory_entries(&namespace, "\\Driver\\Other"),
        vec![("OtherDev".to_string(), "Device".to_string())]
    );

    // A device/child disappearance is visible on the next enumeration
    // and an emptied subtree stops resolving.
    namespace
        .devices
        .retain(|device| device != "\\Device\\CasaTest\\Child");
    namespace
        .device_drivers
        .retain(|(device, _)| device != "\\Device\\CasaTest\\Child");
    assert!(directory_entries(&namespace, "\\Device\\CasaTest").is_empty());
    namespace
        .devices
        .retain(|device| device != "\\Device\\CasaTest");
    namespace
        .device_drivers
        .retain(|(device, _)| device != "\\Device\\CasaTest");
    assert_eq!(
        canonical_directory_name(&namespace, "\\Device\\CasaTest"),
        None
    );
    assert_eq!(
        directory_entries(&namespace, "\\Driver\\CasaDriver"),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn double_load_and_unload_lifecycle() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = build_test_driver(false, false, false);
        let mut first =
            DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory).expect("first load");
        let mut second =
            DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory).expect("second load");
        assert_ne!(
            first.image_base(),
            second.image_base(),
            "each island gets its own guest image mapping"
        );
        assert_eq!(first.device_count(), 1);
        assert_eq!(second.device_count(), 1);

        assert_eq!(
            first
                .unload(&mut runtime, &mut memory)
                .expect("unload first"),
            Some(STATUS_SUCCESS)
        );
        assert!(!first.is_loaded());
        assert_eq!(first.device_count(), 0);
        assert!(first.casak_device_names().is_empty());
        assert!(first.created_devices()[0].deleted);
        assert_eq!(
            memory
                .read_u32(first.image_base() + UNLOAD_MARKER_RVA as u64)
                .unwrap(),
            0xCA5A_0002,
            "DriverUnload executed in the guest"
        );
        assert!(
            first
                .dbg_print_log()
                .iter()
                .any(|message| message.contains("DriverUnload"))
        );
        assert_eq!(
            first
                .unload(&mut runtime, &mut memory)
                .expect("repeat unload"),
            None,
            "a second unload does not execute DriverUnload again"
        );

        assert!(second.is_loaded());
        assert_eq!(second.device_count(), 1);
        assert_eq!(
            second
                .unload(&mut runtime, &mut memory)
                .expect("unload second"),
            Some(STATUS_SUCCESS)
        );
        assert_eq!(second.device_count(), 0);
    });
}

#[test]
fn driver_service_load_unload() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaNtSvc",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\REGISTRY\\MACHINE\\system\\currentcontrolset\\services\\CasaNtSvc",
        );

        // The production thunk mapping resolves the export name.
        assert_eq!(
            crate::runtime::registered_export_implementation_level("ntdll.dll", "NtLoadDriver"),
            ImplementationLevel::Implemented
        );
        assert_eq!(
            crate::runtime::registered_export_implementation_level("ntdll.dll", "NtUnloadDriver"),
            ImplementationLevel::Implemented
        );

        let load = dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtLoadDriver,
            &[service_path],
        );
        assert_eq!(load, STATUS_SUCCESS, "NtLoadDriver loads the service");

        let (image_base, created_devices) = with_loaded_driver(&runtime, "CasaNtSvc", |island| {
            assert_eq!(island.status(), STATUS_SUCCESS);
            assert!(island.is_loaded());
            assert_eq!(island.device_count(), 1);
            assert_eq!(island.casak_device_names(), vec!["CasaTest"]);
            assert_eq!(
                island.created_devices()[0].name,
                "\\Device\\CasaTest",
                "the guest device path is real"
            );
            assert_eq!(island.symbolic_links().len(), 1);
            assert!(
                island
                    .dbg_print_log()
                    .iter()
                    .any(|message| message.contains("CasaTest DriverEntry")),
                "the guest DriverEntry must have run: {:?}",
                island.dbg_print_log()
            );
            (island.image_base(), island.created_devices().len())
        })
        .expect("the service is registered after a successful load");
        assert_eq!(created_devices, 1);
        assert_eq!(
            memory
                .read_u32(image_base + ENTRY_MARKER_RVA as u64)
                .unwrap(),
            0xCA5A_0001,
            "DriverEntry executed in the guest"
        );

        let duplicate = dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtLoadDriver,
            &[service_path],
        );
        assert_eq!(duplicate, STATUS_IMAGE_ALREADY_LOADED);
        assert_eq!(duplicate as u32, 0xC000_010E);

        let unload = dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtUnloadDriver,
            &[service_path],
        );
        assert_eq!(unload, STATUS_SUCCESS, "NtUnloadDriver unloads the service");
        let unloaded = take_last_unloaded_driver().expect("unloaded island retained for evidence");
        assert!(!unloaded.is_loaded());
        assert_eq!(unloaded.device_count(), 0);
        assert!(unloaded.casak_device_names().is_empty());
        assert!(unloaded.created_devices()[0].deleted);
        assert!(unloaded.symbolic_links().is_empty());
        assert!(
            unloaded
                .dbg_print_log()
                .iter()
                .any(|message| message.contains("CasaTest DriverUnload")),
            "the guest DriverUnload must have run: {:?}",
            unloaded.dbg_print_log()
        );
        assert_eq!(
            memory
                .read_u32(image_base + UNLOAD_MARKER_RVA as u64)
                .unwrap(),
            0xCA5A_0002,
            "DriverUnload executed in the guest"
        );
        assert!(
            with_loaded_driver(&runtime, "CasaNtSvc", |_| ()).is_none(),
            "the registration is forgotten after unload"
        );

        let second_unload = dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtUnloadDriver,
            &[service_path],
        );
        assert_eq!(second_unload, STATUS_OBJECT_NAME_NOT_FOUND);
    });
}

#[test]
fn driver_service_load_rejects_missing_registry_value_and_file() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            ge.registry_create_key(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\CasaNoValue",
                RegistryView::Native,
            )
            .expect("create value-less service key");
            ge.registry_create_key(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\CasaNoFile",
                RegistryView::Native,
            )
            .expect("create file-less service key");
            ge.registry_set_value(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\CasaNoFile",
                "ImagePath",
                "REG_SZ",
                json!("C:\\Windows\\System32\\drivers\\missing.sys"),
                RegistryView::Native,
            )
            .expect("write ImagePath");
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);

        let missing_key = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaMissing",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[missing_key],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND,
            "a missing service key"
        );

        let missing_value = guest_unicode_string(
            &mut memory,
            0x41_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaNoValue",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[missing_value],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND,
            "a service without ImagePath"
        );

        let missing_file = guest_unicode_string(
            &mut memory,
            0x42_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaNoFile",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[missing_file],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND,
            "an ImagePath that names no readable file"
        );

        assert_eq!(
            dispatch_nt_thunk(&mut runtime, &mut memory, HostThunk::NtLoadDriver, &[0],),
            STATUS_INVALID_PARAMETER,
            "a null PUNICODE_STRING"
        );

        // Structurally invalid descriptor: odd Length.
        memory.map_bytes(0x43_000, &[0_u8; 16]);
        memory.write_u16(0x43_000, 3);
        memory.write_u64(0x43_008, 0x44_000);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[0x43_000],
            ),
            STATUS_INVALID_PARAMETER,
            "an odd-length UNICODE_STRING"
        );
    });
}

#[test]
fn pe32_driver_entry_executes_and_creates_a_device() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime_x86();
        let mut memory = MemoryImage::default();
        let bytes = build_pe32_driver();
        let island =
            DriverIsland::load_and_start_named(&bytes, "CasaPe32", &mut runtime, &mut memory)
                .expect("PE32 DriverEntry must execute through the x86 guest");
        assert_eq!(island.status(), STATUS_SUCCESS);
        assert!(island.is_loaded());
        assert_eq!(island.device_count(), 1);
        assert_eq!(island.casak_device_names(), vec!["Casa32".to_string()]);
        assert_eq!(
            memory.read_u32(island.image_base() + 0x3014).unwrap(),
            0xCA5A_0005,
            "the x86 DriverEntry bytes executed"
        );
        assert_ne!(
            memory.read_u32(island.image_base() + 0x3010).unwrap(),
            0,
            "IoCreateDevice returned a real guest PDEVICE_OBJECT"
        );
        let driver_object = island.driver_object_pointer();
        assert_eq!(memory.read_u16(driver_object).unwrap(), DRIVER_OBJECT_TYPE);
        assert_eq!(
            memory.read_u32(driver_object + 0x70).unwrap(),
            0x1000_1200,
            "DEVICE_CONTROL major function was installed by the guest"
        );
    });
}

#[test]
fn pe32_mismatched_machine_is_rejected() {
    with_big_stack(|| {
        let mut bytes = build_pe32_driver();
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        let (mut runtime, _directory) = test_runtime_x86();
        let mut memory = MemoryImage::default();
        let error = match DriverIsland::load_and_start_named(
            &bytes,
            "CasaPe32Bad",
            &mut runtime,
            &mut memory,
        ) {
            Ok(_) => panic!("machine/optional-header mismatch must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
    });
}

#[test]
fn delay_imports_are_resolved_eagerly_and_unresolved_ones_reject() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = with_delay_import(build_test_driver(false, false, false), "DbgPrint");
        let island =
            DriverIsland::load_and_start_named(&bytes, "CasaDelay", &mut runtime, &mut memory)
                .expect("delay imports must resolve at load");
        assert!(
            island
                .imports()
                .resolved
                .iter()
                .any(|(dll, symbol, _)| dll == "ntoskrnl.exe" && symbol == "DbgPrint"),
            "the delay import is reported as resolved"
        );
        assert_ne!(
            memory.read_u64(island.image_base() + 0x2570).unwrap(),
            0,
            "the delay IAT was patched with the kernel shim"
        );

        let unresolved = with_delay_import(
            build_test_driver(false, false, false),
            "PsGetCurrentProcess",
        );
        let error = match DriverIsland::load_and_start_named(
            &unresolved,
            "CasaDelayBad",
            &mut runtime,
            &mut memory,
        ) {
            Ok(_) => panic!("an unresolved delay import must reject the load"),
            Err(error) => error,
        };
        assert_eq!(error.code, ReasonCode::RcImportMissing);
        assert!(error.message.contains("PsGetCurrentProcess"));
    });
}

#[test]
fn guest_ioctl_read_and_write_dispatch_real_irps() {
    with_big_stack(|| {
        let image = build_io_driver();
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaIo",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaIo",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );

        let (devices, names) = with_loaded_driver(&runtime, "CasaIo", |island| {
            (island.device_count(), island.casak_device_names())
        })
        .expect("loaded");
        assert_eq!(devices, 1, "DriverEntry created the device: {names:?}");
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        assert_ne!(handle, 0);

        let input = 0x51_000;
        let output = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        let status = dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtDeviceIoControlFile,
            &[
                u64::from(handle),
                0,
                0,
                0,
                iosb,
                0x22_0004,
                input,
                4,
                output,
                8,
            ],
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RESP");
        let image_base =
            with_loaded_driver(&runtime, "CasaIo", |island| island.image_base()).expect("loaded");
        assert_eq!(
            memory.read_u32(image_base + 0x3140).unwrap(),
            0xCA5A_0004,
            "the driver's real DEVICE_CONTROL code ran"
        );

        memory.map_bytes(output, &[0_u8; 8]);
        let status = dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtReadFile,
            &[u64::from(handle), 0, 0, 0, iosb, output, 8, 0, 0],
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RESP");

        memory.map_bytes(input, b"DATA");
        memory.map_bytes(iosb, &[0_u8; 24]);
        let status = dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtWriteFile,
            &[u64::from(handle), 0, 0, 0, iosb, input, 4, 0, 0],
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
        assert_eq!(memory.read_u32(image_base + 0x3140).unwrap(), 0xCA5A_0004);

        // A handle outside the island namespace is an invalid handle.
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[0xDEAD, 0, 0, 0, iosb, 0x22_0004, input, 4, output, 8],
            ),
            STATUS_INVALID_HANDLE
        );
        // A missing device path is not opened.
        let (missing, missing_status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\Missing", 0x45_000);
        assert_eq!(missing, 0);
        assert_eq!(missing_status, STATUS_OBJECT_NAME_NOT_FOUND);
        // An invalid output buffer is rejected before the driver runs.
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x22_0004,
                    input,
                    4,
                    0xDEAD_0000,
                    4,
                ],
            ),
            STATUS_INVALID_PARAMETER
        );
        // Unloading with an open island handle is refused.
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_DEVICE_BUSY
        );
        assert!(with_loaded_driver(&runtime, "CasaIo", |_| ()).is_some());
    });
}

#[test]
fn irp_without_a_handler_fails_with_invalid_device_request() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaNoHandler",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaNoHandler",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let iosb = 0x53_000;
        let buffer = 0x54_000;
        memory.map_bytes(iosb, &[0_u8; 24]);
        memory.map_bytes(buffer, &[0_u8; 8]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtReadFile,
                &[u64::from(handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
            ),
            STATUS_INVALID_DEVICE_REQUEST
        );
    });
}

#[test]
fn pe32_device_ioctl_dispatches_through_x86_irp() {
    with_big_stack(|| {
        let image = build_pe32_driver();
        let (mut runtime, _directory) = test_runtime_x86_with_ge(|ge| {
            stage_service(
                ge,
                "CasaPe32Svc",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string_x86(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaPe32Svc",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\Casa32", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        assert_ne!(handle, 0);

        let input = 0x51_000;
        let output = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x22_0004,
                    input,
                    4,
                    output,
                    8
                ],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(iosb + 4).unwrap(), 4);
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RESP");
        let image_base = with_loaded_driver(&runtime, "CasaPe32Svc", |island| island.image_base())
            .expect("loaded");
        assert_eq!(
            memory.read_u32(image_base + 0x3014).unwrap(),
            0xCA5A_0006,
            "the PE32 DEVICE_CONTROL handler ran"
        );
    });
}

#[test]
fn nt_load_expands_environment_honors_start_type_and_traces() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            let key = "SYSTEM\\CurrentControlSet\\Services\\CasaEnv";
            ge.registry_create_key("HKLM", key, RegistryView::Native)
                .expect("create service key");
            ge.registry_set_value(
                "HKLM",
                key,
                "ImagePath",
                "REG_EXPAND_SZ",
                json!("%CASA_DRIVER_DIR%\\casa_nt.sys"),
                RegistryView::Native,
            )
            .expect("write ImagePath");
            ge.registry_set_value(
                "HKLM",
                key,
                "StartType",
                "REG_DWORD",
                json!(SERVICE_DEMAND_START),
                RegistryView::Native,
            )
            .expect("write StartType");
            let disabled = "SYSTEM\\CurrentControlSet\\Services\\CasaDisabled";
            ge.registry_create_key("HKLM", disabled, RegistryView::Native)
                .expect("create disabled key");
            ge.registry_set_value(
                "HKLM",
                disabled,
                "ImagePath",
                "REG_SZ",
                json!("C:\\Windows\\System32\\drivers\\casa_nt.sys"),
                RegistryView::Native,
            )
            .expect("write disabled ImagePath");
            ge.registry_set_value(
                "HKLM",
                disabled,
                "StartType",
                "REG_DWORD",
                json!(SERVICE_DISABLED),
                RegistryView::Native,
            )
            .expect("write disabled StartType");
            ge.create_directory("C:\\Windows\\System32\\drivers", true)
                .expect("create driver directory");
            ge.write_file(DRIVER_IMAGE_PATH, &image, true)
                .expect("write driver image");
        });
        runtime.process_environment.insert(
            "CASA_DRIVER_DIR".to_string(),
            "C:\\Windows\\System32\\drivers".to_string(),
        );
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaEnv",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS,
            "%%ENV%% in ImagePath expands from the GE environment"
        );
        assert!(runtime.trace_events.iter().any(|event| {
            event.category == "driver"
                && event.call_id == "NtLoadDriver"
                && event
                    .parameters
                    .get("status")
                    .and_then(|value| value.as_str())
                    == Some("0x00000000")
        }));
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        assert!(
            runtime
                .trace_events
                .iter()
                .any(|event| { event.category == "driver" && event.call_id == "NtUnloadDriver" })
        );

        let disabled = guest_unicode_string(
            &mut memory,
            0x42_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaDisabled",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[disabled],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND,
            "SERVICE_DISABLED services are not started"
        );
    });
}

#[test]
fn kmdf_device_add_and_ioctl_complete_through_guest_callbacks() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdf",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdf",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS,
            "WdfDriverCreate must drive EvtDriverDeviceAdd"
        );
        let image_base = with_loaded_driver(&runtime, "CasaKmdf", |island| {
            assert_eq!(island.status(), STATUS_SUCCESS);
            assert_eq!(island.device_count(), 1);
            assert_eq!(island.casak_device_names(), vec!["WdfCasa"]);
            let state = island.inner.borrow();
            assert_ne!(state.kmdf.driver_handle, 0, "real WDFDRIVER object");
            assert_eq!(state.kmdf.devices.len(), 1, "real WDFDEVICE object");
            assert_eq!(state.kmdf.queues.len(), 1, "real WDFQUEUE object");
            assert_eq!(state.kmdf.wait_locks.len(), 1, "real wait lock");
            assert!(
                state.kmdf.requests.is_empty(),
                "WdfRequestCreate built a real CasaK IRP that WdfObjectDelete removed"
            );
            let device = state.kmdf.devices.values().next().expect("device");
            assert_eq!(
                memory.read_u32(device.context_guest).unwrap(),
                0xC0DE,
                "WdfObjectGetTypedContext returned writable context storage"
            );
            drop(state);
            assert_eq!(
                memory
                    .read_u32(island.image_base() + u64::from(K_MARKER_RVA))
                    .unwrap(),
                0xCA5A_0010,
                "the guest EvtDriverDeviceAdd code ran"
            );
            assert_eq!(
                memory
                    .read_u32(island.image_base() + u64::from(K_DELETE_MARKER_RVA))
                    .unwrap(),
                0xCA5A_0012,
                "WdfObjectDelete ran in the guest callback"
            );
            assert_ne!(
                memory
                    .read_u64(island.image_base() + u64::from(K_DEVOBJ_OUT_RVA))
                    .unwrap(),
                0,
                "WdfDeviceWdmGetDeviceObject returned the real PDEVICE_OBJECT"
            );
            island.image_base()
        })
        .expect("loaded");

        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        assert_ne!(handle, 0);
        let input = 0x51_000;
        let output = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x0022_0004,
                    input,
                    4,
                    output,
                    8,
                ],
            ),
            STATUS_SUCCESS,
            "the framework queue delivered the ioctl to EvtIoDeviceControl"
        );
        assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"WDF!");
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(K_IOCTL_MARKER_RVA))
                .unwrap(),
            0x0022_0004,
            "the guest EvtIoDeviceControl code ran"
        );
        with_loaded_driver(&runtime, "CasaKmdf", |island| {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.ioctl_dispatches, 1);
            assert_eq!(state.kmdf.requests.len(), 1, "framework request only");
            assert!(
                state
                    .kmdf
                    .requests
                    .values()
                    .any(|request| request.completed)
            );
        })
        .expect("loaded");

        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_DEVICE_BUSY,
            "the open island handle keeps the KMDF driver busy"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS,
            "closing the handle allows unload"
        );
    });
}

#[test]
fn kmdf_ioctl_without_a_queue_fails_with_invalid_device_request() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfNoQueue",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfNoQueue",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let iosb = 0x53_000;
        let output = 0x52_000;
        memory.map_bytes(iosb, &[0_u8; 24]);
        memory.map_bytes(output, &[0_u8; 8]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[u64::from(handle), 0, 0, 0, iosb, 0x22_0004, 0, 0, output, 8],
            ),
            STATUS_INVALID_DEVICE_REQUEST,
            "an ioctl with no queue must not reach a callback"
        );
        assert!(crate::driver_island::close_island_device_handle(
            &runtime, handle
        ));
    });
}

#[test]
fn kmdf_missing_framework_symbol_rejects_the_image() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = build_kmdf_driver(true, true, false);
        let error = match DriverIsland::load_and_start_named(
            &bytes,
            "CasaKmdfBad",
            &mut runtime,
            &mut memory,
        ) {
            Ok(_) => panic!("a missing WDF symbol must reject the load"),
            Err(error) => error,
        };
        assert_eq!(error.code, ReasonCode::RcImportMissing);
        assert!(
            error.message.contains("WdfDriverCreatX"),
            "{}",
            error.message
        );
    });
}

#[test]
fn kmdf_bad_device_add_callback_is_rejected() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let bytes = build_kmdf_driver(true, false, true);
        let island = DriverIsland::load_and_start_named(
            &bytes,
            "CasaKmdfBadCallback",
            &mut runtime,
            &mut memory,
        )
        .expect("the entry bytes execute");
        assert_eq!(island.status(), STATUS_INVALID_PARAMETER);
        assert!(!island.is_loaded());
        assert_eq!(island.device_count(), 0);
    });
}

#[test]
fn island_handle_close_and_double_close_are_accounted() {
    with_big_stack(|| {
        let image = build_io_driver();
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaClose",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaClose",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_DEVICE_BUSY
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS,
            "NtClose releases an island handle"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_INVALID_HANDLE,
            "double close is rejected"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS,
            "unload succeeds after the handle is closed"
        );
    });
}

#[test]
fn close_handle_releases_an_island_handle() {
    with_big_stack(|| {
        let image = build_io_driver();
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaCloseHandle",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaCloseHandle",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\CasaTest", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        assert_ne!(handle, 0);
        assert!(
            crate::driver_island::is_island_device_handle(&runtime, handle),
            "NtCreateFile minted an island handle"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::CloseHandle,
                &[u64::from(handle)],
            ),
            1
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
    });
}

fn claim_island(runtime: &PeHostRuntime, service: &str) -> DriverIsland {
    with_loaded_driver(runtime, service, |island| DriverIsland {
        inner: island.inner.clone(),
    })
    .expect("driver island loaded")
}

fn queue_for_device(island: &DriverIsland, device: u64) -> u64 {
    island
        .inner
        .borrow()
        .kmdf
        .queues
        .iter()
        .find(|(_, queue)| queue.device == device && queue.default_queue)
        .map(|(handle, _)| *handle)
        .expect("default queue")
}

fn pending_request(island: &DriverIsland) -> u64 {
    island
        .inner
        .borrow()
        .kmdf
        .requests
        .iter()
        .find(|(_, request)| !request.completed)
        .map(|(handle, _)| *handle)
        .expect("pending request")
}

fn write_descriptor(memory: &mut MemoryImage, address: u64, pointer: u64, length: u64) {
    memory.map_bytes(address, &[0_u8; 0x20]);
    memory.write_u32(address, 0);
    memory.write_u64(address + 8, pointer);
    memory.write_u64(address + 0x10, length);
}

#[test]
fn kmdf_full_config_parses_and_invokes_evt_driver_unload() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfConfig",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfConfig",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfConfig");
        assert_eq!(island.device_count(), 2);
        let names = island.casak_device_names();
        assert!(names.iter().any(|name| name == "WdfA"), "{names:?}");
        assert!(names.iter().any(|name| name == "WdfB"), "{names:?}");
        let image_base = island.image_base();
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
            assert_eq!(state.kmdf.driver_init_flags, 0);
            assert_ne!(state.kmdf.evt_driver_unload, 0);
            assert_eq!(state.kmdf.devices.len(), 2);
            assert_eq!(state.kmdf.queues.len(), 2);
            for device in state.kmdf.devices.values() {
                assert_eq!(
                    state
                        .kmdf
                        .objects
                        .get(&device.context_guest.saturating_sub(0x80))
                        .map(|object| object.context_size),
                    Some(0x30),
                    "requested context size is honored"
                );
            }
        }
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_ADD_COUNT))
                .unwrap(),
            1,
            "EvtDriverDeviceAdd ran"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let unloaded = take_last_unloaded_driver().expect("unloaded island");
        assert_eq!(unloaded.inner.borrow().kmdf.driver_unload_calls, 1);
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_UNLOAD_MARKER))
                .unwrap(),
            0xCA5A_0200,
            "WDF_DRIVER_CONFIG.EvtDriverUnload executed"
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_UNLOAD_COUNT))
                .unwrap(),
            1
        );
    });
}

#[test]
fn kmdf_framework_dispatches_read_write_cleanup_close_and_ioctl() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfDispatch",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfDispatch",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfDispatch");
        let image_base = island.image_base();
        let device_guest = island
            .created_devices()
            .into_iter()
            .find(|device| device.name.ends_with("WdfA"))
            .map(|device| device.guest_pointer)
            .expect("device A");
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let input = 0x51_000;
        let output = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x0022_0004,
                    input,
                    4,
                    output,
                    8,
                ],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"KMDF");
        assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_IOCTL_MARKER))
                .unwrap(),
            0x0022_0004
        );
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtReadFile,
                &[u64::from(handle), 0, 0, 0, iosb, output, 8, 0, 0],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"RD01");
        assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
        memory.map_bytes(input, b"DATA");
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtWriteFile,
                &[u64::from(handle), 0, 0, 0, iosb, input, 4, 0, 0],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(iosb + 8).unwrap(), 4);
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_WRITE_MARKER))
                .unwrap(),
            0x41544144
        );
        let (cleanup_status, _) = island
            .dispatch_irp(
                &mut runtime,
                &mut memory,
                device_guest,
                IrpMajorFunction::Cleanup,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("cleanup dispatch");
        assert_eq!(cleanup_status, STATUS_SUCCESS);
        let (close_status, _) = island
            .dispatch_irp(
                &mut runtime,
                &mut memory,
                device_guest,
                IrpMajorFunction::Close,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("close dispatch");
        assert_eq!(close_status, STATUS_SUCCESS);
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.ioctl_dispatches, 1);
            assert_eq!(state.kmdf.read_dispatches, 1);
            assert_eq!(state.kmdf.write_dispatches, 1);
            assert_eq!(state.kmdf.cleanup_dispatches, 1);
            assert_eq!(state.kmdf.close_dispatches, 1);
        }
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_DEFAULT_COUNT))
                .unwrap(),
            2
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS
        );
    });
}

#[test]
fn kmdf_manual_queue_retrieve_and_cancel_callbacks() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(2, true);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfManual",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfManual",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfManual");
        let image_base = island.image_base();
        let device = island.kmdf_device_handles()[0];
        let queue = queue_for_device(&island, device);
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let input = 0x51_000;
        let output = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        for _ in 0..2 {
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING,
                "manual queues defer delivery"
            );
        }
        let requests = island
            .inner
            .borrow()
            .kmdf
            .requests
            .iter()
            .filter(|(_, request)| !request.completed)
            .map(|(handle, _)| *handle)
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        let found_out = 0x54_000;
        memory.map_bytes(found_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveFoundRequest,
                    &[queue, requests[1], found_out],
                )
                .expect("retrieve found") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u64(found_out).unwrap(), requests[1]);
        let next_out = 0x54_100;
        memory.map_bytes(next_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveNextRequest,
                    &[queue, next_out],
                )
                .expect("retrieve next") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u64(next_out).unwrap(), requests[0]);
        for request in requests {
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCompleteWithInformation,
                        &[request, STATUS_SUCCESS as u64, 4],
                    )
                    .expect("complete") as u32 as i32,
                STATUS_SUCCESS
            );
            let (completed, status, information, outer) =
                island.kmdf_request_state(request).unwrap();
            assert!(completed);
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(information, 4);
            assert_eq!(memory.read_u64(outer + 0x40).unwrap(), 4);
        }
        // Queue one more request and cancel it: the queue's
        // EvtIoCanceledOnQueue callback completes it with STATUS_CANCELLED.
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x0022_0004,
                    input,
                    4,
                    output,
                    8,
                ],
            ),
            STATUS_PENDING
        );
        let cancel_request = pending_request(&island);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[cancel_request],
                )
                .expect("cancel queued") as u32 as i32,
            STATUS_SUCCESS
        );
        let (completed, status, _, outer) =
            island.kmdf_request_state(cancel_request).expect("request");
        assert!(completed);
        assert_eq!(status, STATUS_CANCELLED);
        assert_ne!(outer, 0);
        assert_eq!(
            memory.read_u32(outer + 0x30).unwrap(),
            STATUS_CANCELLED as u32
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.manual_retrievals, 2);
            assert_eq!(state.kmdf.cancel_dispatches, 1);
        }
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_CANCEL_COUNT))
                .unwrap(),
            1
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS
        );
    });
}

#[test]
fn kmdf_queue_stop_resume_and_sequential_dispatch() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfQueue",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfQueue",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfQueue");
        let image_base = island.image_base();
        let device = island.kmdf_device_handles()[0];
        let queue = queue_for_device(&island, device);
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStopSynchronously,
                    &[queue],
                )
                .expect("stop") as u32 as i32,
            STATUS_SUCCESS
        );
        let input = 0x51_000;
        let output = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        for _ in 0..2 {
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING,
                "a stopped queue does not deliver"
            );
        }
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStopSynchronously,
                    &[queue],
                )
                .expect("stop queued") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_STOP_COUNT))
                .unwrap(),
            2,
            "EvtIoStop observed both queued requests"
        );
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueStart,
                    &[queue],
                )
                .expect("start") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_RESUME_COUNT))
                .unwrap(),
            2
        );
        {
            let state = island.inner.borrow();
            assert_eq!(
                memory
                    .read_u32(image_base + u64::from(F_IOCTL_COUNT))
                    .unwrap(),
                2,
                "sequential dispatch delivered both queued requests (ioctl_disp={}, queued_disp={}, queues={:?}, reqs={:?})",
                state.kmdf.ioctl_dispatches,
                state.kmdf.queued_dispatches,
                state.kmdf.queues,
                state
                    .kmdf
                    .requests
                    .values()
                    .map(|request| (request.completed, request.status))
                    .collect::<Vec<_>>()
            );
            assert_eq!(state.kmdf.ioctl_dispatches, 2);
            let queue = state.kmdf.queues.get(&queue).expect("queue");
            assert!(queue.queued.is_empty());
            assert!(queue.in_flight.is_empty());
            assert!(!queue.stopped);
            assert!(
                state
                    .kmdf
                    .requests
                    .values()
                    .all(|request| request.completed)
            );
        }
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS
        );
    });
}

#[test]
fn kmdf_iotarget_sends_ioctl_to_another_device() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfTarget",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfTarget",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfTarget");
        let image_base = island.image_base();
        let device_a = island
            .inner
            .borrow()
            .kmdf
            .devices
            .iter()
            .find(|(_, device)| device.name.ends_with("WdfA"))
            .map(|(handle, _)| *handle)
            .expect("device A");
        let device_b = island
            .inner
            .borrow()
            .kmdf
            .devices
            .iter()
            .find(|(_, device)| device.name.ends_with("WdfB"))
            .map(|(handle, _)| *handle)
            .expect("device B");
        let target_a = island
            .call_shim_for_test(
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceGetIoTarget,
                &[device_a],
            )
            .expect("get target");
        assert_ne!(target_a, 0);
        let target_b_out = 0x54_000;
        memory.map_bytes(target_b_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[device_b, 0, target_b_out],
                )
                .expect("create target") as u32 as i32,
            STATUS_SUCCESS
        );
        let target_b = memory.read_u64(target_b_out).unwrap();
        assert_ne!(target_b, target_a);
        let input = 0x56_000;
        let output = 0x56_100;
        let bytes_returned = 0x56_200;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(bytes_returned, &[0_u8; 8]);
        let input_descriptor = 0x55_000;
        let output_descriptor = 0x55_020;
        write_descriptor(&mut memory, input_descriptor, input, 4);
        write_descriptor(&mut memory, output_descriptor, output, 8);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetSendIoctlSynchronously,
                    &[
                        target_b,
                        0,
                        0x0022_0004,
                        input_descriptor,
                        output_descriptor,
                        0,
                        bytes_returned,
                    ],
                )
                .expect("send ioctl") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"KMDF");
        assert_eq!(memory.read_u64(bytes_returned).unwrap(), 4);
        // The formatted-request + WdfRequestSend path completes a real
        // WDFREQUEST against device B.
        let request_out = 0x54_100;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, target_b, request_out],
                )
                .expect("create request") as u32 as i32,
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetFormatRequestForIoctl,
                    &[
                        target_b,
                        request,
                        0x0022_0004,
                        input_descriptor,
                        0,
                        output_descriptor,
                        0,
                    ],
                )
                .expect("format request") as u32 as i32,
            STATUS_SUCCESS
        );
        memory.map_bytes(output, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[request, target_b, 0],
                )
                .expect("send request") as u32 as i32,
            STATUS_SUCCESS
        );
        let (completed, status, information, _) =
            island.kmdf_request_state(request).expect("request");
        assert!(completed);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(information, 4);
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"KMDF");
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.iotarget_sends, 2);
            assert_eq!(state.kmdf.iotargets.len(), 2);
        }
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_IOCTL_COUNT))
                .unwrap(),
            2
        );
    });
}

#[test]
fn kmdf_wait_lock_blocks_with_timeout_and_wakes_waiters() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfLock",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfLock",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfLock");
        let lock = island.kmdf_wait_lock_handles()[0];
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, 0],
                )
                .expect("acquire") as u32 as i32,
            STATUS_SUCCESS
        );
        let gate = island.kmdf_wait_lock_gate(lock).expect("gate");
        let releaser = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                let (mutex, wake) = &*gate;
                let mut locked = mutex.lock().unwrap();
                *locked = false;
                drop(locked);
                wake.notify_all();
            })
        };
        let timeout = 0x54_000;
        memory.map_bytes(timeout, &[0_u8; 8]);
        memory.write_u64(timeout, (-20_000_000_i64) as u64);
        let started = std::time::Instant::now();
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, timeout],
                )
                .expect("blocking acquire") as u32 as i32,
            STATUS_SUCCESS
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(20),
            "acquire parked the guest for {elapsed:?}"
        );
        releaser.join().expect("releaser");
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockRelease,
                    &[lock],
                )
                .expect("release") as u32 as i32,
            STATUS_SUCCESS
        );
        // A held lock with a relative 100 microsecond timeout returns
        // STATUS_TIMEOUT and leaves the lock held.
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, 0],
                )
                .expect("acquire again") as u32 as i32,
            STATUS_SUCCESS
        );
        memory.write_u64(timeout, (-1_000_i64) as u64);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, timeout],
                )
                .expect("timeout acquire") as u32 as i32,
            STATUS_TIMEOUT
        );
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockRelease,
                    &[lock],
                )
                .expect("final release") as u32 as i32,
            STATUS_SUCCESS
        );
        // Adversarial: four independent waiters serialize on the same
        // gate; the shared state must never observe two owners at once.
        let gate = island.kmdf_wait_lock_gate(lock).expect("gate");
        let mut held = {
            let (mutex, _) = &*gate;
            let mut guard = mutex.lock().unwrap();
            *guard = true;
            guard
        };
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut waiters = Vec::new();
        for _ in 0..4 {
            let gate = gate.clone();
            let active = active.clone();
            let peak = peak.clone();
            waiters.push(std::thread::spawn(move || {
                let (mutex, wake) = &*gate;
                let mut locked = mutex.lock().unwrap();
                while *locked {
                    locked = wake.wait(locked).unwrap();
                }
                *locked = true;
                let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(2));
                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                *locked = false;
                drop(locked);
                wake.notify_all();
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        *held = false;
        drop(held);
        let (_, wake) = &*gate;
        wake.notify_all();
        for waiter in waiters {
            waiter.join().expect("waiter");
        }
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
    });
}

#[test]
fn kmdf_object_contexts_attributes_and_cascade_deletion() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfObjects",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfObjects",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfObjects");
        let image_base = island.image_base();
        let driver = island.kmdf_driver_handle();
        let devices = island.kmdf_device_handles();
        let device = devices[0];
        let queue = queue_for_device(&island, device);
        assert_eq!(island.kmdf_context_size(device), Some(0x30));
        let context = island.kmdf_typed_context(device).expect("context");
        memory.write_u32(context, 0x00C0_FFEE);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectGetTypedContext,
                    &[device, 1],
                )
                .expect("typed context")
                .saturating_sub(context),
            0
        );
        let type_info = 0x54_000;
        let context_out = 0x54_010;
        memory.map_bytes(type_info, &[0_u8; 0x20]);
        memory.map_bytes(context_out, &[0_u8; 8]);
        memory.write_u32(type_info, 0x18);
        memory.write_u64(type_info + 0x10, 0x40);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectAllocateContext,
                    &[device, type_info, context_out],
                )
                .expect("allocate context") as u32 as i32,
            STATUS_SUCCESS
        );
        let extra = memory.read_u64(context_out).unwrap();
        assert_ne!(extra, context);
        memory.write_u32(extra + 0x30, 0x1234_5678);
        assert_eq!(memory.read_u32(extra + 0x30).unwrap(), 0x1234_5678);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[queue],
                )
                .expect("delete queue") as u32 as i32,
            STATUS_SUCCESS
        );
        assert!(island.inner.borrow().kmdf.queues.get(&queue).is_none());
        assert_eq!(island.kmdf_device_handles().len(), 2);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[driver],
                )
                .expect("delete driver") as u32 as i32,
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(state.kmdf.devices.is_empty());
            assert!(state.kmdf.queues.is_empty());
        }
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_UNLOAD_MARKER))
                .unwrap(),
            0xCA5A_0200
        );
        assert!(
            memory
                .read_u32(image_base + u64::from(F_CLEANUP_COUNT))
                .unwrap()
                >= 3
        );
        assert!(
            memory
                .read_u32(image_base + u64::from(F_DESTROY_COUNT))
                .unwrap()
                >= 3
        );
    });
}

#[test]
fn kmdf_driver_config_flags_disable_dispatch_override() {
    with_big_stack(|| {
        let mut image = build_kmdf_full_driver(0, true);
        put_u32(&mut image, 0x1000 + 0x1C, 2);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfFlags",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfFlags",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfFlags");
        let state = island.inner.borrow();
        assert_eq!(state.kmdf.driver_init_flags, 2);
        assert!(state.kmdf.framework_dispatches.is_empty());
        assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
    });
}

#[test]
fn kmdf_pe32_driver_executes_and_unloads() {
    with_big_stack(|| {
        let image = build_kmdf_driver_pe32();
        let (mut runtime, _directory) = test_runtime_x86_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdf32",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string_x86(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdf32",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS,
            "the crafted PE32 KMDF DriverEntry must execute"
        );
        let island = claim_island(&runtime, "CasaKmdf32");
        let image_base = island.image_base();
        assert_eq!(island.device_count(), 1);
        assert_eq!(island.casak_device_names(), vec!["Wdf32"]);
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
            assert_ne!(state.kmdf.evt_driver_unload, 0);
        }
        assert_eq!(
            memory
                .read_u32(u64::from(image_base as u32 + X86K_ADD_MARKER))
                .unwrap(),
            0xCA5A_0031
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let unloaded = take_last_unloaded_driver().expect("unloaded");
        assert_eq!(unloaded.inner.borrow().kmdf.driver_unload_calls, 1);
        assert_eq!(
            memory
                .read_u32(u64::from(image_base as u32 + X86K_UNLOAD_MARKER))
                .unwrap(),
            0xCA5A_0032,
            "32-bit EvtDriverUnload executed"
        );
    });
}

#[test]
fn kmdf_cancelled_request_without_callback_completes_cancelled() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(2, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfCancel",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfCancel",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfCancel");
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let iosb = 0x53_000;
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[u64::from(handle), 0, 0, 0, iosb, 0x0022_0004, 0, 0, 0, 0],
            ),
            STATUS_PENDING
        );
        let request = pending_request(&island);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[request],
                )
                .expect("cancel") as u32 as i32,
            STATUS_CANCELLED
        );
        let (completed, status, _, outer) = island.kmdf_request_state(request).expect("request");
        assert!(completed);
        assert_eq!(status, STATUS_CANCELLED);
        assert_eq!(
            memory.read_u32(outer + 0x30).unwrap(),
            STATUS_CANCELLED as u32
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS
        );
    });
}

#[test]
fn loaded_driver_registry_is_shared_across_guest_thread_contexts() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaThreaded",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaThreaded",
        );
        let thread_a = STACK_BASE + STACK_SIZE - 0x180;
        let thread_b = STACK_BASE + STACK_SIZE - 0x280;
        assert_eq!(
            dispatch_nt_thunk_on_thread(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
                thread_a,
            ),
            STATUS_SUCCESS,
            "load from guest thread A"
        );
        assert_eq!(
            dispatch_nt_thunk_on_thread(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
                thread_b,
            ),
            STATUS_IMAGE_ALREADY_LOADED,
            "duplicate load from guest thread B"
        );
        assert_eq!(
            dispatch_nt_thunk_on_thread(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
                thread_b,
            ),
            STATUS_SUCCESS,
            "unload from guest thread B"
        );
        assert!(with_loaded_driver(&runtime, "CasaThreaded", |_| ()).is_none());
    });
}

fn x64_complete_stub(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    island: &DriverIsland,
    status: i32,
    information: u32,
) -> u64 {
    let complete = allocate_shim(runtime, DriverShim::WdfRequestCompleteWithInformation);
    let mut code = vec![0x48, 0x89, 0xD1, 0xBA];
    code.extend_from_slice(&status.to_le_bytes());
    code.extend_from_slice(&[0x41, 0xB8]);
    code.extend_from_slice(&information.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&complete.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0, 0xC3]);
    let entry = island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, code.len(), 16)
        .expect("complete stub");
    memory.map_bytes(entry, &code);
    entry
}

fn x64_marker_stub(memory: &mut MemoryImage, island: &DriverIsland, counter: u64) -> u64 {
    let mut code = vec![0xFF, 0x05, 0, 0, 0, 0, 0xC3];
    let entry = island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, code.len(), 16)
        .expect("marker stub");
    let displacement = counter as i64 - (entry as i64 + 6);
    code[2..6].copy_from_slice(&(displacement as i32).to_le_bytes());
    memory.map_bytes(entry, &code);
    entry
}

/// An interrupt-service stub: increments `counter` and returns TRUE
/// (1), claiming the interrupt.
fn x64_claiming_isr_stub(memory: &mut MemoryImage, island: &DriverIsland, counter: u64) -> u64 {
    let mut code = vec![
        0xFF, 0x05, 0, 0, 0, 0, // inc dword [rip+disp]
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xC3, // ret
    ];
    let entry = island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, code.len(), 16)
        .expect("isr stub");
    let displacement = counter as i64 - (entry as i64 + 6);
    code[2..6].copy_from_slice(&(displacement as i32).to_le_bytes());
    memory.map_bytes(entry, &code);
    entry
}

fn arena_counter(memory: &mut MemoryImage, island: &DriverIsland) -> u64 {
    island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, 8, 8)
        .expect("counter")
}

fn set_queue_callbacks(island: &DriverIsland, queue: u64, f: impl FnOnce(&mut KmdfQueue)) {
    if let Some(queue) = island.inner.borrow_mut().kmdf.queues.get_mut(&queue) {
        f(queue);
    }
}

fn patch_kmdf_config(image: &mut [u8], flags: u32) {
    const STUB: u32 = 0x3078;
    const COUNTER: u32 = 0x30E0;
    let data_offset = |address: u32| 0xC00 + (address - K_DATA_RVA) as usize;
    let stub = data_offset(STUB);
    let counter = data_offset(COUNTER);
    let displacement = COUNTER as i64 - (STUB as i64 + 6);
    image[stub..stub + 2].copy_from_slice(&[0xFF, 0x05]);
    image[stub + 2..stub + 6].copy_from_slice(&(displacement as i32).to_le_bytes());
    image[stub + 6] = 0xC3;
    image[counter..counter + 4].copy_from_slice(&0_u32.to_le_bytes());
    let config = data_offset(K_CONFIG_RVA);
    image[config + 0x10..config + 0x18]
        .copy_from_slice(&(K_IMAGE_BASE + u64::from(STUB)).to_le_bytes());
    image[config + 0x18..config + 0x1C].copy_from_slice(&0x2146_4457_u32.to_le_bytes());
    image[config + 0x1C..config + 0x20].copy_from_slice(&flags.to_le_bytes());
}

fn unload_marker(memory: &MemoryImage, base: u64) -> u32 {
    memory.read_u32(base + 0x30E0).unwrap()
}

#[test]
fn kmdf_driver_config_parse_and_evt_driver_unload() {
    with_big_stack(|| {
        let mut image = build_kmdf_driver(true, false, false);
        patch_kmdf_config(&mut image, 0);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfCfg",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfCfg",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfCfg");
        let base = island.image_base();
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
            assert_eq!(state.kmdf.driver_init_flags, 0);
            assert_ne!(state.kmdf.evt_driver_unload, 0);
            assert_eq!(state.kmdf.framework_dispatches.len(), 7);
        }
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let unloaded = take_last_unloaded_driver().expect("unloaded island");
        assert_eq!(unloaded.inner.borrow().kmdf.driver_unload_calls, 1);
        assert_eq!(unload_marker(&memory, base), 1);
    });
}

#[test]
fn kmdf_read_write_cleanup_and_close_dispatch() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfRw",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfRw",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfRw");
        let device = island.created_devices()[0].guest_pointer;
        let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
        let stub = x64_complete_stub(&mut runtime, &mut memory, &island, STATUS_SUCCESS, 0);
        set_queue_callbacks(&island, queue, |queue| {
            queue.callbacks.read = stub;
            queue.callbacks.write = stub;
            queue.callbacks.default = stub;
        });
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let buffer = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(buffer, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtReadFile,
                &[u64::from(handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtWriteFile,
                &[u64::from(handle), 0, 0, 0, iosb, buffer, 4, 0, 0],
            ),
            STATUS_SUCCESS
        );
        let (status, _) = island
            .dispatch_irp(
                &mut runtime,
                &mut memory,
                device,
                IrpMajorFunction::Cleanup,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("cleanup");
        assert_eq!(status, STATUS_SUCCESS);
        let (status, _) = island
            .dispatch_irp(
                &mut runtime,
                &mut memory,
                device,
                IrpMajorFunction::Close,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("close");
        assert_eq!(status, STATUS_SUCCESS);
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.read_dispatches, 1);
            assert_eq!(state.kmdf.write_dispatches, 1);
            assert_eq!(state.kmdf.cleanup_dispatches, 1);
            assert_eq!(state.kmdf.close_dispatches, 1);
        }
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS
        );
    });
}

#[test]
fn kmdf_manual_queue_retrieval_and_cancellation() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfManual",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfManual",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfManual");
        let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
        set_queue_callbacks(&island, queue, |queue| {
            queue.dispatch_type = 2;
            queue.default_queue = true;
        });
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let input = 0x51_000;
        let output = 0x52_000;
        let iosb = 0x53_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        for _ in 0..2 {
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING
            );
        }
        let requests = island
            .inner
            .borrow()
            .kmdf
            .requests
            .iter()
            .filter(|(_, request)| !request.completed)
            .map(|(handle, _)| *handle)
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 2);
        let out = 0x54_000;
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveFoundRequest,
                    &[queue, requests[1], out],
                )
                .expect("found") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u64(out).unwrap(), requests[1]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueRetrieveNextRequest,
                    &[queue, out],
                )
                .expect("next") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u64(out).unwrap(), requests[0]);
        for request in &requests {
            assert_eq!(
                island
                    .call_shim_for_test(
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestComplete,
                        &[*request, STATUS_SUCCESS as u64],
                    )
                    .expect("complete") as u32 as i32,
                STATUS_SUCCESS
            );
        }
        let cancel_stub =
            x64_complete_stub(&mut runtime, &mut memory, &island, STATUS_CANCELLED, 0);
        set_queue_callbacks(&island, queue, |queue| {
            queue.callbacks.canceled_on_queue = cancel_stub;
        });
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x0022_0004,
                    input,
                    4,
                    output,
                    8,
                ],
            ),
            STATUS_PENDING
        );
        let cancel = island
            .inner
            .borrow()
            .kmdf
            .requests
            .iter()
            .find(|(_, request)| !request.completed)
            .map(|(handle, _)| *handle)
            .unwrap();
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[cancel],
                )
                .expect("cancel") as u32 as i32,
            STATUS_SUCCESS
        );
        let (completed, status, _, _) = island.kmdf_request_state(cancel).unwrap();
        assert!(completed);
        assert_eq!(status, STATUS_CANCELLED);
        // Without EvtIoCanceledOnQueue the framework completes the queued
        // request itself with STATUS_CANCELLED.
        set_queue_callbacks(&island, queue, |queue| {
            queue.callbacks.canceled_on_queue = 0;
        });
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x0022_0004,
                    input,
                    4,
                    output,
                    8,
                ],
            ),
            STATUS_PENDING
        );
        let cancel = island
            .inner
            .borrow()
            .kmdf
            .requests
            .iter()
            .find(|(_, request)| !request.completed)
            .map(|(handle, _)| *handle)
            .unwrap();
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCancelQueuedRequest,
                    &[cancel],
                )
                .expect("cancel no callback") as u32 as i32,
            STATUS_CANCELLED
        );
        assert_eq!(
            island.kmdf_request_state(cancel).unwrap().1,
            STATUS_CANCELLED
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.manual_retrievals, 2);
            assert_eq!(state.kmdf.cancel_dispatches, 2);
        }
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(handle)],
            ),
            STATUS_SUCCESS
        );
    });
}

#[test]
fn kmdf_iotarget_sends_to_another_device_with_real_completion() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfT",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfT",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfT");
        let base = island.image_base();
        let device_a = island.kmdf_device_handles()[0];
        let init = *island
            .inner
            .borrow()
            .kmdf
            .device_inits
            .keys()
            .next()
            .unwrap();
        let name = guest_unicode_string(&mut memory, 0x57_000, "\\Device\\WdfB");
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceInitAssignName,
                    &[init, name],
                )
                .expect("name") as u32 as i32,
            STATUS_SUCCESS
        );
        let device_b_out = 0x54_000;
        memory.map_bytes(device_b_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceCreate,
                    &[init, 0, device_b_out],
                )
                .expect("device B") as u32 as i32,
            STATUS_SUCCESS
        );
        let device_b = memory.read_u64(device_b_out).unwrap();
        let config = 0x58_000;
        memory.map_bytes(config, &[0_u8; 0x60]);
        memory.write_u32(config, 0x50);
        memory.write_u32(config + 4, 1);
        memory.write_u64(config + 0x28, base + u64::from(K_EVT_IOCTL_RVA));
        let queue_out = 0x54_010;
        memory.map_bytes(queue_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoQueueCreate,
                    &[device_b, config, 0, queue_out],
                )
                .expect("queue B") as u32 as i32,
            STATUS_SUCCESS
        );
        let target_b_out = 0x54_020;
        memory.map_bytes(target_b_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetCreate,
                    &[device_b, 0, target_b_out],
                )
                .expect("target B") as u32 as i32,
            STATUS_SUCCESS
        );
        let target_b = memory.read_u64(target_b_out).unwrap();
        assert_ne!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfDeviceGetIoTarget,
                    &[device_a],
                )
                .expect("target A"),
            0
        );
        let input = 0x56_000;
        let output = 0x56_100;
        let bytes_returned = 0x56_200;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(bytes_returned, &[0_u8; 8]);
        let input_descriptor = 0x55_000;
        let output_descriptor = 0x55_020;
        for (descriptor, pointer, length) in [
            (input_descriptor, input, 4u64),
            (output_descriptor, output, 8),
        ] {
            memory.map_bytes(descriptor, &[0_u8; 0x20]);
            memory.write_u32(descriptor, 0);
            memory.write_u64(descriptor + 8, pointer);
            memory.write_u64(descriptor + 0x10, length);
        }
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfIoTargetSendIoctlSynchronously,
                    &[
                        target_b,
                        0,
                        0x0022_0004,
                        input_descriptor,
                        output_descriptor,
                        0,
                        bytes_returned,
                    ],
                )
                .expect("send") as u32 as i32,
            STATUS_SUCCESS
        );
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"WDF!");
        assert_eq!(memory.read_u64(bytes_returned).unwrap(), 4);
        let request_out = 0x54_100;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestCreate,
                    &[0, target_b, request_out],
                )
                .expect("request") as u32 as i32,
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestFormatRequestForIoctl,
                    &[request, target_b, 0x0022_0004, input, 4, output, 8, 0,],
                )
                .expect("format") as u32 as i32,
            STATUS_SUCCESS
        );
        memory.map_bytes(output, &[0_u8; 8]);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfRequestSend,
                    &[request, target_b, 0],
                )
                .expect("send request") as u32 as i32,
            STATUS_SUCCESS
        );
        let (completed, status, information, _) = island.kmdf_request_state(request).unwrap();
        assert!(completed);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(information, 4);
        assert_eq!(&memory.read_bytes(output, 4).unwrap(), b"WDF!");
        assert_eq!(island.inner.borrow().kmdf.iotarget_sends, 2);
    });
}

#[test]
fn kmdf_wait_lock_parks_guest_until_release_with_timeout() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfL",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfL",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfL");
        let lock = island.kmdf_wait_lock_handles()[0];
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, 0],
                )
                .expect("acquire") as u32 as i32,
            STATUS_SUCCESS
        );
        let gate = island.kmdf_wait_lock_gate(lock).unwrap();
        let releaser = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                let (mutex, wake) = &*gate;
                let mut locked = mutex.lock().unwrap();
                *locked = false;
                drop(locked);
                wake.notify_all();
            })
        };
        let timeout = 0x54_000;
        memory.map_bytes(timeout, &[0_u8; 8]);
        memory.write_u64(timeout, (-20_000_000_i64) as u64);
        let started = std::time::Instant::now();
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, timeout],
                )
                .expect("blocking acquire") as u32 as i32,
            STATUS_SUCCESS
        );
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(20),
            "WdfWaitLockAcquire must block the guest until release"
        );
        releaser.join().unwrap();
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockRelease,
                    &[lock],
                )
                .expect("release") as u32 as i32,
            STATUS_SUCCESS
        );
        assert!(island.inner.borrow().kmdf.parked_acquires >= 1);
        // A held lock with a 100 microsecond relative timeout returns
        // STATUS_TIMEOUT without taking ownership.
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, 0],
                )
                .expect("reacquire") as u32 as i32,
            STATUS_SUCCESS
        );
        memory.write_u64(timeout, (-1_000_i64) as u64);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockAcquire,
                    &[lock, timeout],
                )
                .expect("timeout") as u32 as i32,
            STATUS_TIMEOUT
        );
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfWaitLockRelease,
                    &[lock],
                )
                .expect("final release") as u32 as i32,
            STATUS_SUCCESS
        );
        let mut held = {
            let (mutex, _) = &*gate;
            let mut guard = mutex.lock().unwrap();
            *guard = true;
            guard
        };
        // hold the gate while the waiters start
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut waiters = Vec::new();
        for _ in 0..4 {
            let gate = gate.clone();
            let active = active.clone();
            let peak = peak.clone();
            waiters.push(std::thread::spawn(move || {
                let (mutex, wake) = &*gate;
                let mut locked = mutex.lock().unwrap();
                while *locked {
                    locked = wake.wait(locked).unwrap();
                }
                *locked = true;
                let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(2));
                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                *locked = false;
                drop(locked);
                wake.notify_all();
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        *held = false;
        drop(held);
        let (_, wake) = &*gate;
        wake.notify_all();
        for waiter in waiters {
            waiter.join().unwrap();
        }
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 1);
    });
}

#[test]
fn kmdf_object_contexts_attributes_and_driver_cascade() {
    with_big_stack(|| {
        let mut image = build_kmdf_driver(true, false, false);
        patch_kmdf_config(&mut image, 0);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfO",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfO",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfO");
        let base = island.image_base();
        let driver = island.kmdf_driver_handle();
        let device = island.kmdf_device_handles()[0];
        let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
        assert_eq!(island.kmdf_context_size(device), Some(0x80));
        let context = island.kmdf_typed_context(device).unwrap();
        let cleanup_counter = arena_counter(&mut memory, &island);
        let destroy_counter = arena_counter(&mut memory, &island);
        let cleanup_stub = x64_marker_stub(&mut memory, &island, cleanup_counter);
        let destroy_stub = x64_marker_stub(&mut memory, &island, destroy_counter);
        {
            let mut state = island.inner.borrow_mut();
            for handle in [device, queue] {
                let object = state.kmdf.objects.get_mut(&handle).unwrap();
                object.evt_cleanup = cleanup_stub;
                object.evt_destroy = destroy_stub;
            }
        }
        let type_info = 0x54_000;
        let context_out = 0x54_010;
        memory.map_bytes(type_info, &[0_u8; 0x20]);
        memory.map_bytes(context_out, &[0_u8; 8]);
        memory.write_u32(type_info, 0x18);
        memory.write_u64(type_info + 0x10, 0x40);
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectAllocateContext,
                    &[device, type_info, context_out],
                )
                .expect("allocate context") as u32 as i32,
            STATUS_SUCCESS
        );
        let extra = memory.read_u64(context_out).unwrap();
        assert_ne!(extra, context);
        memory.write_u32(extra + 0x30, 0x1234_5678);
        assert_eq!(memory.read_u32(extra + 0x30).unwrap(), 0x1234_5678);
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .objects
                .get(&device)
                .unwrap()
                .extra_contexts[0]
                .2,
            0x40
        );
        assert_eq!(
            island
                .call_shim_for_test(
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfObjectDelete,
                    &[driver],
                )
                .expect("delete driver") as u32 as i32,
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(state.kmdf.devices.is_empty());
            assert!(state.kmdf.queues.is_empty());
        }
        assert_eq!(memory.read_u32(cleanup_counter).unwrap(), 2);
        assert_eq!(memory.read_u32(destroy_counter).unwrap(), 2);
        assert_eq!(unload_marker(&memory, base), 1);
    });
}

#[test]
fn kmdf_driver_init_flags_skip_dispatch_override() {
    with_big_stack(|| {
        let mut image = build_kmdf_driver(true, false, false);
        patch_kmdf_config(&mut image, 2);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            stage_service(
                ge,
                "CasaKmdfF",
                "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfF",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[service_path],
            ),
            STATUS_SUCCESS
        );
        let island = claim_island(&runtime, "CasaKmdfF");
        let state = island.inner.borrow();
        assert_eq!(state.kmdf.driver_init_flags, 2);
        assert!(state.kmdf.framework_dispatches.is_empty());
        assert_eq!(state.kmdf.driver_pool_tag, 0x2146_4457);
    });
}

fn load_staged_island_x64(
    image: &[u8],
    service: &str,
) -> (Box<PeHostRuntime>, TempDir, MemoryImage, DriverIsland) {
    let (runtime, directory) = test_runtime_with_ge(|ge| {
        stage_service(
            ge,
            service,
            "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
            image,
        );
    });
    let mut runtime = Box::new(runtime);
    let mut memory = MemoryImage::default();
    prepare_guest_memory(&mut runtime, &mut memory);
    let service_path = guest_unicode_string(
        &mut memory,
        0x40_000,
        &format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{service}"),
    );
    assert_eq!(
        dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtLoadDriver,
            &[service_path],
        ),
        STATUS_SUCCESS,
        "staged service {service} must load"
    );
    let island = claim_island(&runtime, service);
    (runtime, directory, memory, island)
}

fn load_staged_island_x86(
    image: &[u8],
    service: &str,
) -> (Box<PeHostRuntime>, TempDir, MemoryImage, DriverIsland) {
    let (runtime, directory) = test_runtime_x86_with_ge(|ge| {
        stage_service(
            ge,
            service,
            "\\SystemRoot\\System32\\drivers\\casa_nt.sys",
            image,
        );
    });
    let mut runtime = Box::new(runtime);
    let mut memory = MemoryImage::default();
    prepare_guest_memory(&mut runtime, &mut memory);
    let service_path = guest_unicode_string_x86(
        &mut memory,
        0x40_000,
        &format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{service}"),
    );
    assert_eq!(
        dispatch_nt_thunk(
            &mut runtime,
            &mut memory,
            HostThunk::NtLoadDriver,
            &[service_path],
        ),
        STATUS_SUCCESS,
        "staged x86 service {service} must load"
    );
    let island = claim_island(&runtime, service);
    (runtime, directory, memory, island)
}

fn write_guest_wide(memory: &mut MemoryImage, address: u64, text: &str) {
    let units = text.encode_utf16().collect::<Vec<_>>();
    memory.map_bytes(address, &vec![0_u8; (units.len() + 1) * 2]);
    for (index, unit) in units.iter().enumerate() {
        memory.write_u16(address + index as u64 * 2, *unit);
    }
}

fn call_island_shim(
    island: &DriverIsland,
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    function: DriverShim,
    args: &[u64],
) -> AppResult<i32> {
    island
        .call_shim_for_test(runtime, memory, function, args)
        .map(|value| value as u32 as i32)
}

fn call_island_shim_raw(
    island: &DriverIsland,
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    function: DriverShim,
    args: &[u64],
) -> AppResult<u64> {
    island.call_shim_for_test(runtime, memory, function, args)
}

#[test]
fn shim_x86_arg_bytes_abi_mismatch_or_zero_width_rejects() {
    let expected = [
        (DriverShim::DbgPrint, 4u64),
        (DriverShim::IoCreateDevice, 28),
        (DriverShim::IoDeleteDevice, 4),
        (DriverShim::IoCreateSymbolicLink, 8),
        (DriverShim::IoDeleteSymbolicLink, 8),
        (DriverShim::IoAllocateIrp, 8),
        (DriverShim::IoFreeIrp, 4),
        (DriverShim::RtlInitUnicodeString, 8),
        (DriverShim::IofCompleteRequest, 8),
        (DriverShim::IoCompleteRequest, 8),
        (DriverShim::ExAllocatePoolWithTag, 12),
        (DriverShim::ExFreePoolWithTag, 8),
        (DriverShim::ExAllocatePool, 8),
        (DriverShim::ExFreePool, 4),
        (DriverShim::KeGetCurrentIrql, 0),
        (DriverShim::KeQuerySystemTime, 0),
        (DriverShim::PsGetCurrentProcessId, 0),
        (DriverShim::PsGetCurrentThreadId, 0),
        (DriverShim::KfRaiseIrql, 4),
        (DriverShim::KfLowerIrql, 4),
        (DriverShim::KeAcquireSpinLockRaiseToDpc, 4),
        (DriverShim::KeReleaseSpinLock, 8),
        (DriverShim::KeInitializeDpc, 12),
        (DriverShim::KeInsertQueueDpc, 12),
        (DriverShim::KeRemoveQueueDpc, 4),
        (DriverShim::KeInitializeEvent, 12),
        (DriverShim::KeSetEvent, 12),
        (DriverShim::KeResetEvent, 4),
        (DriverShim::KeReadStateEvent, 4),
        (DriverShim::KeWaitForSingleObject, 16),
        (DriverShim::IoAllocateMdl, 20),
        (DriverShim::MmProbeAndLockPages, 12),
        (DriverShim::MmUnlockPages, 4),
        (DriverShim::IoFreeMdl, 4),
        (DriverShim::MmGetMdlByteCount, 4),
        (DriverShim::ZwOpenKey, 12),
        (DriverShim::ZwQueryValueKey, 24),
        (DriverShim::ZwClose, 4),
        (DriverShim::ExInitializeNPagedLookasideList, 28),
        (DriverShim::ExInitializePagedLookasideList, 28),
        (DriverShim::ExAllocateFromNPagedLookasideList, 4),
        (DriverShim::ExAllocateFromPagedLookasideList, 4),
        (DriverShim::ExFreeToNPagedLookasideList, 8),
        (DriverShim::ExFreeToPagedLookasideList, 8),
        (DriverShim::PsCreateSystemThread, 20),
        (DriverShim::PsTerminateSystemThread, 4),
        (DriverShim::IoConnectInterrupt, 44),
        (DriverShim::IoConnectInterruptEx, 4),
        (DriverShim::IoDisconnectInterrupt, 4),
        (DriverShim::EtwRegister, 16),
        (DriverShim::EtwUnregister, 4),
        (DriverShim::EtwWrite, 16),
        (DriverShim::NtAlpcConnectPort, 28),
        (DriverShim::KeQueryInterruptTime, 0),
        (DriverShim::IslandSafepoint, 0),
        (DriverShim::IrpDispatch, 8),
        (DriverShim::WdfDriverCreate, 20),
        (DriverShim::WdfDeviceInitSetDeviceType, 8),
        (DriverShim::WdfDeviceInitSetIoType, 8),
        (DriverShim::WdfDeviceInitAssignName, 8),
        (DriverShim::WdfDeviceCreate, 12),
        (DriverShim::WdfIoQueueCreate, 16),
        (DriverShim::WdfRequestCreate, 12),
        (DriverShim::WdfRequestFormatRequestForIoctl, 32),
        (DriverShim::WdfRequestRetrieveInputBuffer, 16),
        (DriverShim::WdfRequestRetrieveOutputBuffer, 16),
        (DriverShim::WdfRequestComplete, 8),
        (DriverShim::WdfRequestCompleteWithInformation, 12),
        (DriverShim::WdfDeviceWdmGetDeviceObject, 4),
        (DriverShim::WdfObjectGetTypedContext, 8),
        (DriverShim::WdfObjectDelete, 4),
        (DriverShim::WdfWaitLockCreate, 8),
        (DriverShim::WdfWaitLockAcquire, 8),
        (DriverShim::WdfWaitLockRelease, 4),
        (DriverShim::WdfObjectAllocateContext, 12),
        (DriverShim::WdfDeviceGetIoTarget, 4),
        (DriverShim::WdfIoTargetCreate, 12),
        (DriverShim::WdfIoTargetSendIoctlSynchronously, 28),
        (DriverShim::WdfIoTargetFormatRequestForIoctl, 28),
        (DriverShim::WdfRequestSend, 12),
        (DriverShim::WdfRequestCancelQueuedRequest, 4),
        (DriverShim::WdfIoQueueRetrieveNextRequest, 12),
        (DriverShim::WdfIoQueueRetrieveFoundRequest, 12),
        (DriverShim::WdfIoQueueStop, 12),
        (DriverShim::WdfIoQueueStopSynchronously, 4),
        (DriverShim::WdfIoQueueDrain, 12),
        (DriverShim::WdfIoQueueDrainSynchronously, 4),
        (DriverShim::WdfIoQueuePurge, 12),
        (DriverShim::WdfIoQueuePurgeSynchronously, 4),
        (DriverShim::WdfIoQueueStart, 4),
        (DriverShim::WdfEvtIoReadDispatch, 8),
        (DriverShim::WdfEvtIoWriteDispatch, 8),
        (DriverShim::WdfEvtIoDeviceControlDispatch, 8),
        (DriverShim::WdfEvtIoCleanupDispatch, 8),
        (DriverShim::WdfEvtIoCloseDispatch, 8),
        (DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks, 8),
        (DriverShim::WdfDeviceInitSetFileObjectConfig, 8),
        (DriverShim::WdfMemoryCreate, 24),
        (DriverShim::WdfMemoryCreatePreallocated, 16),
        (DriverShim::WdfMemoryGetBuffer, 8),
        (DriverShim::WdfStringCreate, 12),
        (DriverShim::WdfStringGetUnicodeString, 8),
        (DriverShim::WdfDeviceEnqueueRequest, 8),
        (DriverShim::WdfPdoInitAllocate, 4),
        (DriverShim::WdfPdoInitAssignDeviceID, 8),
        (DriverShim::WdfPdoInitAssignInstanceID, 8),
        (DriverShim::WdfPdoInitAddHardwareID, 8),
        (DriverShim::WdfPdoInitAddCompatibleID, 8),
        (DriverShim::WdfSpinLockCreate, 8),
        (DriverShim::WdfSpinLockAcquire, 4),
        (DriverShim::WdfSpinLockRelease, 4),
        (DriverShim::WdfTimerCreate, 12),
        (DriverShim::WdfTimerStart, 8),
        (DriverShim::WdfTimerStop, 8),
        (DriverShim::WdfWorkItemCreate, 12),
        (DriverShim::WdfWorkItemEnqueue, 4),
        (DriverShim::WdfWorkItemFlush, 4),
        (DriverShim::WdfRequestFormatRequestForRead, 20),
        (DriverShim::WdfRequestFormatRequestForWrite, 20),
        (DriverShim::WdfRequestGetStatus, 4),
        (DriverShim::WdfRequestIsCanceled, 4),
        (DriverShim::WdfRequestMarkCancelable, 8),
        (DriverShim::WdfRequestUnmarkCancelable, 4),
        (DriverShim::WdfDeviceStopIdle, 8),
        (DriverShim::WdfDeviceResumeIdle, 4),
        (DriverShim::WdfRequestForwardToIoQueue, 8),
        (DriverShim::WdfDeviceInitSetPowerPolicyOwnership, 8),
        (DriverShim::WdfEvtPnpDispatch, 8),
        (DriverShim::WdfEvtPowerDispatch, 8),
        (DriverShim::WdfCollectionCreate, 12),
        (DriverShim::WdfCollectionAdd, 8),
        (DriverShim::WdfCollectionRemove, 8),
        (DriverShim::WdfCollectionRemoveAll, 4),
        (DriverShim::WdfCollectionGetItem, 8),
        (DriverShim::WdfCollectionGetCount, 4),
        (DriverShim::WdfCollectionContains2, 8),
        (DriverShim::WdfLookasideListCreate, 20),
        (DriverShim::WdfMemoryCreateFromLookaside, 8),
        (DriverShim::WdfInterruptCreate, 16),
        (DriverShim::WdfInterruptQueueDpcForIsr, 4),
        (DriverShim::WdfInterruptAcquireLock, 4),
        (DriverShim::WdfInterruptReleaseLock, 4),
        (DriverShim::WdfInterruptSynchronize, 12),
        (DriverShim::WdfInterruptDisable, 4),
        (DriverShim::WdfInterruptEnable, 4),
        (DriverShim::WdfDmaEnablerCreate, 16),
        (DriverShim::WdfDmaEnablerCalculateMaximumTransferSize, 4),
        (DriverShim::WdfDmaTransactionCreate, 12),
        (DriverShim::WdfDmaTransactionInitialize, 20),
        (DriverShim::WdfDmaTransactionExecute, 8),
        (DriverShim::WdfDmaTransactionRelease, 4),
        (DriverShim::WdfDmaTransactionCancel, 4),
        (DriverShim::WdfUsbTargetDeviceCreate, 16),
        (DriverShim::WdfUsbTargetDeviceGetInformation, 8),
        (DriverShim::WdfUsbInterfaceGetConfiguredPipe, 16),
        (DriverShim::WdfUsbTargetPipeReadPipe, 16),
        (DriverShim::WdfUsbTargetPipeWritePipe, 16),
        (DriverShim::WdfUsbTargetPipeAbortPipe, 4),
        (DriverShim::WdfUsbTargetPipeResetPipe, 4),
        (DriverShim::WdfUsbTargetPipeGetType, 4),
        (DriverShim::WdfRegistryOpenKey, 16),
        (DriverShim::WdfRegistryCreateKey, 16),
        (DriverShim::WdfRegistryClose, 4),
        (DriverShim::WdfRegistryQueryValue, 24),
        (DriverShim::WdfRegistryAssignValue, 20),
        (DriverShim::WdfRegistryDeleteValue, 8),
        (DriverShim::WdfChildListCreate, 16),
        (DriverShim::WdfChildListGetFirst, 8),
        (DriverShim::WdfChildListGetNext, 8),
        (DriverShim::WdfChildListGetChildCount, 4),
        (DriverShim::WdfEvtChildListScanDispatch, 4),
        (DriverShim::WdfCmResourceListCreate, 12),
        (DriverShim::WdfCmResourceListGetDescriptor, 8),
        (DriverShim::WdfCmResourceListGetCount, 4),
        (DriverShim::WdfMemoryCopy, 12),
        (DriverShim::WdfMemoryAssign, 12),
        (DriverShim::WdfRequestCreateFromIrp, 12),
        (DriverShim::WdfRequestImpersonate, 8),
        (DriverShim::WdfRequestStopImpersonating, 4),
        (DriverShim::WdfRequestWdmGetIrp, 4),
        (DriverShim::WdfRequestSetInformation, 8),
        (DriverShim::WdfRequestForwardToParentDeviceIoQueue, 12),
        (DriverShim::WdfObjectReference, 4),
        (DriverShim::WdfObjectDereference, 4),
        (DriverShim::WdfControlDeviceInitAllocate, 8),
        (DriverShim::WdfControlFinishInitializing, 4),
    ];
    for (shim, want) in expected {
        assert_eq!(
            shim.x86_arg_bytes(),
            want,
            "{shim:?} must pop its exact stdcall byte count"
        );
    }
}

#[test]
fn unload_error_restores_registration_and_reports_invalid_parameter() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaUnloadFail");
        island.inner.borrow_mut().unload_guest = Some(0xDEAD_BEEF);
        let service_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaUnloadFail",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_INVALID_PARAMETER,
            "a failed DriverUnload must be reported as INVALID_PARAMETER"
        );
        assert!(
            with_loaded_driver(&runtime, "CasaUnloadFail", |_| ()).is_some(),
            "the island must be re-registered after a failed unload"
        );
        assert!(island.is_loaded(), "failed unload leaves the island loaded");
    });
}

#[test]
fn io_shims_reject_malformed_names_and_links() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaBadIo");
        let link = guest_unicode_string(&mut memory, 0x50_000, "\\??\\CasaTest");
        let target = guest_unicode_string(&mut memory, 0x52_000, "\\Device\\CasaTest");

        let deleted = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoDeleteSymbolicLink,
            &[link],
        );
        assert_eq!(deleted.expect("delete link"), STATUS_SUCCESS);
        let missing = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoDeleteSymbolicLink,
            &[link],
        );
        assert_eq!(
            missing.expect("delete missing link"),
            STATUS_OBJECT_NAME_NOT_FOUND
        );

        let created = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateSymbolicLink,
            &[link, target],
        );
        assert_eq!(created.expect("recreate link"), STATUS_SUCCESS);
        let duplicate = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateSymbolicLink,
            &[link, target],
        );
        assert_eq!(
            duplicate.expect("duplicate link"),
            STATUS_OBJECT_NAME_COLLISION
        );
        let null_link = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateSymbolicLink,
            &[0, target],
        );
        assert_eq!(
            null_link.expect("empty link name"),
            STATUS_INVALID_PARAMETER
        );

        let irp = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoAllocateIrp,
            &[1, 0],
        )
        .expect("allocate irp");
        assert_ne!(irp, 0);
        let freed = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoFreeIrp,
            &[irp],
        )
        .expect("free irp");
        assert_eq!(freed, 0);
        let free_unknown = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoFreeIrp,
            &[0xDEAD_0000],
        )
        .expect("free unknown irp");
        assert_eq!(free_unknown, 0);

        let default_dispatch = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IrpDispatch,
            &[0, 0],
        )
        .expect("default dispatch");
        assert_eq!(default_dispatch, STATUS_INVALID_DEVICE_REQUEST);

        let wide = 0x54_000;
        write_guest_wide(&mut memory, wide, "CasaWide");
        let header = 0x56_000;
        memory.map_bytes(header, &[0_u8; 16]);
        let init = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::RtlInitUnicodeString,
            &[header, wide],
        );
        assert_eq!(init.expect("init unicode string"), 0);
        assert_eq!(memory.read_u16(header).unwrap(), 16);
        let null_source = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::RtlInitUnicodeString,
            &[header, 0],
        );
        assert_eq!(null_source.expect("null source"), 0);
        assert_eq!(memory.read_u16(header).unwrap(), 0);
        let bad_destination = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::RtlInitUnicodeString,
            &[1, wide],
        );
        assert_eq!(
            bad_destination.expect("bad unicode destination"),
            STATUS_INVALID_PARAMETER
        );
        let unterminated = 0x46_000;
        memory.map_bytes(unterminated, &vec![0xFF_u8; 0x8000]);
        let error = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::RtlInitUnicodeString,
            &[header, unterminated],
        )
        .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);

        let no_format = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::DbgPrint,
            &[0],
        );
        assert_eq!(no_format.expect("null format"), 0);
        let bad_ansi = 0x46_000;
        memory.map_bytes(bad_ansi, &vec![b'A'; 4096]);
        let error = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::DbgPrint,
            &[bad_ansi],
        )
        .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);

        let driver = island.driver_object_pointer();
        let out = 0x58_000;
        memory.map_bytes(out, &[0_u8; 8]);
        let wrong_driver = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateDevice,
            &[0xDEAD, 0, 0, 3, 0, 0, out],
        );
        assert_eq!(
            wrong_driver.expect("wrong driver object"),
            STATUS_INVALID_PARAMETER
        );
        let null_out = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateDevice,
            &[driver, 0, 0, 3, 0, 0, 0],
        );
        assert_eq!(null_out.expect("null device out"), STATUS_INVALID_PARAMETER);
        let huge_extension = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateDevice,
            &[driver, 0x20_0000, 0, 3, 0, 0, out],
        );
        assert_eq!(
            huge_extension.expect("oversized extension"),
            STATUS_INSUFFICIENT_RESOURCES
        );
        let nameless = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateDevice,
            &[driver, 0, 0, 3, 0, 0, out],
        );
        assert_eq!(nameless.expect("nameless device"), STATUS_SUCCESS);
        let exclusive = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateDevice,
            &[driver, 0, 0, 3, 0, 1, out],
        );
        assert_eq!(exclusive.expect("exclusive device"), STATUS_SUCCESS);
        let duplicate_name = guest_unicode_string(&mut memory, 0x5A_000, "\\Device\\CasaTest");
        let duplicate = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateDevice,
            &[driver, 0, duplicate_name, 3, 0, 0, out],
        );
        assert_eq!(
            duplicate.expect("duplicate device name"),
            STATUS_OBJECT_NAME_COLLISION
        );

        {
            let mut state = island.inner.borrow_mut();
            state.driver_object_guest = 0;
            let no_driver = state
                .create_device_object(&mut memory, Some("NoDriver".into()), 0, 3, false)
                .expect("no-driver result");
            assert_eq!(no_driver, Err(STATUS_INVALID_PARAMETER));
            state.driver_object_guest = driver;
            let too_large = state
                .create_device_object(&mut memory, Some("TooLarge".into()), 0x20_0000, 3, false)
                .expect("oversized result");
            assert_eq!(too_large, Err(STATUS_INSUFFICIENT_RESOURCES));
            let saved_end = state.arena.end;
            state.arena.end = state.arena.cursor;
            let exhausted = state
                .create_device_object(&mut memory, Some("Exhausted".into()), 0, 3, false)
                .expect("arena result");
            assert_eq!(exhausted, Err(STATUS_INSUFFICIENT_RESOURCES));
            let start = align_up(state.arena.cursor, 16);
            state.arena.end = start + 0x180;
            let extension_fail = state
                .create_device_object(&mut memory, Some("ExtFail".into()), 0x10, 3, false)
                .expect("extension arena result");
            assert_eq!(extension_fail, Err(STATUS_INSUFFICIENT_RESOURCES));
            state.arena.end = saved_end;
        }

        let zero_length = 0x5C_000;
        memory.map_bytes(zero_length, &[0_u8; 16]);
        memory.write_u16(zero_length, 0);
        memory.write_u64(zero_length + 8, wide);
        let empty_name = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateSymbolicLink,
            &[zero_length, target],
        );
        assert_eq!(
            empty_name.expect("zero-length link"),
            STATUS_INVALID_PARAMETER
        );
        let odd_length = 0x5D_000;
        memory.map_bytes(odd_length, &[0_u8; 16]);
        memory.write_u16(odd_length, 3);
        memory.write_u64(odd_length + 8, wide);
        let error = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateSymbolicLink,
            &[odd_length, target],
        )
        .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);
        let null_buffer = 0x5E_000;
        memory.map_bytes(null_buffer, &[0_u8; 16]);
        memory.write_u16(null_buffer, 4);
        memory.write_u64(null_buffer + 8, 0);
        let error = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoCreateSymbolicLink,
            &[null_buffer, target],
        )
        .unwrap_err();
        assert_eq!(error.code, ReasonCode::RcMemoryAccessViolation);
    });
}

#[test]
fn dbg_print_format_rejects_malformed_conversions() {
    let mut memory = MemoryImage::default();
    let ansi = 0x10_000;
    let wide = 0x11_000;
    let unicode = 0x12_000;
    write_guest_wide(&mut memory, wide, "wide");
    memory.map_bytes(ansi, b"ansi\0");
    memory.map_bytes(unicode, &[0_u8; 16]);
    memory.write_u16(unicode, 8);
    memory.write_u64(unicode + 8, wide);
    assert_eq!(
        format_dbg_print("tail %", &[], &memory, GuestArch::X64),
        "tail %"
    );
    assert_eq!(format_dbg_print("%%", &[], &memory, GuestArch::X64), "%");
    assert_eq!(format_dbg_print("%w", &[], &memory, GuestArch::X64), "%");
    assert_eq!(format_dbg_print("%hd", &[7], &memory, GuestArch::X64), "7");
    assert_eq!(
        format_dbg_print("%ws", &[u64::from(wide as u32)], &memory, GuestArch::X64),
        "wide"
    );
    assert_eq!(
        format_dbg_print("%S", &[u64::from(ansi as u32)], &memory, GuestArch::X64),
        "ansi"
    );
    assert_eq!(
        format_dbg_print("%Z", &[u64::from(unicode as u32)], &memory, GuestArch::X64),
        "wide"
    );
    assert_eq!(
        format_dbg_print(
            "%u %d %x %X %p %c %q",
            &[1, (-2i32) as u64, 0xAB, 0xCD, 0x10, 0x41, 0],
            &memory,
            GuestArch::X64
        ),
        "1 -2 ab CD 0x10 A %q"
    );
}

#[test]
fn driver_image_helpers_reject_malformed_layouts_and_paths() {
    let short = [0_u8; 0x20];
    assert_eq!(
        pe_image_arch(&short),
        Err("driver island requires a PE image".to_string())
    );
    let mut bad_magic = vec![0_u8; 0x100];
    bad_magic[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    put_u32(&mut bad_magic, 0x3C, 0x80);
    assert_eq!(
        pe_image_arch(&bad_magic),
        Err("driver island requires a PE image".to_string())
    );
    let mut x86_magic = build_test_driver(false, false, false);
    put_u16(&mut x86_magic, 0x84, 0x014C);
    assert_eq!(
        pe_image_arch(&x86_magic),
        Err("PE32+ optional header on an x86 machine".to_string())
    );
    let mut x64_magic = build_test_driver(false, false, false);
    put_u16(&mut x64_magic, 0x98, 0x010B);
    assert_eq!(
        pe_image_arch(&x64_magic),
        Err("PE32 optional header on an x64 machine".to_string())
    );
    let mut unknown = build_test_driver(false, false, false);
    put_u16(&mut unknown, 0x84, 0x1234);
    assert_eq!(
        pe_image_arch(&unknown),
        Err("driver island rejects machine 0x1234".to_string())
    );
    assert_eq!(pe_layout_hint(&short), None);
    assert_eq!(pe_layout_hint(&bad_magic), None);
    let mut unknown_magic = build_test_driver(false, false, false);
    put_u16(&mut unknown_magic, 0x98, 0x9999);
    assert_eq!(pe_layout_hint(&unknown_magic), None);
    let hint = pe_layout_hint(&build_test_driver(false, false, false)).expect("layout hint");
    assert_eq!(hint.0, 0x1_4000_0000);
    assert_eq!(hint.1, 0x4000);

    assert_eq!(
        parse_service_name("\\Registry\\Machine\\System\\Foo"),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        parse_service_name("\\Registry\\Machine\\System\\CurrentControlSet\\Foo"),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        parse_service_name("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\\\"),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        parse_service_name(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaCase\\Parameters"
        ),
        Ok("CasaCase".to_string())
    );

    let environment = BTreeMap::from([
        ("WINDIR".to_string(), "C:\\Windows".to_string()),
        ("SYSTEMROOT".to_string(), "C:\\Windows".to_string()),
    ]);
    assert_eq!(
        expand_driver_image_path("\"C:\\Windows\\x.sys\"", &environment),
        "C:\\Windows\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("\"C:\\Windows\\x.sys", &environment),
        "\"C:\\Windows\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("\\??\\C:\\Windows\\x.sys", &environment),
        "C:\\Windows\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("\\DosDevices\\C:\\Windows\\x.sys", &environment),
        "C:\\Windows\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("\\SystemRoot\\System32\\x.sys", &environment),
        "C:\\Windows\\System32\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("\\System32\\x.sys", &environment),
        "C:\\Windows\\System32\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("System32\\x.sys", &environment),
        "C:\\Windows\\System32\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("%WINDIR%/x.sys", &environment),
        "C:\\Windows\\x.sys"
    );
    assert_eq!(
        expand_driver_image_path("%NOPE%\\x.sys", &environment),
        "C:\\Windows\\%NOPE%\\x.sys"
    );
    assert_eq!(expand_environment_percent("%NOPE%", &environment), "%NOPE%");
    assert_eq!(
        expand_environment_percent("a%WINDIR%b", &environment),
        "aC:\\Windowsb"
    );

    let not_found = AppError::new(ReasonCode::RcFsNotFound, "missing");
    assert_eq!(
        nt_load_error_status(&not_found),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    let registry = AppError::new(ReasonCode::RcRegistryNotFound, "missing");
    assert_eq!(
        nt_load_error_status(&registry),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    let parse = AppError::new(ReasonCode::RcPeParseInvalid, "bad");
    assert_eq!(
        nt_load_error_status(&parse),
        crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32
    );
    let image_error = driver_image_error(0xC000_0010);
    assert_eq!(image_error.code, ReasonCode::RcPeParseInvalid);
    assert_eq!(
        image_error.message,
        "driver image rejected with NTSTATUS 0xc0000010"
    );
    let io_error = nt_error("IoCreateDriver", STATUS_INVALID_HANDLE);
    assert_eq!(io_error.code, ReasonCode::RcIo);
    assert_eq!(
        io_error.message,
        "IoCreateDriver failed with NTSTATUS 0xc0000008"
    );
    assert_eq!(strip_device_prefix("\\Device\\Casa"), "Casa");
    assert_eq!(strip_device_prefix("\\\\Casa"), "Casa");
    assert_eq!(strip_device_prefix("Casa"), "Casa");
    assert_eq!(align_up(5, 0), 5);
    assert_eq!(align_up(5, 1), 5);
    assert_eq!(align_up(5, 4), 8);
}

#[test]
fn choose_placement_rejects_exhausted_and_overlapping_x86_ranges() {
    let (runtime, _directory) = test_runtime_x86();
    let placed = choose_placement(&runtime, 0x10000, 0x2000, GuestArch::X86)
        .expect("stack overlap is skipped");
    assert_ne!(placed.0, 0x10000, "the stack-overlapping base is skipped");
    assert!(placed.0 > 0x12000, "placement is above the stack");
    assert_eq!(placed.0 & 0xFFFF, 0, "placement stays 64 KiB aligned");
    let error = choose_placement(&runtime, 0x7FF0_0000, 0x2000, GuestArch::X86)
        .expect_err("no x86 range below the 4 GiB boundary");
    assert_eq!(error.code, ReasonCode::RcIo);
    assert!(
        error.message.contains("no free guest address range"),
        "placement error names the exhausted range: {}",
        error.message
    );
}

#[test]
fn nt_load_rejects_non_string_image_path_and_expands_quoted_path() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            let bad_key = "SYSTEM\\CurrentControlSet\\Services\\CasaBadType";
            ge.registry_create_key("HKLM", bad_key, RegistryView::Native)
                .expect("create key");
            ge.registry_set_value(
                "HKLM",
                bad_key,
                "ImagePath",
                "REG_DWORD",
                json!(7),
                RegistryView::Native,
            )
            .expect("write bad type");
            stage_service(
                ge,
                "CasaQuoted",
                "\"C:\\Windows\\System32\\drivers\\casa_nt.sys\"",
                &image,
            );
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let bad_path = guest_unicode_string(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaBadType",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[bad_path],
            ),
            crate::driver_image::STATUS_INVALID_IMAGE_FORMAT as i32,
            "a non-string ImagePath cannot name a driver image"
        );
        let quoted_path = guest_unicode_string(
            &mut memory,
            0x42_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaQuoted",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtLoadDriver,
                &[quoted_path],
            ),
            STATUS_SUCCESS,
            "a quoted ImagePath is stripped and loaded"
        );
    });
}

#[test]
fn import_ordinals_reject_regular_and_delay_tables() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime();
        let mut regular = build_test_driver(false, false, false);
        let ilt = 0x400 + (ILT_RVA - RDATA_RVA) as usize;
        put_u64(&mut regular, ilt, 0x8000_0000_0000_0001);
        let mut memory = MemoryImage::default();
        let error = DriverIsland::load_and_start(&regular, &mut runtime, &mut memory)
            .expect_err("ordinal imports have no shim");
        assert_eq!(error.code, ReasonCode::RcImportMissing);
        assert!(
            error.message.contains("ntoskrnl.exe"),
            "ordinal rejection names the module: {}",
            error.message
        );

        let (mut runtime, _directory) = test_runtime();
        let mut delay = with_delay_import(build_test_driver(false, false, false), "IoDeleteDevice");
        let int = 0x400 + (0x2560 - RDATA_RVA) as usize;
        put_u64(&mut delay, int, 0x8000_0000_0000_0002);
        let mut memory = MemoryImage::default();
        let error = DriverIsland::load_and_start(&delay, &mut runtime, &mut memory)
            .expect_err("delay ordinal imports have no shim");
        assert_eq!(error.code, ReasonCode::RcImportMissing);
    });
}

#[test]
fn no_active_island_shim_is_rejected_with_unimplemented_reason() {
    let (mut runtime, _directory) = test_runtime();
    let mut memory = MemoryImage::default();
    let mut cpu = CpuState::new(GuestArch::X64);
    let error = dispatch_shim(&mut runtime, &mut cpu, &mut memory, DriverShim::DbgPrint)
        .expect_err("shim outside an island must fail");
    assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    assert!(
        error.message.contains("no active island"),
        "the error names the missing island: {}",
        error.message
    );
}

fn x64_ret_stub(memory: &mut MemoryImage, island: &DriverIsland) -> u64 {
    let entry = island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, 1, 1)
        .expect("ret stub");
    memory.map_bytes(entry, &[0xC3]);
    entry
}

#[test]
fn kmdf_driver_and_device_shims_reject_invalid_arguments() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaKmdfBadArgs");
        let driver = island.driver_object_pointer();
        let out = 0x58_000;
        memory.map_bytes(out, &[0_u8; 8]);

        // Parent attachment is idempotent, ignores unknown parents, and
        // never cross-links an object that already has a parent.
        {
            let mut state = island.inner.borrow_mut();
            let first = *state.kmdf.objects.keys().next().expect("kernel object");
            let second = *state
                .kmdf
                .objects
                .keys()
                .nth(1)
                .expect("second kernel object");
            state.attach_kmdf_parent(first, second);
            assert_eq!(
                state
                    .kmdf
                    .objects
                    .get(&first)
                    .and_then(|object| object.parent),
                Some(second)
            );
            state.attach_kmdf_parent(first, first);
            assert_eq!(
                state
                    .kmdf
                    .objects
                    .get(&first)
                    .and_then(|object| object.parent),
                Some(second),
                "an existing parent is not replaced"
            );
            state.attach_kmdf_parent(first, 0xDEAD_BEEF);
            assert_eq!(
                state
                    .kmdf
                    .objects
                    .get(&first)
                    .and_then(|object| object.parent),
                Some(second),
                "an unknown parent leaves the object untouched"
            );
            state.attach_kmdf_parent(0xDEAD_BEEF, second);
            assert!(
                !state.kmdf.objects.contains_key(&0xDEAD_BEEF),
                "an unknown handle is ignored"
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[0xDEAD, 0, 0, 0, out],
            )
            .expect("wrong driver object"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, 0, 0],
            )
            .expect("null driver out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, u64::MAX, out],
            )
            .expect("unmapped config"),
            STATUS_INVALID_PARAMETER
        );
        let small_config = 0x58_100;
        memory.map_bytes(small_config, &[0_u8; 0x40]);
        memory.write_u32(small_config, 4);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, small_config, out],
            )
            .expect("undersized config"),
            STATUS_INVALID_PARAMETER
        );
        let good_config = 0x58_200;
        memory.map_bytes(good_config, &[0_u8; 0x40]);
        memory.write_u32(good_config, 0x20);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, good_config, out],
            )
            .expect("driver create without device add"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, good_config, out],
            )
            .expect("driver create reuses framework dispatches"),
            STATUS_SUCCESS
        );

        let init = *island
            .inner
            .borrow()
            .kmdf
            .device_inits
            .keys()
            .next()
            .expect("device init");
        let name = guest_unicode_string(&mut memory, 0x59_000, "\\Device\\WdfCasa");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetDeviceType,
                &[0xDEAD, 1],
            )
            .expect("set type on missing init"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetIoType,
                &[0xDEAD, 1],
            )
            .expect("set io type on missing init"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitAssignName,
                &[0xDEAD, name],
            )
            .expect("assign name on missing init"),
            STATUS_INVALID_PARAMETER
        );
        let init_pointer = 0x59_800;
        memory.map_bytes(init_pointer, &[0_u8; 8]);
        memory.write_u64(init_pointer, init);
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[init_pointer, 0, out],
            )
            .expect("duplicate device through init pointer"),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[init, 0, out],
            )
            .expect("duplicate device through init handle"),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[init, 0, 0],
            )
            .expect("null device out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitAssignName,
                &[init, 0],
            )
            .expect("clear init name"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[init, 0, out],
            )
            .expect("unnamed device via cleared init"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[0xDEAD, 0, out],
            )
            .expect("missing init"),
            STATUS_INVALID_PARAMETER
        );

        let device = island.kmdf_device_handles()[0];
        let queue_out = 0x5A_000;
        memory.map_bytes(queue_out, &[0_u8; 8]);
        let parentless_queue_out = 0x5A_100;
        memory.map_bytes(parentless_queue_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, 0, 0, parentless_queue_out],
            )
            .expect("parentless queue creation"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[0xDEAD, 0, 0, queue_out],
            )
            .expect("queue for missing device"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, 0, 0, 0],
            )
            .expect("null queue out"),
            STATUS_INVALID_PARAMETER
        );
        let queue_config = 0x5A_100;
        memory.map_bytes(queue_config, &[0_u8; 0x60]);
        memory.write_u32(queue_config, 4);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, 1, 0, queue_out],
            )
            .expect("unmapped queue config"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, queue_config, 0, queue_out],
            )
            .expect("undersized queue config"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u32(queue_config, 0x50);
        memory.write_u32(queue_config + 4, 3);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, queue_config, 0, queue_out],
            )
            .expect("unsupported dispatch type"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u32(queue_config + 4, 1);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, queue_config, 0, queue_out],
            )
            .expect("valid queue"),
            STATUS_SUCCESS
        );

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, 0],
            )
            .expect("null request out"),
            STATUS_INVALID_PARAMETER
        );
        let request_out = 0x5B_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request for live device"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_ne!(request, 0);
        let queue = *island.inner.borrow().kmdf.queues.keys().next().unwrap();
        let target = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfDeviceGetIoTarget,
            &[device],
        )
        .expect("request target");
        assert_ne!(target, 0);
        let saved_devices = {
            let mut state = island.inner.borrow_mut();
            std::mem::take(&mut state.kmdf.devices)
        };
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, 0, request_out],
            )
            .expect("request without devices"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        island.inner.borrow_mut().kmdf.devices = saved_devices;
        let saved_device = {
            let mut state = island.inner.borrow_mut();
            state.kmdf.devices.remove(&device)
        };
        assert!(saved_device.is_some());
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, target, request_out],
            )
            .expect("request for stale iotarget device"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        if let Some(device_record) = saved_device {
            island
                .inner
                .borrow_mut()
                .kmdf
                .devices
                .insert(device, device_record);
        }
        {
            let mut state = island.inner.borrow_mut();
            let missing = state.new_kmdf_request(
                &mut memory,
                0xDEAD,
                queue,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            );
            assert_eq!(
                missing.expect("missing device result"),
                Err(STATUS_INVALID_DEVICE_REQUEST)
            );
            let casak = state.kmdf.devices.get(&device).unwrap().casak;
            let _ = state.io.delete_device(casak);
            let deleted = state.new_kmdf_request(
                &mut memory,
                device,
                queue,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            );
            assert_eq!(
                deleted.expect("deleted device result"),
                Err(crate::casak::io::STATUS_DELETE_PENDING as i32)
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("shim allocation failure"),
            crate::casak::io::STATUS_DELETE_PENDING as i32
        );
    });
}

#[test]
fn kmdf_requests_and_iotargets_reject_bad_handles_and_buffers() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaKmdfBadReq");
        let device_a = island.kmdf_device_handles()[0];
        let device_b = island.kmdf_device_handles()[1];

        let out = 0x5C_000;
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device_a, out],
            )
            .expect("request a"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(out).unwrap();

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForIoctl,
                &[0xDEAD, device_a, 1, 0, 0, 0, 0, 0],
            )
            .expect("format missing request"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestRetrieveInputBuffer,
                &[request, 0, 0, out],
            )
            .expect("retrieve null buffer out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestRetrieveInputBuffer,
                &[0xDEAD, 0, out, out],
            )
            .expect("retrieve missing request"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestRetrieveOutputBuffer,
                &[request, 1, out, out],
            )
            .expect("retrieve beyond buffer"),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[0xDEAD, STATUS_SUCCESS as u64],
            )
            .expect("complete missing request"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[request, STATUS_SUCCESS as u64],
            )
            .expect("complete request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[request, STATUS_SUCCESS as u64],
            )
            .expect("double complete"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceWdmGetDeviceObject,
                &[0xDEAD],
            )
            .expect("missing device object"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[0xDEAD, 0],
            )
            .expect("missing typed context"),
            0
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectAllocateContext,
                &[device_a, 0, 0],
            )
            .expect("null context out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectAllocateContext,
                &[0xDEAD, 0, out],
            )
            .expect("context for missing object"),
            STATUS_INVALID_HANDLE
        );
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device_a, out],
            )
            .expect("request for context"),
            STATUS_SUCCESS
        );
        let context_request = memory.read_u64(out).unwrap();
        let context_out = 0x5C_100;
        memory.map_bytes(context_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectAllocateContext,
                &[context_request, 0, context_out],
            )
            .expect("default context size"),
            STATUS_SUCCESS
        );
        let default_context = memory.read_u64(context_out).unwrap();
        assert_eq!(
            island.kmdf_context_size(context_request),
            Some(0x80),
            "the request kind's default context size is used"
        );
        let type_info = 0x5C_200;
        memory.map_bytes(type_info, &[0_u8; 0x20]);
        memory.write_u32(type_info, 0x18);
        memory.write_u64(type_info + 0x10, 0x20);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectAllocateContext,
                &[context_request, type_info, context_out],
            )
            .expect("typed context size"),
            STATUS_SUCCESS
        );
        let typed_context = memory.read_u64(context_out).unwrap();
        assert_ne!(typed_context, default_context);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[context_request, type_info],
            )
            .expect("typed context lookup"),
            typed_context
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[0xDEAD],
            )
            .expect("delete missing object"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[context_request],
            )
            .expect("delete context request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[context_request],
            )
            .expect("double delete object"),
            STATUS_INVALID_HANDLE
        );
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device_a, out],
            )
            .expect("deleted object request"),
            STATUS_SUCCESS
        );
        let deleted_object = memory.read_u64(out).unwrap();
        island
            .inner
            .borrow_mut()
            .kmdf
            .objects
            .get_mut(&deleted_object)
            .unwrap()
            .deleted = true;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[deleted_object],
            )
            .expect("delete already deleted object"),
            STATUS_INVALID_HANDLE
        );

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceGetIoTarget,
                &[0xDEAD],
            )
            .expect("target for missing device"),
            STATUS_INVALID_HANDLE
        );
        let target_out = 0x5D_000;
        memory.map_bytes(target_out, &[0_u8; 8]);
        let target_a = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfDeviceGetIoTarget,
            &[device_a],
        )
        .expect("target a");
        assert_ne!(target_a, 0);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceGetIoTarget,
                &[device_a],
            )
            .expect("cached target a"),
            target_a
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetCreate,
                &[0xDEAD, 0, target_out],
            )
            .expect("target for missing device create"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetCreate,
                &[device_a, 0, 0],
            )
            .expect("null target out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetCreate,
                &[device_b, 0, target_out],
            )
            .expect("target b"),
            STATUS_SUCCESS
        );
        let target_b = memory.read_u64(target_out).unwrap();
        assert_ne!(target_b, 0);

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetFormatRequestForIoctl,
                &[target_b, 0xDEAD, 1, 0, 0, 0, 0],
            )
            .expect("format missing request"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSend,
                &[0xDEAD, target_b, 0],
            )
            .expect("send missing request"),
            STATUS_INVALID_HANDLE
        );

        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device_a, out],
            )
            .expect("send request"),
            STATUS_SUCCESS
        );
        let send_request = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSend,
                &[send_request, 0, 0],
            )
            .expect("send with implicit target"),
            STATUS_PENDING
        );
        {
            let mut state = island.inner.borrow_mut();
            let request = state.kmdf.requests.get_mut(&send_request).unwrap();
            request.completed = false;
            request.input_guest = 1;
            request.input_len = 4;
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSend,
                &[send_request, 0, 0],
            )
            .expect("send with unreadable input"),
            STATUS_INVALID_PARAMETER
        );

        let bad_input = 1;
        let input_descriptor = 0x5E_100;
        memory.map_bytes(input_descriptor, &[0_u8; 0x20]);
        memory.write_u64(input_descriptor + 8, bad_input);
        memory.write_u64(input_descriptor + 0x10, 4);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetSendIoctlSynchronously,
                &[target_a, 0, 0x22_0004, input_descriptor, 0, 0, 0],
            )
            .expect("sync send with unreadable input"),
            STATUS_INVALID_PARAMETER
        );

        let saved_devices = {
            let mut state = island.inner.borrow_mut();
            std::mem::take(&mut state.kmdf.devices)
        };
        {
            let mut state = island.inner.borrow_mut();
            if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                request.completed = false;
                request.input_guest = 0;
                request.input_len = 0;
                request.target = Some(target_b);
            }
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSend,
                &[send_request, target_b, 0],
            )
            .expect("send to iotarget with no device"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        {
            let mut state = island.inner.borrow_mut();
            if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                request.completed = false;
                request.target = None;
            }
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetSendIoctlSynchronously,
                &[0, 0, 0, 0, 0, 0, 0],
            )
            .expect("sync send with no devices"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        island.inner.borrow_mut().kmdf.devices = saved_devices;

        {
            let mut state = island.inner.borrow_mut();
            let casak = state.kmdf.devices.get(&device_b).unwrap().casak;
            let _ = state.io.delete_device(casak);
        }
        {
            let mut state = island.inner.borrow_mut();
            if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                request.completed = false;
            }
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSend,
                &[send_request, device_b, 0],
            )
            .expect("send after casak device deletion"),
            STATUS_INVALID_DEVICE_REQUEST
        );

        island
            .inner
            .borrow_mut()
            .apply_iotarget_result(&mut memory, 0xDEAD, STATUS_SUCCESS, 0)
            .expect("missing request result");

        let driver = island.driver_object_pointer();
        let major_slot = driver + 0x70 + IrpMajorFunction::DeviceControl.code() as u64 * 8;
        memory.write_u64(major_slot, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetSendIoctlSynchronously,
                &[device_a, 0, 0x22_0004, 0, 0, 0, 0],
            )
            .expect("sync send with no handler"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        let default_dispatch = island.inner.borrow().default_dispatch;
        memory.write_u64(major_slot, default_dispatch);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetSendIoctlSynchronously,
                &[device_a, 0, 0x22_0004, 0, 0, 0, 0],
            )
            .expect("sync send with default handler"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        let framework_dispatch = island.inner.borrow().kmdf.framework_dispatch;
        assert_ne!(framework_dispatch, 0);
        memory.write_u64(major_slot, framework_dispatch);
    });
}

fn kmdf_device_named(island: &DriverIsland, name: &str) -> u64 {
    island
        .inner
        .borrow()
        .kmdf
        .devices
        .iter()
        .find(|(_, device)| device.name.ends_with(name))
        .map(|(handle, _)| *handle)
        .expect("named kmdf device")
}

fn make_kmdf_request(
    island: &DriverIsland,
    memory: &mut MemoryImage,
    device: u64,
    queue: u64,
    major: IrpMajorFunction,
) -> u64 {
    island
        .inner
        .borrow_mut()
        .new_kmdf_request(memory, device, queue, major, 0, 0, 0, 0, 0, 0)
        .expect("request result")
        .expect("request")
}

#[test]
fn kmdf_queue_edges_reject_stale_requests_and_recover_from_drain_races() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(2, true);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaKmdfQueueEdge");
        let image_base = island.image_base();
        let device_a = kmdf_device_named(&island, "WdfA");
        let device_b = kmdf_device_named(&island, "WdfB");
        let device_a_guest = island
            .created_devices()
            .into_iter()
            .find(|device| device.name.ends_with("WdfA"))
            .map(|device| device.guest_pointer)
            .expect("device a guest");
        let device_b_guest = island
            .created_devices()
            .into_iter()
            .find(|device| device.name.ends_with("WdfB"))
            .map(|device| device.guest_pointer)
            .expect("device b guest");
        let queue_a = queue_for_device(&island, device_a);
        let queue_b = island
            .inner
            .borrow()
            .kmdf
            .queues
            .iter()
            .find(|(_, queue)| queue.device == device_b)
            .map(|(handle, _)| *handle)
            .expect("queue for device b");
        let ret_stub = x64_ret_stub(&mut memory, &island);
        let complete = x64_complete_stub(&mut runtime, &mut memory, &island, STATUS_SUCCESS, 0);

        set_queue_callbacks(&island, queue_a, |queue| {
            queue.callbacks.default = 0;
            queue.callbacks.read = 0;
            queue.callbacks.write = 0;
            queue.callbacks.device_control = 0;
            queue.dispatch_type = 0;
            queue.stopped = false;
            queue.draining = false;
            queue.queued.clear();
            queue.in_flight.clear();
        });

        let request = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        island
            .inner
            .borrow_mut()
            .kmdf
            .queues
            .get_mut(&queue_a)
            .unwrap()
            .queued
            .push_back(request);
        {
            let mut state = island.inner.borrow_mut();
            assert!(
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("entry zero dispatch")
                    .is_none()
            );
        }
        let (completed, status, _, _) = island.kmdf_request_state(request).unwrap();
        assert!(completed);
        assert_eq!(status, STATUS_INVALID_DEVICE_REQUEST);

        let cleanup = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::Cleanup,
        );
        island
            .inner
            .borrow_mut()
            .kmdf
            .queues
            .get_mut(&queue_a)
            .unwrap()
            .queued
            .push_back(cleanup);
        {
            let mut state = island.inner.borrow_mut();
            assert!(
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("cleanup entry zero")
                    .is_none()
            );
        }
        let (completed, status, _, _) = island.kmdf_request_state(cleanup).unwrap();
        assert!(completed);
        assert_eq!(status, STATUS_SUCCESS);

        island
            .inner
            .borrow_mut()
            .kmdf
            .queues
            .get_mut(&queue_a)
            .unwrap()
            .queued
            .push_back(0xDEAD);
        {
            let mut state = island.inner.borrow_mut();
            assert!(
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("stale queued handle")
                    .is_none()
            );
        }
        assert!(
            island
                .inner
                .borrow()
                .kmdf
                .queues
                .get(&queue_a)
                .unwrap()
                .queued
                .is_empty()
        );

        island
            .inner
            .borrow_mut()
            .kmdf
            .queues
            .get_mut(&queue_a)
            .unwrap()
            .draining = true;
        {
            let mut state = island.inner.borrow_mut();
            assert!(
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("drained queue")
                    .is_none()
            );
        }
        {
            let state = island.inner.borrow();
            let queue = state.kmdf.queues.get(&queue_a).unwrap();
            assert!(!queue.draining);
            assert!(queue.stopped);
        }

        let type2 = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        {
            let mut state = island.inner.borrow_mut();
            let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
            queue.dispatch_type = 2;
            queue.stopped = false;
            queue.draining = false;
            queue.queued.push_back(type2);
        }
        {
            let mut state = island.inner.borrow_mut();
            assert!(
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("manual queue skipped")
                    .is_none()
            );
        }
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .queues
                .get(&queue_a)
                .unwrap()
                .queued
                .len(),
            1
        );

        {
            let mut state = island.inner.borrow_mut();
            let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
            queue.dispatch_type = 0;
            queue.stopped = true;
            queue.draining = false;
        }
        {
            let mut state = island.inner.borrow_mut();
            assert!(
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("stopped queue skipped")
                    .is_none()
            );
        }
        {
            let mut state = island.inner.borrow_mut();
            let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
            queue.stopped = false;
            queue.in_flight.insert(type2);
        }
        {
            let mut state = island.inner.borrow_mut();
            assert!(
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("sequential in-flight skip")
                    .is_none()
            );
        }
        {
            let mut state = island.inner.borrow_mut();
            let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
            queue.queued.clear();
            queue.in_flight.clear();
            queue.callbacks.default = complete;
        }

        for (major, label, counter) in [
            (IrpMajorFunction::Read, "EvtIoRead", 0usize),
            (IrpMajorFunction::Write, "EvtIoWrite", 1),
            (IrpMajorFunction::DeviceControl, "EvtIoDeviceControl", 2),
            (IrpMajorFunction::Cleanup, "EvtIoDefault", 3),
            (IrpMajorFunction::Close, "EvtIoDefault", 4),
            (IrpMajorFunction::Create, "EvtIoDefault", 5),
        ] {
            let request = make_kmdf_request(&island, &mut memory, device_a, queue_a, major);
            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .queued
                .push_back(request);
            let call = {
                let mut state = island.inner.borrow_mut();
                state
                    .dispatch_next_queued(&mut memory)
                    .expect("queued dispatch")
                    .expect("callback")
            };
            assert_eq!(call.label, label);
            assert_eq!(call.args[1], request);
            {
                let mut state = island.inner.borrow_mut();
                let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
                queue.in_flight.remove(&request);
            }
            let state = island.inner.borrow();
            let counters = [
                state.kmdf.read_dispatches,
                state.kmdf.write_dispatches,
                state.kmdf.ioctl_dispatches,
                state.kmdf.cleanup_dispatches,
                state.kmdf.close_dispatches,
                state.kmdf.queued_dispatches,
            ];
            let expected = match counter {
                0 => [1, 0, 0, 0, 0, 1],
                1 => [1, 1, 0, 0, 0, 2],
                2 => [1, 1, 1, 0, 0, 3],
                3 => [1, 1, 1, 1, 0, 4],
                4 => [1, 1, 1, 1, 1, 5],
                _ => [1, 1, 1, 1, 1, 6],
            };
            assert_eq!(counters, expected, "counter {counter}");
        }

        let device_object = island
            .inner
            .borrow()
            .kmdf
            .devices
            .get(&device_a)
            .unwrap()
            .object_guest;
        let mut cpu = CpuState::new(GuestArch::X64);
        cpu.set(Register::Rcx, 0);
        cpu.set(Register::Rdx, device_object);
        let mut state = island.inner.borrow_mut();
        let call = state
            .wdf_dispatch(IrpMajorFunction::Create, &mut cpu, &mut memory)
            .expect("unsupported major dispatch")
            .expect("default callback");
        assert_eq!(call.label, "EvtIoDefault");
        let queue = state.kmdf.queues.get(&queue_a).unwrap().clone();
        drop(state);
        for request in queue.in_flight.iter() {
            island
                .inner
                .borrow_mut()
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .in_flight
                .remove(request);
        }

        let irp_guest = 0x5F_800;
        memory.map_bytes(irp_guest, &[0_u8; 0x100]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtIoDeviceControlDispatch,
                &[irp_guest, 0xDEAD],
            )
            .expect("dispatch for missing device object"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            memory.read_u32(irp_guest + 0x30).unwrap(),
            STATUS_INVALID_DEVICE_REQUEST as u32
        );

        {
            let mut state = island.inner.borrow_mut();
            let casak = state.kmdf.devices.get(&device_b).unwrap().casak;
            let _ = state.io.delete_device(casak);
        }
        let (status, _) = island
            .dispatch_irp(
                &mut runtime,
                &mut memory,
                device_b_guest,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("dispatch after casak deletion");
        assert_eq!(status, crate::casak::io::STATUS_DELETE_PENDING as i32);

        set_queue_callbacks(&island, queue_a, |queue| {
            queue.callbacks.default = 0;
            queue.callbacks.read = 0;
            queue.callbacks.write = 0;
            queue.callbacks.device_control = 0;
            queue.dispatch_type = 0;
            queue.stopped = false;
            queue.draining = false;
            queue.queued.clear();
            queue.in_flight.clear();
        });
        let (status, _) = island
            .dispatch_irp(
                &mut runtime,
                &mut memory,
                device_a_guest,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("ioctl without callback");
        assert_eq!(status, STATUS_INVALID_DEVICE_REQUEST);
        for major in [IrpMajorFunction::Cleanup, IrpMajorFunction::Close] {
            let (status, _) = island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device_a_guest,
                    major,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("cleanup dispatch without callback");
            assert_eq!(status, STATUS_SUCCESS);
        }

        {
            let mut state = island.inner.borrow_mut();
            state
                .complete_kmdf_request(&mut memory, 0xDEAD, STATUS_SUCCESS, 0)
                .expect("complete missing request");
        }
        let done = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        {
            let mut state = island.inner.borrow_mut();
            state
                .complete_kmdf_request(&mut memory, done, STATUS_SUCCESS, 4)
                .expect("complete request");
            state
                .complete_kmdf_request(&mut memory, done, STATUS_SUCCESS, 4)
                .expect("double complete is ignored");
        }
        let draining = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        {
            let mut state = island.inner.borrow_mut();
            state
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .in_flight
                .insert(draining);
            state.kmdf.queues.get_mut(&queue_a).unwrap().draining = true;
            state.kmdf.queues.get_mut(&queue_a).unwrap().queued.clear();
            state
                .complete_kmdf_request(&mut memory, draining, STATUS_SUCCESS, 0)
                .expect("complete draining request");
            let queue = state.kmdf.queues.get(&queue_a).unwrap();
            assert!(!queue.draining);
            assert!(queue.stopped);
        }

        set_queue_callbacks(&island, queue_a, |queue| {
            queue.callbacks.default = complete;
            queue.callbacks.read = 0;
            queue.callbacks.write = 0;
            queue.callbacks.device_control = 0;
            queue.dispatch_type = 0;
            queue.stopped = false;
            queue.draining = false;
            queue.queued.clear();
            queue.in_flight.clear();
        });
        let (device_handle, file_status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x5A_000);
        assert_eq!(file_status, STATUS_SUCCESS);
        let buffer = 0x5B_000;
        let iosb = 0x5B_100;
        memory.map_bytes(buffer, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtReadFile,
                &[u64::from(device_handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
            ),
            STATUS_SUCCESS,
            "read falls back to the default queue callback"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtWriteFile,
                &[u64::from(device_handle), 0, 0, 0, iosb, buffer, 8, 0, 0],
            ),
            STATUS_SUCCESS,
            "write falls back to the default queue callback"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(device_handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x0022_0004,
                    buffer,
                    8,
                    buffer,
                    8,
                ],
            ),
            STATUS_SUCCESS,
            "ioctl falls back to the default queue callback"
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtClose,
                &[u64::from(device_handle)],
            ),
            STATUS_SUCCESS
        );

        memory.map_bytes(0x5F_000, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueRetrieveNextRequest,
                &[queue_b, 0],
            )
            .expect("retrieve null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueRetrieveNextRequest,
                &[0xDEAD, 0x5F_000],
            )
            .expect("retrieve missing queue"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueRetrieveNextRequest,
                &[queue_b, 0x5F_000],
            )
            .expect("retrieve from empty queue"),
            STATUS_NO_MORE_ENTRIES
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStop,
                &[0xDEAD],
            )
            .expect("stop missing queue"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueDrain,
                &[queue_b],
            )
            .expect("drain empty queue"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueDrainSynchronously,
                &[queue_b],
            )
            .expect("drain synchronously empty queue"),
            STATUS_SUCCESS
        );

        let stop_count = memory
            .read_u32(image_base + u64::from(F_STOP_COUNT))
            .unwrap();
        let stop_request = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        {
            let mut state = island.inner.borrow_mut();
            let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
            queue.callbacks.default = ret_stub;
            queue.callbacks.stop = image_base + u64::from(F_STOP_RVA);
            queue.callbacks.resume = image_base + u64::from(F_RESUME_RVA);
            queue.in_flight.insert(stop_request);
            queue.queued.clear();
            queue.stopped = false;
            queue.draining = false;
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStop,
                &[queue_a],
            )
            .expect("stop with in-flight request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_STOP_COUNT))
                .unwrap(),
            stop_count + 1
        );
        let resume_count = memory
            .read_u32(image_base + u64::from(F_RESUME_COUNT))
            .unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStart,
                &[queue_a],
            )
            .expect("resume in-flight request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_RESUME_COUNT))
                .unwrap(),
            resume_count + 1
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStart,
                &[0xDEAD],
            )
            .expect("start missing queue"),
            STATUS_INVALID_HANDLE
        );
        {
            let mut state = island.inner.borrow_mut();
            state
                .kmdf
                .queues
                .get_mut(&queue_a)
                .unwrap()
                .in_flight
                .clear();
            state
                .kmdf
                .requests
                .get_mut(&stop_request)
                .unwrap()
                .completed = true;
        }

        let cancel_before = memory
            .read_u32(image_base + u64::from(F_CANCEL_COUNT))
            .unwrap();
        let queued_cancel = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        let inflight_cancel = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        {
            let mut state = island.inner.borrow_mut();
            let queue = state.kmdf.queues.get_mut(&queue_a).unwrap();
            queue.callbacks.canceled_on_queue = image_base + u64::from(F_CANCEL_RVA);
            queue.queued.push_back(queued_cancel);
            queue.in_flight.insert(inflight_cancel);
            queue.stopped = false;
            queue.draining = false;
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueuePurge,
                &[queue_a],
            )
            .expect("purge with cancel callback"),
            STATUS_SUCCESS
        );
        for request in [queued_cancel, inflight_cancel] {
            let (completed, status, _, _) = island.kmdf_request_state(request).unwrap();
            assert!(completed);
            assert_eq!(status, STATUS_CANCELLED);
        }
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_CANCEL_COUNT))
                .unwrap(),
            cancel_before + 2
        );

        set_queue_callbacks(&island, queue_a, |queue| {
            queue.callbacks.canceled_on_queue = 0;
        });
        let force_cancel = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        island
            .inner
            .borrow_mut()
            .kmdf
            .queues
            .get_mut(&queue_a)
            .unwrap()
            .queued
            .push_back(force_cancel);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueuePurgeSynchronously,
                &[queue_a],
            )
            .expect("purge without cancel callback"),
            STATUS_SUCCESS
        );
        let (completed, status, _, _) = island.kmdf_request_state(force_cancel).unwrap();
        assert!(completed);
        assert_eq!(status, STATUS_CANCELLED);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueuePurgeSynchronously,
                &[0xDEAD],
            )
            .expect("purge missing queue"),
            STATUS_INVALID_HANDLE
        );

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCancelQueuedRequest,
                &[0xDEAD],
            )
            .expect("cancel missing request"),
            STATUS_INVALID_HANDLE
        );
        let no_queue = make_kmdf_request(
            &island,
            &mut memory,
            device_a,
            queue_a,
            IrpMajorFunction::DeviceControl,
        );
        {
            let mut state = island.inner.borrow_mut();
            state.kmdf.requests.get_mut(&no_queue).unwrap().queue = None;
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCancelQueuedRequest,
                &[no_queue],
            )
            .expect("cancel request without queue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        {
            let mut state = island.inner.borrow_mut();
            state.kmdf.requests.get_mut(&no_queue).unwrap().queue = Some(0xDEAD);
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCancelQueuedRequest,
                &[no_queue],
            )
            .expect("cancel request with missing queue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        {
            let mut state = island.inner.borrow_mut();
            state.kmdf.requests.get_mut(&no_queue).unwrap().queue = Some(queue_a);
            state.kmdf.queues.get_mut(&queue_a).unwrap().queued.clear();
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCancelQueuedRequest,
                &[no_queue],
            )
            .expect("cancel request not queued"),
            STATUS_INVALID_DEVICE_REQUEST
        );
    });
}

#[test]
fn kmdf_wait_lock_rejects_invalid_handles_and_recovers_from_poison() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaKmdfBadLock");
        let lock = island.kmdf_wait_lock_handles()[0];
        let driver = island.kmdf_driver_handle();
        let out = 0x5F_000;
        memory.map_bytes(out, &[0_u8; 8]);

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockCreate,
                &[0, 0],
            )
            .expect("null lock out"),
            STATUS_INVALID_PARAMETER
        );
        let attrs = 0x5F_100;
        let type_info = 0x5F_200;
        memory.map_bytes(attrs, &[0_u8; 0x38]);
        memory.map_bytes(type_info, &[0_u8; 0x20]);
        memory.write_u32(attrs, 0x38);
        memory.write_u64(attrs + 0x20, driver);
        memory.write_u64(attrs + 0x28, 0);
        memory.write_u64(attrs + 0x30, type_info);
        memory.write_u32(type_info, 0x18);
        memory.write_u64(type_info + 0x10, 0x20);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockCreate,
                &[attrs, out],
            )
            .expect("typed wait lock"),
            STATUS_SUCCESS
        );
        let typed_lock = memory.read_u64(out).unwrap();
        assert_eq!(island.kmdf_context_size(typed_lock), Some(0x20));
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .objects
                .get(&typed_lock)
                .and_then(|object| object.parent),
            Some(driver)
        );
        assert!(
            island
                .inner
                .borrow()
                .kmdf
                .objects
                .get(&driver)
                .is_some_and(|object| object.children.contains(&typed_lock))
        );
        memory.map_bytes(0x5F_FFC, &[0_u8; 4]);
        memory.write_u32(0x5F_FFC, 0x38);
        let ignored = island
            .inner
            .borrow()
            .parse_object_attributes(&memory, 0x5F_FFC)
            .expect("invalid attrs are ignored");
        assert_eq!(ignored.evt_cleanup, 0);
        assert_eq!(ignored.evt_destroy, 0);
        assert!(ignored.parent.is_none());
        assert_eq!(ignored.context_size_override, 0);
        assert_eq!(ignored.context_type_info, 0);

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockAcquire,
                &[0xDEAD, 0],
            )
            .expect("acquire missing lock"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockRelease,
                &[0xDEAD],
            )
            .expect("release missing lock"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockAcquire,
                &[lock, 0],
            )
            .expect("acquire lock"),
            STATUS_SUCCESS
        );
        let zero_timeout = 0x5F_300;
        memory.map_bytes(zero_timeout, &[0_u8; 8]);
        memory.write_u64(zero_timeout, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockAcquire,
                &[lock, zero_timeout],
            )
            .expect("zero timeout on held lock"),
            STATUS_TIMEOUT
        );
        let gate = island.kmdf_wait_lock_gate(lock).unwrap();
        let releaser = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                let (mutex, wake) = &*gate;
                let mut locked = mutex.lock().unwrap();
                *locked = false;
                drop(locked);
                wake.notify_all();
            })
        };
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockAcquire,
                &[lock, 0],
            )
            .expect("infinite wait"),
            STATUS_SUCCESS
        );
        releaser.join().expect("releaser");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockRelease,
                &[lock],
            )
            .expect("release lock"),
            STATUS_SUCCESS
        );

        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockCreate,
                &[0, out],
            )
            .expect("poisoned lock create"),
            STATUS_SUCCESS
        );
        let poisoned = memory.read_u64(out).unwrap();
        let gate = island.kmdf_wait_lock_gate(poisoned).unwrap();
        let poisoner = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                let (mutex, _) = &*gate;
                let mut locked = mutex.lock().unwrap();
                *locked = true;
                panic!("poison the wait lock");
            })
        };
        assert!(poisoner.join().is_err(), "the poisoner panics");
        let tiny_timeout = 0x5F_400;
        memory.map_bytes(tiny_timeout, &[0_u8; 8]);
        memory.write_u64(tiny_timeout, (-1_i64) as u64);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockAcquire,
                &[poisoned, tiny_timeout],
            )
            .expect("poisoned timed acquire"),
            STATUS_TIMEOUT
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockRelease,
                &[poisoned],
            )
            .expect("poisoned release"),
            STATUS_SUCCESS
        );

        let absolute = 0x5F_500;
        memory.map_bytes(absolute, &[0_u8; 8]);
        memory.write_u64(absolute, 10);
        let island_state = island.inner.borrow();
        assert_eq!(
            island_state
                .wait_lock_timeout(&memory, absolute)
                .expect("absolute timeout"),
            Some(Duration::from_nanos(1_000))
        );
        assert_eq!(
            island_state
                .wait_lock_timeout(&memory, zero_timeout)
                .expect("zero timeout"),
            Some(Duration::ZERO)
        );
    });
}

#[test]
fn kmdf_object_cascade_cancels_queued_requests_and_rejects_stale_objects() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaKmdfCascade");
        let device = island.kmdf_device_handles()[0];

        let mut callbacks = Vec::new();
        island
            .inner
            .borrow_mut()
            .collect_delete_callbacks(0xDEAD, &mut callbacks);
        assert!(callbacks.is_empty());

        let out = 0x50_000;
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, out],
            )
            .expect("cascade request"),
            STATUS_SUCCESS
        );
        let cascade_request = memory.read_u64(out).unwrap();
        {
            let mut state = island.inner.borrow_mut();
            state
                .kmdf
                .objects
                .get_mut(&cascade_request)
                .unwrap()
                .deleted = true;
            let mut callbacks = Vec::new();
            state.collect_delete_callbacks(cascade_request, &mut callbacks);
            assert!(callbacks.is_empty());
        }
        {
            let mut state = island.inner.borrow_mut();
            assert!(!state.force_cancel_request(0xDEAD));
            assert!(
                state.force_cancel_request(cascade_request),
                "a stale-deleted request is still cancelable"
            );
        }

        let config = 0x51_000;
        let queue_out = 0x52_000;
        memory.map_bytes(config, &[0_u8; 0x60]);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(config, 0x50);
        memory.write_u32(config + 4, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("cascade queue"),
            STATUS_SUCCESS
        );
        let cascade_queue = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, out],
            )
            .expect("queued cascade request"),
            STATUS_SUCCESS
        );
        let queued = memory.read_u64(out).unwrap();
        {
            let mut state = island.inner.borrow_mut();
            state
                .kmdf
                .queues
                .get_mut(&cascade_queue)
                .unwrap()
                .queued
                .push_back(queued);
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[cascade_queue],
            )
            .expect("delete queue with queued requests"),
            STATUS_SUCCESS
        );
        let (canceled, status, _, _) = island.kmdf_request_state(queued).unwrap();
        assert!(canceled);
        assert_eq!(status, STATUS_CANCELLED);

        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, out],
            )
            .expect("current request"),
            STATUS_SUCCESS
        );
        let current = memory.read_u64(out).unwrap();
        island.inner.borrow_mut().kmdf.current_request = current;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[current],
            )
            .expect("delete current request"),
            STATUS_SUCCESS
        );
        assert_eq!(island.inner.borrow().kmdf.current_request, 0);

        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, out],
            )
            .expect("completed request"),
            STATUS_SUCCESS
        );
        let completed = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[completed, STATUS_SUCCESS as u64],
            )
            .expect("complete request"),
            STATUS_SUCCESS
        );
        assert!(!island.inner.borrow_mut().force_cancel_request(completed));
    });
}

#[test]
fn x86_kmdf_layout_paths_and_shims_reject_malformed_blocks() {
    with_big_stack(|| {
        let image = build_kmdf_driver_pe32();
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x86(&image, "CasaX86Layout");
        let driver = island.kmdf_driver_handle();
        let device = island.kmdf_device_handles()[0];

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetDeviceType,
                &[0xDEAD, 1],
            )
            .expect("x86 missing init"),
            STATUS_INVALID_PARAMETER
        );

        let irp_guest = 0x50_000;
        memory.map_bytes(irp_guest, &[0_u8; 0x100]);
        {
            let state = island.inner.borrow();
            state
                .write_irp_status(&mut memory, irp_guest, STATUS_ACCESS_VIOLATION, 7)
                .expect("x86 irp status");
        }
        assert_eq!(
            memory.read_u32(irp_guest + 0x18).unwrap(),
            STATUS_ACCESS_VIOLATION as u32
        );
        assert_eq!(memory.read_u32(irp_guest + 0x20).unwrap(), 7);

        let attrs = 0x51_000;
        let type_info = 0x51_040;
        memory.map_bytes(attrs, &[0_u8; 0x40]);
        memory.write_u32(attrs, 0x30);
        memory.write_u32(attrs + 0x04, 0);
        memory.write_u32(attrs + 0x08, 0);
        memory.write_u32(attrs + 0x14, driver as u32);
        memory.write_u32(attrs + 0x18, 0);
        memory.write_u32(attrs + 0x1C, type_info as u32);
        let parsed = island
            .inner
            .borrow()
            .parse_object_attributes(&memory, attrs)
            .expect("x86 attributes");
        assert_eq!(parsed.evt_cleanup, 0);
        assert_eq!(parsed.evt_destroy, 0);
        assert_eq!(parsed.parent, Some(driver));
        assert_eq!(parsed.context_size_override, 0);
        assert_eq!(parsed.context_type_info, u64::from(type_info as u32));

        memory.map_bytes(type_info, &[0_u8; 0x20]);
        memory.write_u32(type_info + 0x08, 0x18);
        assert_eq!(
            island
                .inner
                .borrow()
                .context_type_size(&memory, type_info)
                .expect("x86 context type size"),
            0x18
        );

        let timeout = 0x52_000;
        memory.map_bytes(timeout, &[0_u8; 8]);
        memory.write_u32(timeout, 0);
        assert_eq!(
            island
                .inner
                .borrow()
                .wait_lock_timeout(&memory, timeout)
                .expect("x86 zero timeout"),
            Some(Duration::ZERO)
        );
        memory.write_u32(timeout, 10);
        assert_eq!(
            island
                .inner
                .borrow()
                .wait_lock_timeout(&memory, timeout)
                .expect("x86 absolute timeout"),
            Some(Duration::from_nanos(1_000))
        );
        memory.write_u32(timeout, (-1_i32) as u32);
        assert_eq!(
            island
                .inner
                .borrow()
                .wait_lock_timeout(&memory, timeout)
                .expect("x86 relative timeout"),
            Some(Duration::from_nanos(100))
        );

        let descriptor = 0x53_000;
        memory.map_bytes(descriptor, &[0_u8; 0x20]);
        memory.write_u32(descriptor, 0);
        memory.write_u32(descriptor + 4, 0x1234_5678);
        memory.write_u32(descriptor + 8, 9);
        assert_eq!(
            island
                .inner
                .borrow()
                .read_memory_descriptor(&memory, descriptor)
                .expect("x86 descriptor"),
            (0x1234_5678, 9)
        );

        let config = 0x54_000;
        let queue_out = 0x54_100;
        memory.map_bytes(config, &[0_u8; 0x60]);
        memory.map_bytes(queue_out, &[0_u8; 4]);
        memory.write_u32(config, 0x50);
        memory.write_u32(config + 4, 1);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("x86 queue create"),
            STATUS_SUCCESS
        );
        memory.write_u32(config + 4, 3);
        memory.map_bytes(queue_out, &[0_u8; 4]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("x86 invalid dispatch type"),
            STATUS_INVALID_PARAMETER
        );

        let finish_irp_guest = 0x55_000;
        memory.map_bytes(finish_irp_guest, &[0_u8; 0x100]);
        memory.write_u32(finish_irp_guest + 0x18, STATUS_ACCESS_VIOLATION as u32);
        memory.write_u32(finish_irp_guest + 0x20, 7);
        let mut state = island.inner.borrow_mut();
        let casak = state.kmdf.devices.get(&device).unwrap().casak;
        let irp = state
            .io
            .allocate_irp(
                casak,
                IrpParameterBlock::new(IrpMajorFunction::DeviceControl, 0, 0),
            )
            .expect("x86 irp");
        let pending = PendingIoTargetSend {
            irp,
            irp_guest: finish_irp_guest,
            entry: 0,
            device_object: 0,
            system_buffer: 0,
            output_ptr: 0,
            output_len: 0,
            bytes_returned: 0,
            request: 0,
            target: 0,
            io_control: 0,
            input_ptr: 0,
            input_len: 0,
            saved: (0, 0, 0, 0, 0, 0, 0),
        };
        assert_eq!(
            state
                .finish_ioctl_send(&mut memory, pending)
                .expect("x86 finish send"),
            (STATUS_ACCESS_VIOLATION, 7)
        );
    });
}

#[test]
fn island_namespace_rejects_bad_paths_stale_handles_and_missing_services() {
    with_big_stack(|| {
        let image = build_test_driver(false, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaNamespace");
        assert_eq!(normalize_device_path("\\\\.\\CasaTest"), "\\??\\CasaTest");
        assert_eq!(
            normalize_device_path("\\Device\\CasaTest\\\\"),
            "\\Device\\CasaTest"
        );
        assert_eq!(normalize_device_path("  "), "");
        assert!(resolve_island_device(&runtime, "").is_none());
        assert!(resolve_island_device(&runtime, "   ").is_none());

        let handle_ptr = 0x5F_000;
        memory.map_bytes(handle_ptr, &[0_u8; 8]);
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "", handle_ptr),
            None
        );
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest", 0),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest", 1),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest", handle_ptr),
            Some(STATUS_SUCCESS)
        );
        let direct_handle = memory.read_u32(handle_ptr).unwrap();
        assert_ne!(direct_handle, 0);
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "\\??\\CasaTest", handle_ptr),
            Some(STATUS_SUCCESS),
            "the driver's symbolic link resolves"
        );
        let link_handle = memory.read_u32(handle_ptr).unwrap();
        assert_ne!(link_handle, direct_handle);
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "\\DosDevices\\CasaTest", handle_ptr),
            Some(STATUS_SUCCESS),
            "the DOS-device prefix resolves without a link"
        );
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "\\Device\\CasaTest\\\\", handle_ptr),
            Some(STATUS_SUCCESS),
            "trailing separators are normalized"
        );

        assert_eq!(
            dispatch_island_device_io(
                &mut runtime,
                &mut memory,
                0xDEAD_0000,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("unknown handle"),
            None
        );
        assert_eq!(
            dispatch_island_device_io(
                &mut runtime,
                &mut memory,
                direct_handle,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("live handle"),
            Some((STATUS_INVALID_DEVICE_REQUEST, 0))
        );

        let runtime_id = runtime_identity(&runtime);
        let saved_services = lock_registry().services.remove(&runtime_id);
        assert!(saved_services.is_some());
        assert_eq!(
            dispatch_island_device_io(
                &mut runtime,
                &mut memory,
                link_handle,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("handle with missing service"),
            Some((STATUS_INVALID_HANDLE, 0))
        );
        if let Some(services) = saved_services {
            lock_registry().services.insert(runtime_id, services);
        }

        let record = lock_registry()
            .device_handles
            .get(&runtime_id)
            .and_then(|handles| handles.get(&direct_handle))
            .cloned()
            .expect("direct handle record");
        island
            .inner
            .borrow_mut()
            .device_ids
            .remove(&record.device_guest);
        assert_eq!(
            dispatch_island_device_io(
                &mut runtime,
                &mut memory,
                direct_handle,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("stale device handle"),
            Some((STATUS_INVALID_HANDLE, 0))
        );
    });
}

#[test]
fn wdf_config_edges_reject_stale_parents_and_invalid_dispatch_type() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfConfigEdges");
        let device = island.kmdf_device_handles()[0];
        let driver = island.driver_object_pointer();
        let out = 0x41_000;
        memory.map_bytes(out, &[0_u8; 0x40]);

        let text = 0x42_000;
        memory.map_bytes(text, &[0_u8; 0x40]);
        memory.write_u16(text, u16::from(b'A'));
        memory.write_u16(text + 2, u16::from(b'B'));
        memory.write_u16(text + 4, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::RtlInitUnicodeString,
                &[0xFFFF_FFFF, text],
            )
            .expect("invalid destination"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::RtlInitUnicodeString,
                &[text, text],
            )
            .expect("overlapping source and destination"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u16(text).unwrap(), 4);
        assert_eq!(memory.read_u16(text + 2).unwrap(), 6);
        assert_eq!(memory.read_u64(text + 8).unwrap(), text);

        let attrs = 0x43_000;
        let type_info = 0x44_000;
        let lock_out = 0x45_000;
        memory.map_bytes(attrs, &[0_u8; 0x40]);
        memory.map_bytes(type_info, &[0_u8; 0x20]);
        memory.write_u32(attrs, 0x38);
        memory.write_u64(attrs + 0x20, 0xDEAD_BEEF);
        memory.write_u64(attrs + 0x28, 0x20_0000);
        memory.write_u32(type_info, 0x18);
        memory.write_u64(type_info + 0x10, 0x18);
        memory.write_u64(attrs + 0x30, type_info);
        memory.map_bytes(lock_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWaitLockCreate,
                &[attrs, lock_out],
            )
            .expect("wait lock with stale parent"),
            STATUS_SUCCESS
        );
        let lock = memory.read_u64(lock_out).unwrap();
        {
            let state = island.inner.borrow();
            let object = state.kmdf.objects.get(&lock).expect("wait lock object");
            assert_eq!(object.context_size, 0x10_000);
            assert_eq!(object.parent, Some(state.kmdf.driver_handle));
        }

        let short_config = 0x46_000;
        memory.map_bytes(short_config, &[0_u8; 0x40]);
        memory.write_u32(short_config, 0x1F);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, short_config, out],
            )
            .expect("undersized driver config"),
            STATUS_INVALID_PARAMETER
        );

        let config = 0x46_040;
        memory.map_bytes(config, &[0_u8; 0x40]);
        memory.write_u32(config, 0x20);
        memory.write_u64(config + 0x10, 0xDEAD_BEEF);
        memory.write_u32(config + 0x18, 0xCA5A_2146);
        memory.write_u32(config + 0x1C, 2);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, config, out],
            )
            .expect("full driver config"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.evt_driver_unload, 0xDEAD_BEEF);
            assert_eq!(state.kmdf.driver_pool_tag, 0xCA5A_2146);
            assert_eq!(state.kmdf.driver_init_flags, 2);
        }

        let queue_config = 0x47_000;
        let queue_out = 0x47_040;
        memory.map_bytes(queue_config, &[0_u8; 0x20]);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(queue_config, 0x0E);
        memory.write_u32(queue_config + 4, 3);
        memory.write_u8(queue_config + 0x0C, 1);
        memory.write_u8(queue_config + 0x0D, 1);
        let queues_before = island.inner.borrow().kmdf.queues.len();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, queue_config, 0, queue_out],
            )
            .expect("invalid queue dispatch type"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(island.inner.borrow().kmdf.queues.len(), queues_before);

        assert_eq!(
            parse_service_name("\\Registry\\Machine\\System\\CurrentControlSet\\Other\\X"),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(parse_service_name(""), Err(STATUS_INVALID_PARAMETER));
    });
}

#[test]
fn wdf_request_iotarget_edges_reject_stale_devices_and_invalid_driver_objects() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfEdges");
        let device_a = kmdf_device_named(&island, "WdfA");
        let device_b = kmdf_device_named(&island, "WdfB");
        let device_b_object = island
            .inner
            .borrow()
            .kmdf
            .devices
            .get(&device_b)
            .expect("device b")
            .object_guest;
        let out = 0x41_000;
        memory.map_bytes(out, &[0_u8; 8]);

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device_a, out],
            )
            .expect("request create"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(out).unwrap();
        {
            let state = island.inner.borrow();
            assert_eq!(
                state
                    .kmdf
                    .objects
                    .get(&request)
                    .expect("request object")
                    .parent,
                Some(device_a)
            );
            assert!(
                state
                    .kmdf
                    .objects
                    .get(&device_a)
                    .expect("device object")
                    .children
                    .contains(&request)
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[request],
            )
            .expect("delete request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[request],
            )
            .expect("double delete request"),
            STATUS_INVALID_HANDLE
        );

        let target_out = 0x42_000;
        memory.map_bytes(target_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetCreate,
                &[0xDEAD, 0, target_out],
            )
            .expect("target for missing device"),
            STATUS_INVALID_PARAMETER
        );
        let attrs = 0x43_000;
        memory.map_bytes(attrs, &[0_u8; 0x40]);
        memory.write_u32(attrs, 0x38);
        memory.write_u64(attrs + 0x20, 0xDEAD_BEEF);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetCreate,
                &[device_a, attrs, target_out],
            )
            .expect("target with stale parent"),
            STATUS_SUCCESS
        );
        let target = memory.read_u64(target_out).unwrap();
        {
            let state = island.inner.borrow();
            assert_eq!(
                state
                    .kmdf
                    .objects
                    .get(&target)
                    .expect("target object")
                    .parent,
                Some(device_a)
            );
            assert!(
                state
                    .kmdf
                    .objects
                    .get(&device_a)
                    .expect("device object")
                    .children
                    .contains(&target)
            );
        }

        let driver = island.driver_object_pointer();
        let major_slot = driver + 0x70 + IrpMajorFunction::DeviceControl.code() as u64 * 8;
        memory.write_u64(major_slot, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetSendIoctlSynchronously,
                &[target, 0, 0x0022_0004, 0, 0, 0, 0],
            )
            .expect("sync send without handler"),
            STATUS_INVALID_DEVICE_REQUEST
        );

        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device_a, out],
            )
            .expect("send request create"),
            STATUS_SUCCESS
        );
        let send_request = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForIoctl,
                &[send_request, target, 0x0022_0004, 0, 0, 0, 0, 0],
            )
            .expect("format request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSend,
                &[send_request, target, 0],
            )
            .expect("send without handler"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        let (completed, status, _, _) = island
            .kmdf_request_state(send_request)
            .expect("request state");
        assert!(completed);
        assert_eq!(status, STATUS_INVALID_DEVICE_REQUEST);

        let saved_driver_object = island.inner.borrow().driver_object_guest;
        island.inner.borrow_mut().driver_object_guest = 0x7000_0000_0000;
        let sync_error = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfIoTargetSendIoctlSynchronously,
            &[target, 0, 0x0022_0004, 0, 0, 0, 0],
        )
        .expect_err("sync send with corrupt driver object");
        assert_eq!(sync_error.code, ReasonCode::RcUnimplInsn);
        {
            let mut state = island.inner.borrow_mut();
            if let Some(request) = state.kmdf.requests.get_mut(&send_request) {
                request.completed = false;
            }
        }
        let send_error = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfRequestSend,
            &[send_request, target, 0],
        )
        .expect_err("request send with corrupt driver object");
        assert_eq!(send_error.code, ReasonCode::RcUnimplInsn);
        island.inner.borrow_mut().driver_object_guest = saved_driver_object;
        memory.write_u64(major_slot, 0);

        let irp_guest = 0x44_000;
        memory.map_bytes(irp_guest, &[0_u8; 0x100]);
        {
            let mut state = island.inner.borrow_mut();
            let casak = state.kmdf.devices.get(&device_b).expect("device b").casak;
            let _ = state.io.delete_device(casak);
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtIoDeviceControlDispatch,
                &[irp_guest, device_b_object],
            )
            .expect("dispatch to deleted device"),
            crate::casak::io::STATUS_DELETE_PENDING as i32
        );
        assert_eq!(
            memory.read_u32(irp_guest + 0x30).unwrap(),
            crate::casak::io::STATUS_DELETE_PENDING as u32
        );
    });
}

#[test]
fn kmdf_queue_stop_start_and_purge_reject_orphaned_requests() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfQueueEdges");
        let image_base = island.image_base();
        let device = kmdf_device_named(&island, "WdfA");
        let queue = queue_for_device(&island, device);
        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfA", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStopSynchronously,
                &[queue],
            )
            .expect("stop empty queue"),
            STATUS_SUCCESS
        );
        let input = 0x46_000;
        let output = 0x47_000;
        let iosb = 0x48_000;
        memory.map_bytes(input, b"PING");
        memory.map_bytes(output, &[0_u8; 8]);
        memory.map_bytes(iosb, &[0_u8; 24]);
        for _ in 0..2 {
            assert_eq!(
                dispatch_nt_thunk(
                    &mut runtime,
                    &mut memory,
                    HostThunk::NtDeviceIoControlFile,
                    &[
                        u64::from(handle),
                        0,
                        0,
                        0,
                        iosb,
                        0x0022_0004,
                        input,
                        4,
                        output,
                        8,
                    ],
                ),
                STATUS_PENDING
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStopSynchronously,
                &[queue],
            )
            .expect("stop queued queue"),
            STATUS_SUCCESS
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_STOP_COUNT))
                .unwrap(),
            2
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStart,
                &[queue],
            )
            .expect("restart queue"),
            STATUS_SUCCESS
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_RESUME_COUNT))
                .unwrap(),
            2
        );
        assert_eq!(
            memory
                .read_u32(image_base + u64::from(F_IOCTL_COUNT))
                .unwrap(),
            2
        );
        {
            let state = island.inner.borrow();
            let queue_state = state.kmdf.queues.get(&queue).expect("queue");
            assert!(queue_state.queued.is_empty());
            assert!(queue_state.in_flight.is_empty());
            assert!(!queue_state.stopped);
            assert_eq!(state.kmdf.stop_dispatches, 2);
            assert_eq!(state.kmdf.resume_dispatches, 2);
            assert!(
                state
                    .kmdf
                    .requests
                    .values()
                    .all(|request| request.completed)
            );
        }

        let ret_stub = x64_ret_stub(&mut memory, &island);
        set_queue_callbacks(&island, queue, |queue| {
            queue.callbacks.device_control = ret_stub;
        });
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtDeviceIoControlFile,
                &[
                    u64::from(handle),
                    0,
                    0,
                    0,
                    iosb,
                    0x0022_0004,
                    input,
                    4,
                    output,
                    8,
                ],
            ),
            STATUS_PENDING
        );
        let in_flight_request = island
            .inner
            .borrow()
            .kmdf
            .requests
            .iter()
            .find(|(_, request)| !request.completed && request.queue == Some(queue))
            .map(|(request, _)| *request)
            .expect("in-flight request");
        let (_, _, _, outer) = island
            .kmdf_request_state(in_flight_request)
            .expect("request state");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueuePurge,
                &[queue],
            )
            .expect("purge in-flight request"),
            STATUS_SUCCESS
        );
        let (completed, status, _, outer_after) = island
            .kmdf_request_state(in_flight_request)
            .expect("request state");
        assert!(completed);
        assert_eq!(status, STATUS_CANCELLED);
        assert_eq!(outer_after, outer);
        assert_eq!(
            memory.read_u32(outer + 0x30).unwrap(),
            STATUS_CANCELLED as u32
        );
        assert_eq!(island.inner.borrow().kmdf.cancel_dispatches, 1);
        assert!(
            island
                .inner
                .borrow()
                .kmdf
                .queues
                .get(&queue)
                .expect("queue")
                .in_flight
                .is_empty()
        );
    });
}

#[test]
fn wait_lock_gate_poison_race_and_corrupt_driver_object_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfPoison");
        let lock = island.kmdf_wait_lock_handles()[0];
        let gate = island.kmdf_wait_lock_gate(lock).expect("gate");
        let poison = gate.clone();
        let panicked = std::thread::spawn(move || {
            let (mutex, _) = &*poison;
            let _guard = mutex.lock().expect("lock before poison");
            panic!("poison wait lock mutex");
        })
        .join();
        assert!(panicked.is_err());
        assert!(gate.0.is_poisoned());
        {
            let (mutex, _) = &*gate;
            let mut locked = mutex.lock().unwrap_err().into_inner();
            *locked = true;
        }
        let notify = gate.clone();
        let notifier = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let (mutex, wake) = &*notify;
            let mut locked = mutex.lock().unwrap_err().into_inner();
            *locked = false;
            drop(locked);
            wake.notify_all();
        });
        assert_eq!(
            island.inner.borrow().wait_lock_acquire_gate(&gate, None),
            STATUS_SUCCESS
        );
        notifier.join().expect("notifier");
        {
            let (mutex, _) = &*gate;
            let mut locked = mutex.lock().unwrap_err().into_inner();
            *locked = true;
        }
        assert_eq!(
            island
                .inner
                .borrow()
                .wait_lock_acquire_gate(&gate, Some(Duration::from_millis(20))),
            STATUS_TIMEOUT
        );

        let (handle, status) =
            create_device_file(&mut runtime, &mut memory, "\\Device\\WdfCasa", 0x41_000);
        assert_eq!(status, STATUS_SUCCESS);
        let driver_object = island.driver_object_pointer();
        let saved_driver_object = island.inner.borrow().driver_object_guest;
        island.inner.borrow_mut().driver_object_guest = 0x7000_0000_0000;
        let error = dispatch_island_device_io(
            &mut runtime,
            &mut memory,
            handle,
            IrpMajorFunction::DeviceControl,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        .expect_err("dispatch with corrupt driver object");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        island.inner.borrow_mut().driver_object_guest = saved_driver_object;
        let major_slot = driver_object + 0x70 + IrpMajorFunction::DeviceControl.code() as u64 * 8;
        let saved_handler = memory.read_u64(major_slot).unwrap();
        memory.write_u64(major_slot, 0);
        assert_eq!(
            dispatch_island_device_io(
                &mut runtime,
                &mut memory,
                handle,
                IrpMajorFunction::DeviceControl,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("dispatch without handler"),
            Some((STATUS_INVALID_DEVICE_REQUEST, 0))
        );
        memory.write_u64(major_slot, saved_handler);
    });
}

#[test]
fn pe32_unload_corrupt_callback_and_exhausted_unicode_arena_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver_pe32();
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x86(&image, "CasaPe32Edges");
        let driver = island.driver_object_pointer();
        let default_dispatch = island.inner.borrow().default_dispatch;
        assert_eq!(
            memory.read_u32(driver + 0x38).unwrap(),
            default_dispatch as u32
        );
        let image_base = island.image_base();
        {
            let state = island.inner.borrow();
            assert_eq!(state.unload_guest, None);
            assert_eq!(
                state.kmdf.evt_driver_unload,
                image_base + u64::from(X86K_UNLOAD_RVA)
            );
        }
        assert_eq!(memory.read_u32(driver + 0x34).unwrap(), 0);

        let header = {
            let mut state = island.inner.borrow_mut();
            allocate_unicode_string(&mut state, &mut memory, "AB").expect("unicode string")
        };
        assert_eq!(memory.read_u16(header).unwrap(), 4);
        assert_eq!(memory.read_u16(header + 2).unwrap(), 6);
        assert_ne!(memory.read_u32(header + 4).unwrap(), 0);

        let saved_cursor = {
            let mut state = island.inner.borrow_mut();
            let saved = state.arena.cursor;
            state.arena.cursor = state.arena.end;
            saved
        };
        let error = {
            let mut state = island.inner.borrow_mut();
            allocate_unicode_string(&mut state, &mut memory, "AB").expect_err("exhausted arena")
        };
        assert_eq!(error.code, ReasonCode::RcIo);
        assert!(
            error.message.contains("driver island arena exhausted"),
            "{}",
            error.message
        );
        island.inner.borrow_mut().arena.cursor = saved_cursor;

        island.inner.borrow_mut().kmdf.evt_driver_unload = 0xDEAD_BEEF;
        let service_path = guest_unicode_string_x86(
            &mut memory,
            0x40_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaPe32Edges",
        );
        assert_eq!(
            dispatch_nt_thunk(
                &mut runtime,
                &mut memory,
                HostThunk::NtUnloadDriver,
                &[service_path],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert!(island.is_loaded());
    });
}

#[test]
fn kmdf_short_attributes_and_zero_destination_reject_implicit_members() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfAttrShort");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::RtlInitUnicodeString,
                &[0, 0xDEAD_BEEF],
            )
            .expect("zero destination must be accepted"),
            STATUS_SUCCESS
        );

        let attrs = 0x41_000;
        memory.map_bytes(attrs, &[0_u8; 0x40]);
        memory.write_u32(attrs, 8);
        let parsed = island
            .inner
            .borrow()
            .parse_object_attributes(&memory, attrs)
            .expect("short attributes");
        assert_eq!(parsed.evt_cleanup, 0);
        assert_eq!(parsed.evt_destroy, 0);
        assert_eq!(parsed.parent, None);
        assert_eq!(parsed.context_size_override, 0);
        assert_eq!(parsed.context_type_info, 0);

        memory.write_u32(attrs, 0x28);
        memory.write_u64(attrs + 0x20, 0x1234_5678);
        memory.write_u64(attrs + 0x28, 0xDEAD_BEEF);
        memory.write_u64(attrs + 0x30, 0xFEED_FACE);
        let parsed = island
            .inner
            .borrow()
            .parse_object_attributes(&memory, attrs)
            .expect("parent-only attributes");
        assert_eq!(parsed.parent, Some(0x1234_5678));
        assert_eq!(parsed.context_size_override, 0);
        assert_eq!(parsed.context_type_info, 0);
    });
}

#[test]
fn kmdf_driver_and_queue_config_omissions_reject_implicit_fields() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfConfigOmit");
        let driver = island.driver_object_pointer();
        let out = 0x41_000;
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDriverCreate,
                &[driver, 0, 0, 0, out],
            )
            .expect("config-less driver create"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.evt_driver_unload, 0);
            assert_eq!(state.kmdf.driver_pool_tag, 0);
            assert_eq!(state.kmdf.driver_init_flags, 0);
        }

        let device = island.kmdf_device_handles()[0];
        let config = 0x42_000;
        let queue_out = 0x43_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(config, 8);
        memory.write_u32(config + 4, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("short queue config"),
            STATUS_SUCCESS
        );
        let queue = memory.read_u64(queue_out).unwrap();
        {
            let state = island.inner.borrow();
            let record = state.kmdf.queues.get(&queue).expect("created queue");
            assert_eq!(record.default_queue, false);
            assert_eq!(record.dispatch_type, 0);
            assert_eq!(record.callbacks.default, 0);
            assert_eq!(record.callbacks.device_control, 0);
        }
    });
}

#[test]
fn kmdf_object_parent_edges_and_driverless_delete_reject_cascade() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfParentEdges");
        let device = island.kmdf_device_handles()[0];
        let attrs = 0x41_000;
        memory.map_bytes(attrs, &[0_u8; 0x40]);
        memory.write_u32(attrs, 0x38);
        memory.write_u64(attrs + 0x20, device);
        let request_out = 0x42_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[attrs, device, request_out],
            )
            .expect("request with explicit parent"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .objects
                .get(&request)
                .expect("request object")
                .parent,
            Some(device)
        );

        let saved_driver_object = island.inner.borrow().driver_object_guest;
        island.inner.borrow_mut().driver_object_guest = 0;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[request],
            )
            .expect("driverless object delete"),
            STATUS_SUCCESS
        );
        island.inner.borrow_mut().driver_object_guest = saved_driver_object;
        assert_eq!(
            island.inner.borrow().kmdf.objects.contains_key(&request),
            false
        );

        let target_out = 0x43_000;
        memory.map_bytes(target_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoTargetCreate,
                &[device, attrs, target_out],
            )
            .expect("iotarget with explicit parent"),
            STATUS_SUCCESS
        );
        let target = memory.read_u64(target_out).unwrap();
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .objects
                .get(&target)
                .expect("target object")
                .parent,
            Some(device)
        );
    });
}

#[test]
fn kmdf_queue_callback_absence_and_stale_completion_edges_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfQueueNoCallbacks");
        let device = island.kmdf_device_handles()[0];
        let queue = *island
            .inner
            .borrow()
            .kmdf
            .queues
            .keys()
            .next()
            .expect("queue");
        set_queue_callbacks(&island, queue, |record| {
            record.callbacks.stop = 0;
            record.callbacks.resume = 0;
            record.callbacks.canceled_on_queue = 0;
        });
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStop,
                &[queue],
            )
            .expect("stop without callback"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .queues
                .get(&queue)
                .expect("queue")
                .stopped,
            true
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStart,
                &[queue],
            )
            .expect("start without callback"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .queues
                .get(&queue)
                .expect("queue")
                .stopped,
            false
        );

        island
            .inner
            .borrow_mut()
            .kmdf
            .queues
            .get_mut(&queue)
            .expect("queue")
            .queued
            .push_back(0xDEAD);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueuePurge,
                &[queue],
            )
            .expect("purge stale queued handle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .inner
                .borrow()
                .kmdf
                .queues
                .get(&queue)
                .expect("queue")
                .queued
                .is_empty(),
            true
        );

        let request = make_kmdf_request(
            &island,
            &mut memory,
            device,
            queue,
            IrpMajorFunction::DeviceControl,
        );
        island
            .inner
            .borrow_mut()
            .kmdf
            .requests
            .get_mut(&request)
            .expect("request")
            .queue = Some(0xDEAD);
        island
            .inner
            .borrow_mut()
            .complete_kmdf_request(&mut memory, request, STATUS_CANCELLED, 0)
            .expect("complete request with stale queue");
        let (completed, status, _, _) = island.kmdf_request_state(request).expect("state");
        assert_eq!(completed, true);
        assert_eq!(status, STATUS_CANCELLED);
    });
}

const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;

fn pnp_u32(memory: &MemoryImage, base: u64, rva: u32) -> u32 {
    memory
        .read_u32(base + u64::from(rva))
        .expect("pnp fixture dword")
}

fn pnp_set_failure(memory: &mut MemoryImage, base: u64, mask: u32, status: i32) {
    memory.write_u32(base + u64::from(P_FAIL_MASK), mask);
    memory.write_u32(base + u64::from(P_FAIL_STATUS), status as u32);
}

fn pnp_load(
    service: &str,
) -> (
    Box<PeHostRuntime>,
    TempDir,
    MemoryImage,
    DriverIsland,
    u64,
    u64,
) {
    let image = build_kmdf_pnp_driver();
    let (runtime, directory, memory, island) = load_staged_island_x64(&image, service);
    let base = island.image_base();
    let device = island
        .created_devices()
        .into_iter()
        .next()
        .expect("pnp fixture device")
        .guest_pointer;
    (runtime, directory, memory, island, base, device)
}

#[test]
fn pnp_invalid_minors_repeated_start_stop_and_remove_after_remove_reject() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, base, device) = pnp_load("CasaPnpLife");
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                .expect("stop before start")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("D3 before start")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("D0 before start")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, 0x01)
                .expect("query-remove minor")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, 2)
                .expect("D2 power state")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device,
                    IrpMajorFunction::Power,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("non-set-power minor")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 0);

        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 0);
        assert_eq!(
            pnp_u32(&memory, base, P_LAST_PREV),
            WDF_POWER_DEVICE_D3_FINAL
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("repeated start")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 1);

        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("D3")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_SUSPEND_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_LAST_TARGET), WDF_POWER_DEVICE_D3);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("repeated D3")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                .expect("stop while D3")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("D0")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 2);
        assert_eq!(pnp_u32(&memory, base, P_LAST_PREV), WDF_POWER_DEVICE_D3);
        assert_eq!(pnp_u32(&memory, base, P_RESTART_COUNT), 1);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("repeated D0")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );

        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                .expect("stop")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_SELFFINI_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 2);
        assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 1);
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                .expect("repeated stop")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("D3 after stop")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );

        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("restart after stop")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                .expect("remove")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_SELFFINI_COUNT), 2);
        assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 2);
        assert_eq!(pnp_u32(&memory, base, P_CLEANUP_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_DESTROY_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_CLEANUP_AFTER_DESTROY), 0);
        assert_eq!(pnp_u32(&memory, base, P_DESTROY_AFTER_CLEANUP), 1);
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                .expect("repeated remove")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("start after remove")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(island.device_count(), 0);
        assert!(island.created_devices()[0].deleted);
    });
}

#[test]
fn pnp_start_callback_failures_roll_back_and_never_become_ready() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, base, device) = pnp_load("CasaPnpStartFail");
        pnp_set_failure(&mut memory, base, 1, STATUS_INSUFFICIENT_RESOURCES);
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("prepare hardware failure")
                .0,
            STATUS_INSUFFICIENT_RESOURCES
        );
        assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 0);
        assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 0);
        assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 0);
        {
            let handle = island.kmdf_device_handles()[0];
            let state = island.inner.borrow();
            let record = state.kmdf.devices.get(&handle).expect("device");
            assert_eq!(record.started, false);
            assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
        }
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                .expect("stop after failed start")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );

        pnp_set_failure(&mut memory, base, 2, STATUS_UNSUCCESSFUL);
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("D0Entry failure")
                .0,
            STATUS_UNSUCCESSFUL
        );
        assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 2);
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 0);
        {
            let handle = island.kmdf_device_handles()[0];
            let state = island.inner.borrow();
            let record = state.kmdf.devices.get(&handle).expect("device");
            assert_eq!(record.started, false);
            assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
        }

        pnp_set_failure(&mut memory, base, 4, STATUS_ACCESS_DENIED);
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("self-managed IO failure")
                .0,
            STATUS_ACCESS_DENIED
        );
        assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 3);
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 2);
        assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 2);
        {
            let handle = island.kmdf_device_handles()[0];
            let state = island.inner.borrow();
            let record = state.kmdf.devices.get(&handle).expect("device");
            assert_eq!(record.started, false);
            assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
        }

        pnp_set_failure(&mut memory, base, 0, 0);
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("start after rollbacks")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 3);
        assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 2);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("power down")
                .0,
            STATUS_SUCCESS
        );
        pnp_set_failure(&mut memory, base, 2, STATUS_UNSUCCESSFUL);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("D0 failure")
                .0,
            STATUS_UNSUCCESSFUL
        );
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 4);
        assert_eq!(pnp_u32(&memory, base, P_RESTART_COUNT), 0);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("D3 after failed D0")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        pnp_set_failure(&mut memory, base, 0, 0);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("D0 recovery")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_LAST_PREV), WDF_POWER_DEVICE_D3);
        assert_eq!(pnp_u32(&memory, base, P_RESTART_COUNT), 1);
    });
}

#[test]
fn pnp_file_cleanup_and_device_cleanup_destroy_ordering_reject_out_of_order() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, base, device) = pnp_load("CasaPnpOrder");
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device,
                    IrpMajorFunction::Cleanup,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("file cleanup")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_FCLEANUP_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_FCLOSE_COUNT), 0);
        assert_eq!(
            island
                .dispatch_irp(
                    &mut runtime,
                    &mut memory,
                    device,
                    IrpMajorFunction::Close,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                .expect("file close")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_FCLOSE_COUNT), 1);
        {
            let handle = island.kmdf_device_handles()[0];
            let state = island.inner.borrow();
            let object = state.kmdf.objects.get(&handle).expect("device object");
            assert_ne!(object.evt_cleanup, 0);
            assert_ne!(object.evt_destroy, 0);
        }
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                .expect("remove")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_CLEANUP_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_DESTROY_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_CLEANUP_AFTER_DESTROY), 0);
        assert_eq!(pnp_u32(&memory, base, P_DESTROY_AFTER_CLEANUP), 1);
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.file_cleanup_dispatches, 1);
            assert_eq!(state.kmdf.file_close_dispatches, 1);
            assert!(state.kmdf.devices.is_empty());
        }
    });
}

#[test]
fn pnp_malformed_callback_config_and_unsupported_framework_import_reject() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, _base, device) = pnp_load("CasaPnpMalformed");
        let init = *island
            .inner
            .borrow()
            .kmdf
            .device_inits
            .keys()
            .next()
            .expect("fixture device init");
        let config = 0x41_000;
        memory.map_bytes(config, &[0_u8; 0x40]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                &[init, 0],
            )
            .expect("null callback table"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                &[0xDEAD, config],
            )
            .expect("stale device init"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u32(config, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                &[init, config],
            )
            .expect("zero-size callback table"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetFileObjectConfig,
                &[init, 0, 0],
            )
            .expect("null file config"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u32(config, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetFileObjectConfig,
                &[init, config, 0],
            )
            .expect("zero-size file config"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[0xDEAD, 0xBEEF],
            )
            .expect("stale enqueue device"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        let request_out = 0x42_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, 0, request_out],
            )
            .expect("request create"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).expect("request handle");
        let device_handle = island.kmdf_device_handles()[0];
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device_handle, request],
            )
            .expect("enqueue without a queue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, 0xDEAD],
            )
            .expect("stale request"),
            STATUS_INVALID_DEVICE_REQUEST
        );
    });
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _dir, mut memory, island) =
            load_staged_island_x64(&image, "CasaPnpNoCallbacks");
        let device = island.created_devices()[0].guest_pointer;
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                .expect("remove without callbacks"),
            (STATUS_SUCCESS, 0)
        );
        assert_eq!(island.device_count(), 0);
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_REMOVE_DEVICE)
                .expect("repeated remove without callbacks")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
    });
    with_big_stack(|| {
        let mut image = build_kmdf_pnp_driver();
        image[0x1642..0x1660].fill(0);
        image[0x1642..0x1649].copy_from_slice(b"WdfFoo\0");
        let (mut runtime, _directory) = test_runtime();
        let mut memory = MemoryImage::default();
        let error = DriverIsland::load_and_start_named(
            &image,
            "CasaPnpUnsupported",
            &mut runtime,
            &mut memory,
        )
        .expect_err("an unsupported framework import must reject the image");
        assert_eq!(error.code, ReasonCode::RcImportMissing);
        assert!(
            error.message.contains("Kmdf:WdfLdr.sys!WdfFoo"),
            "{}",
            error.message
        );
    });
}

#[test]
fn wdf_memory_string_and_typed_context_sizing_errors_reject() {
    with_big_stack(|| {
        assert!(matches!(
            DriverShim::for_import("WdfMemoryCreate"),
            Some(DriverShim::WdfMemoryCreate)
        ));
        assert!(matches!(
            DriverShim::for_import("WdfMemoryDelete"),
            Some(DriverShim::WdfObjectDelete)
        ));
        assert!(matches!(
            DriverShim::for_import("WdfStringCreate"),
            Some(DriverShim::WdfStringCreate)
        ));
        assert!(matches!(
            DriverShim::for_import("WdfStringDelete"),
            Some(DriverShim::WdfObjectDelete)
        ));
        assert!(matches!(
            DriverShim::for_import("WdfDeviceEnqueueRequest"),
            Some(DriverShim::WdfDeviceEnqueueRequest)
        ));
        assert!(matches!(
            DriverShim::for_import("WdfPdoInitAllocate"),
            Some(DriverShim::WdfPdoInitAllocate)
        ));
        assert!(matches!(
            DriverShim::for_import("WdfPdoInitSetEventCallbacks"),
            None
        ));
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaWdfMem");
        let device = island.kmdf_device_handles()[0];
        let memory_out = 0x41_000;
        let buffer_out = 0x41_008;
        let size_out = 0x41_010;
        memory.map_bytes(0x41_000, &[0_u8; 0x20]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreate,
                &[0, 2, 0x2146_4457, 0x10, memory_out, buffer_out],
            )
            .expect("invalid pool type"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreate,
                &[0, 0, 0x2146_4457, 0x20_0000, memory_out, buffer_out],
            )
            .expect("oversized memory"),
            STATUS_INSUFFICIENT_RESOURCES
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreate,
                &[0, 0, 0x2146_4457, 0x10, 0, buffer_out],
            )
            .expect("null memory out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreate,
                &[0, 0, 0x2146_4457, 0x10, memory_out, 0xDEAD_0000],
            )
            .expect("invalid buffer out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreatePreallocated,
                &[0, 0xDEAD_0000, 0x10, memory_out],
            )
            .expect("invalid preallocated buffer"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreate,
                &[0, 0, 0x2146_4457, 0x80, memory_out, buffer_out],
            )
            .expect("memory create"),
            STATUS_SUCCESS
        );
        let handle = memory.read_u64(memory_out).expect("memory handle");
        let buffer = memory.read_u64(buffer_out).expect("memory buffer");
        assert_ne!(buffer, 0);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryGetBuffer,
                &[handle, size_out],
            )
            .expect("memory buffer"),
            buffer
        );
        assert_eq!(memory.read_u64(size_out).expect("memory size"), 0x80);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryGetBuffer,
                &[handle, 0],
            )
            .expect("memory buffer without size"),
            buffer
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryGetBuffer,
                &[0xDEAD, size_out],
            )
            .expect("stale memory handle"),
            0
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryGetBuffer,
                &[handle, 0xDEAD_0000],
            )
            .expect("invalid size out"),
            0
        );
        let preallocated = 0x43_000;
        memory.map_bytes(preallocated, &[0_u8; 0x20]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreatePreallocated,
                &[0, preallocated, 0x10, memory_out],
            )
            .expect("preallocated memory"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[handle],
            )
            .expect("delete memory"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryGetBuffer,
                &[handle, size_out],
            )
            .expect("deleted memory"),
            0
        );

        let source = guest_unicode_string(&mut memory, 0x44_000, "WdfStr");
        let string_out = 0x45_000;
        let destination = 0x45_100;
        memory.map_bytes(string_out, &[0_u8; 8]);
        memory.map_bytes(destination, &[0_u8; 16]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringCreate,
                &[0xDEAD_0000, 0, string_out],
            )
            .expect("invalid source string"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringCreate,
                &[0, 0, string_out],
            )
            .expect("null source string"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringCreate,
                &[source, 0, 0],
            )
            .expect("null string out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringCreate,
                &[source, 0, string_out],
            )
            .expect("string create"),
            STATUS_SUCCESS
        );
        let string = memory.read_u64(string_out).expect("string handle");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringGetUnicodeString,
                &[string, destination],
            )
            .expect("string readback"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u16(destination).expect("length"), 12);
        assert_eq!(memory.read_u16(destination + 2).expect("maximum"), 14);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringGetUnicodeString,
                &[0xDEAD, destination],
            )
            .expect("stale string"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringGetUnicodeString,
                &[string, 0],
            )
            .expect("null string destination"),
            STATUS_INVALID_PARAMETER
        );

        let type_info = 0x46_000;
        memory.map_bytes(type_info, &[0_u8; 0x30]);
        memory.write_u32(type_info, 0x18);
        memory.write_u64(type_info + 0x10, 0x1000);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[device, type_info],
            )
            .expect("oversized typed context"),
            0
        );
        memory.write_u64(type_info + 0x10, 0x80);
        assert_ne!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[device, type_info],
            )
            .expect("sized typed context"),
            0
        );
        assert_ne!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[device, 0],
            )
            .expect("untyped context"),
            0
        );
        let odd = 0x47_000;
        memory.map_bytes(odd, &[0_u8; 0x20]);
        memory.write_u16(odd, 3);
        memory.write_u16(odd + 2, 8);
        memory.write_u64(odd + 8, 0x47_100);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringCreate,
                &[odd, 0, string_out],
            )
            .expect("odd unicode length"),
            STATUS_INVALID_PARAMETER
        );
        let overlong = 0x48_000;
        memory.map_bytes(overlong, &[0_u8; 0x20]);
        memory.write_u16(overlong, 4);
        memory.write_u16(overlong + 2, 2);
        memory.write_u64(overlong + 8, 0x48_100);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringCreate,
                &[overlong, 0, string_out],
            )
            .expect("length beyond maximum"),
            STATUS_INVALID_PARAMETER
        );
        let missing = 0x49_000;
        memory.map_bytes(missing, &[0_u8; 0x20]);
        memory.write_u16(missing, 4);
        memory.write_u16(missing + 2, 4);
        memory.write_u64(missing + 8, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfStringCreate,
                &[missing, 0, string_out],
            )
            .expect("null unicode buffer"),
            STATUS_INVALID_PARAMETER
        );
        let extra_type = 0x4A_000;
        let extra_out = 0x4A_100;
        memory.map_bytes(extra_type, &[0_u8; 0x20]);
        memory.map_bytes(extra_out, &[0_u8; 8]);
        memory.write_u32(extra_type, 0x18);
        memory.write_u64(extra_type + 0x10, 0x20);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectAllocateContext,
                &[device, extra_type, extra_out],
            )
            .expect("allocate extra context"),
            STATUS_SUCCESS
        );
        let extra = memory.read_u64(extra_out).expect("extra context");
        assert_ne!(extra, 0);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[device, extra_type],
            )
            .expect("typed extra context"),
            extra
        );
        let device_object = island
            .inner
            .borrow()
            .kmdf
            .devices
            .get(&device)
            .expect("device")
            .object_guest;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtPnpDispatch,
                &[0, device_object],
            )
            .expect("pnp without an IRP"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtPowerDispatch,
                &[0, device_object],
            )
            .expect("power without an IRP"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtPnpDispatch,
                &[0x1234, 0xDEAD],
            )
            .expect("pnp for an unknown device"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtPowerDispatch,
                &[0x1234, 0xDEAD],
            )
            .expect("power for an unknown device"),
            STATUS_INVALID_DEVICE_REQUEST
        );
    });
}

#[test]
fn wdf_device_enqueue_request_rejects_double_enqueue_and_dispatch_edges() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _dir, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfEnqueue");
        let device = island.kmdf_device_handles()[0];
        let queue = *island
            .inner
            .borrow()
            .kmdf
            .queues
            .keys()
            .next()
            .expect("fixture queue");
        let base = island.image_base();
        let request_out = 0x41_000;
        let output = 0x42_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        memory.map_bytes(output, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, 0, request_out],
            )
            .expect("request create"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).expect("request");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForIoctl,
                &[request, 0, 0x0022_0004, 0, 0, output, 4, 0],
            )
            .expect("format request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, request],
            )
            .expect("enqueue"),
            STATUS_SUCCESS
        );
        assert_eq!(
            memory
                .read_u32(base + u64::from(K_IOCTL_MARKER_RVA))
                .expect("ioctl marker"),
            0x0022_0004
        );
        assert_eq!(
            island.kmdf_request_state(request),
            Some((true, STATUS_SUCCESS, 4, 0))
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, request],
            )
            .expect("double enqueue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[0xDEAD, request],
            )
            .expect("stale enqueue device"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, 0xDEAD],
            )
            .expect("stale enqueue request"),
            STATUS_INVALID_DEVICE_REQUEST
        );

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStop,
                &[queue, 0, 0],
            )
            .expect("stop queue"),
            STATUS_SUCCESS
        );
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, 0, request_out],
            )
            .expect("deferred request create"),
            STATUS_SUCCESS
        );
        let deferred = memory.read_u64(request_out).expect("deferred request");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForIoctl,
                &[deferred, 0, 0x0022_0004, 0, 0, output, 4, 0],
            )
            .expect("deferred format"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, deferred],
            )
            .expect("deferred enqueue"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_request_state(deferred).map(|state| state.0),
            Some(false)
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueRetrieveNextRequest,
                &[queue, request_out],
            )
            .expect("retrieve deferred"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u64(request_out).expect("retrieved"), deferred);

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStart,
                &[queue],
            )
            .expect("start queue"),
            STATUS_SUCCESS
        );
        set_queue_callbacks(&island, queue, |record| {
            record.callbacks.default = 0;
            record.callbacks.device_control = 0;
        });
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, 0, request_out],
            )
            .expect("callbackless request create"),
            STATUS_SUCCESS
        );
        let callbackless = memory.read_u64(request_out).expect("callbackless request");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, callbackless],
            )
            .expect("callbackless enqueue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island.kmdf_request_state(callbackless).map(|state| state.1),
            Some(STATUS_INVALID_DEVICE_REQUEST)
        );
    });
}

#[test]
fn wdf_pdo_init_rejects_malformed_ids_and_invalid_parent() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaWdfPdo");
        let device = island.kmdf_device_handles()[0];
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAllocate,
                &[0xDEAD],
            )
            .expect("stale parent"),
            STATUS_INVALID_HANDLE
        );
        let init = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfPdoInitAllocate,
            &[device],
        )
        .expect("pdo init");
        assert_ne!(init, 0);
        let ordinary_init = *island
            .inner
            .borrow()
            .kmdf
            .device_inits
            .keys()
            .find(|handle| **handle != init)
            .expect("ordinary device init");
        let device_id = guest_unicode_string(&mut memory, 0x43_000, "CasaPnpDev");
        let hardware_id = guest_unicode_string(&mut memory, 0x44_000, "CasaPnpHw");
        let instance_id = guest_unicode_string(&mut memory, 0x45_000, "Instance1");
        let empty = guest_unicode_string(&mut memory, 0x46_000, "");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAssignDeviceID,
                &[0xDEAD, device_id],
            )
            .expect("stale pdo init"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAssignDeviceID,
                &[ordinary_init, device_id],
            )
            .expect("non-pdo init"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAssignDeviceID,
                &[init, 0xDEAD_0000],
            )
            .expect("invalid device id string"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAssignDeviceID,
                &[init, empty],
            )
            .expect("empty device id"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAssignDeviceID,
                &[init, device_id],
            )
            .expect("device id"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAddHardwareID,
                &[init, 0xDEAD_0000],
            )
            .expect("invalid hardware id string"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAddHardwareID,
                &[init, empty],
            )
            .expect("empty hardware id"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAddHardwareID,
                &[0xDEAD, hardware_id],
            )
            .expect("stale hardware id init"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAddHardwareID,
                &[ordinary_init, hardware_id],
            )
            .expect("non-pdo hardware id"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAddCompatibleID,
                &[ordinary_init, hardware_id],
            )
            .expect("non-pdo compatible id"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAssignInstanceID,
                &[init, instance_id],
            )
            .expect("instance id"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAddCompatibleID,
                &[init, hardware_id],
            )
            .expect("compatible id"),
            STATUS_SUCCESS
        );
        for _ in 0..16 {
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfPdoInitAddHardwareID,
                    &[init, hardware_id],
                )
                .expect("hardware id"),
                STATUS_SUCCESS
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfPdoInitAddHardwareID,
                &[init, hardware_id],
            )
            .expect("hardware id overflow"),
            STATUS_INSUFFICIENT_RESOURCES
        );
        let device_out = 0x47_000;
        memory.map_bytes(device_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[0xDEAD, 0, device_out],
            )
            .expect("stale pdo create"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[init, 0, device_out],
            )
            .expect("pdo device create"),
            STATUS_SUCCESS
        );
        let created = memory.read_u64(device_out).expect("pdo handle");
        let state = island.inner.borrow();
        let record = state.kmdf.devices.get(&created).expect("pdo device");
        assert_eq!(record.device_id.as_deref(), Some("CasaPnpDev"));
        assert_eq!(record.hardware_ids.len(), 16);
        assert_eq!(record.compatible_ids.len(), 1);
        assert_eq!(record.instance_id.as_deref(), Some("Instance1"));
        assert_eq!(record.power_state, WDF_POWER_DEVICE_D3);
        assert!(!record.started);
    });
}

#[test]
fn pnp_x86_callbacks_power_and_sized_context_reject_stale_edges() {
    with_big_stack(|| {
        let image = build_kmdf_driver_pe32();
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x86(&image, "CasaPnpX86");
        let init = *island
            .inner
            .borrow()
            .kmdf
            .device_inits
            .keys()
            .next()
            .expect("x86 device init");
        let device = island.created_devices()[0].guest_pointer;
        let config = 0x41_000;
        memory.map_bytes(config, &[0_u8; 0x40]);
        memory.write_u32(config, 4);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                &[init, config],
            )
            .expect("short x86 pnp callbacks"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let parsed = state.kmdf.device_inits.get(&init).expect("init").pnp_power;
            assert_eq!(parsed.prepare_hardware, 0);
            assert_eq!(parsed.self_managed_io_fini, 0);
        }
        memory.write_u32(config, 0x2C);
        for (index, offset) in [0x04u32, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C]
            .iter()
            .enumerate()
        {
            memory.write_u32(config + u64::from(*offset), 0x1000 + index as u32 * 0x10);
        }
        memory.write_u32(config + 0x28, 0x2000);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPnpPowerEventCallbacks,
                &[init, config],
            )
            .expect("full x86 pnp callbacks"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let parsed = state.kmdf.device_inits.get(&init).expect("init").pnp_power;
            assert_eq!(parsed.prepare_hardware, 0x1000);
            assert_eq!(parsed.release_hardware, 0x1010);
            assert_eq!(parsed.d0_entry, 0x1020);
            assert_eq!(parsed.d0_exit, 0x1030);
            assert_eq!(parsed.self_managed_io_init, 0x1040);
            assert_eq!(parsed.self_managed_io_suspend, 0x1050);
            assert_eq!(parsed.self_managed_io_restart, 0x1060);
            assert_eq!(parsed.self_managed_io_fini, 0);
            assert_eq!(parsed.surprise_removal, 0x2000);
        }
        let file_config = 0x42_000;
        memory.map_bytes(file_config, &[0_u8; 0x20]);
        memory.write_u32(file_config, 8);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetFileObjectConfig,
                &[init, file_config, 0],
            )
            .expect("short x86 file config"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let parsed = state
                .kmdf
                .device_inits
                .get(&init)
                .expect("init")
                .file_object;
            assert_eq!(parsed.evt_file_cleanup, 0);
            assert_eq!(parsed.evt_file_close, 0);
        }
        memory.write_u32(file_config, 0x18);
        memory.write_u32(file_config + 0x08, 0x3000);
        memory.write_u32(file_config + 0x0C, 0x3010);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetFileObjectConfig,
                &[init, file_config, 0],
            )
            .expect("full x86 file config"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let parsed = state
                .kmdf
                .device_inits
                .get(&init)
                .expect("init")
                .file_object;
            assert_eq!(parsed.evt_file_close, 0x3000);
            assert_eq!(parsed.evt_file_cleanup, 0x3010);
        }
        let device_handle = island.kmdf_device_handles()[0];
        let type_info = 0x43_000;
        memory.map_bytes(type_info, &[0_u8; 0x20]);
        memory.write_u32(type_info, 0x10);
        memory.write_u32(type_info + 0x08, 0x1000);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[device_handle, type_info],
            )
            .expect("oversized x86 typed context"),
            0
        );
        memory.write_u32(type_info + 0x08, 0x40);
        assert_ne!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectGetTypedContext,
                &[device_handle, type_info],
            )
            .expect("sized x86 typed context"),
            0
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("x86 D3 before start")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("x86 start")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("x86 D3")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("x86 D0")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                .expect("x86 stop")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_STOP_DEVICE)
                .expect("repeated x86 stop")
                .0,
            STATUS_INVALID_DEVICE_REQUEST
        );
    });
}

#[test]
fn pnp_start_without_release_and_cleanup_without_hardware_roll_back() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, base, device) =
            pnp_load("CasaPnpRollbackEdges");
        let handle = island.kmdf_device_handles()[0];
        {
            let mut state = island.inner.borrow_mut();
            let record = state.kmdf.devices.get_mut(&handle).expect("device");
            record.pnp_power.prepare_hardware = 0;
            record.pnp_power.release_hardware = 0;
            record.pnp_power.self_managed_io_init = 0;
        }
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("start without prepare/release/self-io")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_PREPARE_COUNT), 0);
        assert_eq!(pnp_u32(&memory, base, P_SELFINIT_COUNT), 0);
        assert_eq!(pnp_u32(&memory, base, P_RELEASE_COUNT), 0);
    });
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, false);
        let (mut runtime, _dir, mut memory, island) =
            load_staged_island_x64(&image, "CasaPnpStaleFileDevice");
        let handles = island.kmdf_device_handles();
        let stale_handle = handles[1];
        let (object, casak) = {
            let state = island.inner.borrow();
            let record = state.kmdf.devices.get(&stale_handle).expect("device");
            (record.object_guest, record.casak)
        };
        {
            let mut state = island.inner.borrow_mut();
            state
                .kmdf
                .devices
                .get_mut(&stale_handle)
                .expect("device")
                .file_cleanup = 0x1234;
            state.io.delete_device(casak).expect("delete stale device");
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtIoCleanupDispatch,
                &[0, object],
            )
            .expect("file dispatch for a deleted device"),
            crate::casak::io::STATUS_DELETE_PENDING
        );
    });
}

#[test]
fn kmdf_dispatch_arena_exhaustion_rejects_with_io_error() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfArenaFault");
        let device_object = *island
            .inner
            .borrow()
            .kmdf
            .devices_by_object
            .keys()
            .next()
            .expect("device object");
        {
            let mut state = island.inner.borrow_mut();
            let handle = *state
                .kmdf
                .devices_by_object
                .get(&device_object)
                .expect("device handle");
            state
                .kmdf
                .devices
                .get_mut(&handle)
                .expect("device")
                .file_cleanup = 0x1234;
        }
        let saved_cursor = {
            let mut state = island.inner.borrow_mut();
            let saved = state.arena.cursor;
            state.arena.cursor = state.arena.end;
            saved
        };
        let error = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfEvtIoDeviceControlDispatch,
            &[0, device_object],
        )
        .expect_err("exhausted arena must reject request creation");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert_eq!(
            error.message.contains("driver island arena exhausted"),
            true
        );
        let error = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfEvtIoCleanupDispatch,
            &[0, device_object],
        )
        .expect_err("exhausted arena must reject file request creation");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert_eq!(
            error.message.contains("driver island arena exhausted"),
            true
        );
        island.inner.borrow_mut().arena.cursor = saved_cursor;
    });
}

fn kernel_test_island() -> (PeHostRuntime, MemoryImage, DriverIsland) {
    let (mut runtime, _directory) = test_runtime();
    let mut memory = MemoryImage::default();
    prepare_guest_memory(&mut runtime, &mut memory);
    let bytes = build_test_driver(false, false, false);
    let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
        .expect("DriverEntry must execute");
    (runtime, memory, island)
}

fn call_kernel_raw(
    island: &DriverIsland,
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    function: DriverShim,
    args: &[u64],
) -> u64 {
    island
        .call_shim_for_test(runtime, memory, function, args)
        .expect("kernel shim")
}

fn call_kernel_shim(
    island: &DriverIsland,
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    function: DriverShim,
    args: &[u64],
) -> i32 {
    call_kernel_raw(island, runtime, memory, function, args) as u32 as i32
}

#[test]
fn irql_and_spinlock_state_machine_rejects_invalid_transitions_exactly() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let lock = 0x54_000;
        memory.map_bytes(lock, &[0_u8; 0x40]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeGetCurrentIrql,
                &[],
            ),
            0
        );
        let untagged = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::ExAllocatePool,
            &[u64::from(NON_PAGED_POOL), 0x20],
        );
        assert_ne!(untagged, 0);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::ExFreePool,
            &[untagged],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[u64::from(NON_PAGED_POOL), 0x100_0000],
            ),
            0
        );
        let saved_cursor = {
            let mut state = island.inner.borrow_mut();
            let saved = state.arena.cursor;
            state.arena.cursor = state.arena.end;
            saved
        };
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[u64::from(NON_PAGED_POOL), 0x100],
            ),
            0
        );
        island.inner.borrow_mut().arena.cursor = saved_cursor;
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[u64::from(PAGED_POOL), 0],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[9, 0x20],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePoolWithTag,
                &[9, 0x20, 0x31747343],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KfRaiseIrql,
                &[2],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeGetCurrentIrql,
                &[],
            ),
            2
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KfRaiseIrql,
                &[1],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[u64::from(PAGED_POOL), 0x20],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePoolWithTag,
                &[u64::from(PAGED_POOL), 0x20, 0x31747343],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KfLowerIrql,
                &[3],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[2],
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[1],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeGetCurrentIrql,
                &[],
            ),
            1
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KfRaiseIrql,
                &[0xFF],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeAcquireSpinLockRaiseToDpc,
                &[0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeAcquireSpinLockRaiseToDpc,
                &[lock],
            ),
            0
        );
        assert_eq!(memory.read_u64(lock).unwrap(), 1);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeAcquireSpinLockRaiseToDpc,
                &[lock],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReleaseSpinLock,
                &[lock, 1],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReleaseSpinLock,
                &[lock, 0],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u64(lock).unwrap(), 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReleaseSpinLock,
                &[lock, 0],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeGetCurrentIrql,
                &[],
            ),
            0
        );
    });
}

#[test]
fn paged_pool_is_refused_at_dispatch_level() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let paged = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::ExAllocatePool,
            &[u64::from(PAGED_POOL), 0x20],
        );
        assert_ne!(paged, 0);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::ExFreePool,
            &[paged],
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfRaiseIrql,
            &[u64::from(DISPATCH_LEVEL)],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[u64::from(PAGED_POOL), 0x20],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePoolWithTag,
                &[u64::from(PAGED_POOL), 0x20, 0x31747343],
            ),
            0
        );
        assert_ne!(
            call_kernel_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[u64::from(NON_PAGED_POOL), 0x20],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocatePool,
                &[9, 0x20],
            ),
            0
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
    });
}

#[test]
fn mdl_locking_probe_and_lifecycle_pin_exact_statuses() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let virtual_address = 0x56_000;
        memory.map_bytes(virtual_address, &vec![0_u8; 0x2000]);
        let mdl = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoAllocateMdl,
            &[virtual_address, 0x2000, 0, 0, 0],
        );
        assert_ne!(mdl, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmGetMdlByteCount,
                &[mdl],
            ),
            0x2000
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmProbeAndLockPages,
                &[mdl, u64::from(KERNEL_MODE), u64::from(IO_READ_ACCESS)],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmProbeAndLockPages,
                &[mdl, u64::from(KERNEL_MODE), u64::from(IO_READ_ACCESS)],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoFreeMdl,
                &[mdl],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmUnlockPages,
                &[mdl],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmUnlockPages,
                &[mdl],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoFreeMdl,
                &[mdl],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoFreeMdl,
                &[mdl],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoAllocateMdl,
                &[virtual_address, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoAllocateMdl,
                &[virtual_address, 0x1000, 1, 0, 0],
            ),
            0
        );
        let unmapped = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoAllocateMdl,
            &[0x9FFF_0000, 0x1000, 0, 0, 0],
        );
        assert_ne!(unmapped, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmProbeAndLockPages,
                &[unmapped, u64::from(KERNEL_MODE), u64::from(IO_WRITE_ACCESS)],
            ),
            STATUS_ACCESS_VIOLATION
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmProbeAndLockPages,
                &[unmapped, u64::from(KERNEL_MODE), 9],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmGetMdlByteCount,
                &[0xDEAD],
            ),
            0
        );
        let write_mdl = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoAllocateMdl,
            &[virtual_address, 0x1000, 0, 0, 0],
        );
        assert_ne!(write_mdl, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmProbeAndLockPages,
                &[
                    write_mdl,
                    u64::from(KERNEL_MODE),
                    u64::from(IO_WRITE_ACCESS),
                ],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmUnlockPages,
                &[write_mdl],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmProbeAndLockPages,
                &[write_mdl, 9, u64::from(IO_READ_ACCESS)],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmProbeAndLockPages,
                &[0xDEAD, u64::from(KERNEL_MODE), u64::from(IO_READ_ACCESS)],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoFreeMdl,
                &[write_mdl],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::MmUnlockPages,
                &[0xDEAD],
            ),
            STATUS_INVALID_PARAMETER
        );
        let saved_cursor = {
            let mut state = island.inner.borrow_mut();
            let saved = state.arena.cursor;
            state.arena.cursor = state.arena.end;
            saved
        };
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoAllocateMdl,
                &[virtual_address, 0x1000, 0, 0, 0],
            ),
            0
        );
        island.inner.borrow_mut().arena.cursor = saved_cursor;
        assert!(!probe_guest_range(&runtime, &memory, 0, 0x1000, false));
        assert!(!probe_guest_range(
            &runtime,
            &memory,
            virtual_address,
            0,
            false
        ));
        assert_eq!(align_up(0x1234, 1), 0x1234);
        assert_eq!(align_up_usize(0x1234, 1), 0x1234);
        runtime
            .win32
            .address_space_mut()
            .register(0x70_000, 0x1000, VmRegionKind::Private);
        runtime
            .win32
            .address_space_mut()
            .commit(0x70_000, 0x1000, VmProtection::READ, false);
        memory.map_bytes(0x70_000, &[0_u8; 0x1000]);
        assert!(!probe_guest_range(&runtime, &memory, 0x70_000, 0x100, true));
        let mut x86_runtime = test_runtime_x86().0;
        let mut x86_memory = MemoryImage::default();
        prepare_guest_memory(&mut x86_runtime, &mut x86_memory);
        let x86_bytes = build_pe32_driver();
        let x86_island =
            DriverIsland::load_and_start(&x86_bytes, &mut x86_runtime, &mut x86_memory)
                .expect("PE32 DriverEntry must execute");
        let x86_va = 0x56_000;
        x86_memory.map_bytes(x86_va, &vec![0_u8; 0x1000]);
        let x86_mdl = call_kernel_raw(
            &x86_island,
            &mut x86_runtime,
            &mut x86_memory,
            DriverShim::IoAllocateMdl,
            &[x86_va, 0x1000, 0, 0, 0],
        );
        assert_ne!(x86_mdl, 0);
        assert_eq!(
            call_kernel_shim(
                &x86_island,
                &mut x86_runtime,
                &mut x86_memory,
                DriverShim::MmGetMdlByteCount,
                &[x86_mdl],
            ),
            0x1000
        );
    });
}

#[test]
fn dispatcher_events_auto_reset_and_report_exact_timeout() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let event = 0x57_000;
        let timeout = 0x57_100;
        memory.map_bytes(event, &[0_u8; 0x40]);
        memory.map_bytes(timeout, &[0_u8; 8]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[event, u64::from(SYNCHRONIZATION_EVENT), 0],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReadStateEvent,
                &[event],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[event, 0, 0, timeout],
            ),
            STATUS_TIMEOUT
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[event, 0, 0, 0],
            ),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeSetEvent,
                &[event, 0, 0],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReadStateEvent,
                &[event],
            ),
            1
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[event, 0, 0, timeout],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReadStateEvent,
                &[event],
            ),
            0
        );
        let notification = 0x57_200;
        memory.map_bytes(notification, &[0_u8; 0x40]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[notification, u64::from(NOTIFICATION_EVENT), 1],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[notification, 0, 0, timeout],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReadStateEvent,
                &[notification],
            ),
            1
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeResetEvent,
                &[notification],
            ),
            1
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeSetEvent,
                &[0xDEAD, 0, 0],
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeResetEvent,
                &[0xDEAD],
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReadStateEvent,
                &[0xDEAD],
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[0xDEAD, 0, 0, timeout],
            ),
            STATUS_INVALID_HANDLE
        );
        let invalid_type = 0x57_300;
        memory.map_bytes(invalid_type, &[0_u8; 0x40]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[invalid_type, 9, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u64(timeout, (-10_000_i64) as u64);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[event, 0, 0, timeout],
            ),
            STATUS_TIMEOUT
        );
        let concurrent = 0x57_400;
        memory.map_bytes(concurrent, &[0_u8; 0x40]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[concurrent, u64::from(SYNCHRONIZATION_EVENT), 0],
            ),
            STATUS_SUCCESS
        );
        let gate = island
            .inner
            .borrow()
            .kernel
            .events
            .get(&concurrent)
            .expect("initialized concurrent event")
            .gate
            .clone();
        let signaler = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            *gate
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
            gate.1.notify_all();
        });
        memory.write_u64(timeout, (-5_000_000_i64) as u64);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[concurrent, 0, 0, timeout],
            ),
            STATUS_SUCCESS
        );
        signaler.join().expect("signaler");
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeReadStateEvent,
                &[concurrent],
            ),
            0
        );
    });
}

#[test]
fn dpc_runs_only_when_irql_drops_and_removal_is_observable() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let dpc = 0x58_000;
        let second_dpc = 0x58_100;
        memory.map_bytes(dpc, &[0_u8; 0x40]);
        memory.map_bytes(second_dpc, &[0_u8; 0x40]);
        let routine = island.unload_pointer().expect("exported DriverUnload");
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeDpc,
                &[dpc, routine, 0xCAFE],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeDpc,
                &[second_dpc, routine, 0xBEEF],
            ),
            STATUS_SUCCESS
        );
        let marker = island.image_base() + u64::from(UNLOAD_MARKER_RVA);
        assert_eq!(memory.read_u32(marker).unwrap(), 0);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfRaiseIrql,
            &[u64::from(DISPATCH_LEVEL)],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[dpc, 0, 0],
            ),
            1
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[dpc, 0, 0],
            ),
            0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeRemoveQueueDpc,
                &[dpc],
            ),
            1
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
        assert_eq!(memory.read_u32(marker).unwrap(), 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeRemoveQueueDpc,
                &[dpc],
            ),
            0
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfRaiseIrql,
            &[u64::from(DISPATCH_LEVEL)],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[dpc, 0x11, 0x22],
            ),
            1
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
        assert_eq!(memory.read_u32(marker).unwrap(), 0xCA5A_0002);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfRaiseIrql,
            &[u64::from(DISPATCH_LEVEL)],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[dpc, 0, 0],
            ),
            1
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[second_dpc, 0, 0],
            ),
            1
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
        assert_eq!(memory.read_u32(marker).unwrap(), 0xCA5A_0002);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[0xDEAD, 0, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeDpc,
                &[0, routine, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeDpc,
                &[dpc, 0, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeRemoveQueueDpc,
                &[0xDEAD],
            ),
            0
        );
        memory.write_u32(marker, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[second_dpc, 0, 0],
            ),
            1
        );
        assert_eq!(memory.read_u32(marker).unwrap(), 0xCA5A_0002);
        let nester = 0x58_200;
        memory.map_bytes(nester, &[0_u8; 0x40]);
        let insert_shim = allocate_shim(&mut runtime, DriverShim::KeInsertQueueDpc);
        let stub = island.image_base() + 0x3400;
        let mut code = Vec::new();
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        code.extend_from_slice(&[0x48, 0xB9]);
        code.extend_from_slice(&second_dpc.to_le_bytes());
        code.extend_from_slice(&[0x31, 0xD2, 0x45, 0x31, 0xC0]);
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&insert_shim.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3]);
        for (index, byte) in code.iter().enumerate() {
            memory.write_u8(stub + index as u64, *byte);
        }
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeDpc,
                &[nester, stub, 0],
            ),
            STATUS_SUCCESS
        );
        memory.write_u32(marker, 0);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfRaiseIrql,
            &[u64::from(DISPATCH_LEVEL)],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInsertQueueDpc,
                &[nester, 0, 0],
            ),
            1
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
        assert_eq!(memory.read_u32(marker).unwrap(), 0xCA5A_0002);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeGetCurrentIrql,
                &[],
            ),
            0
        );
    });
}

#[test]
fn kernel_registry_query_pins_overflow_missing_and_access_contracts() {
    with_big_stack(|| {
        let (mut runtime, _directory) = test_runtime_with_ge(|ge| {
            ge.registry_create_key("HKLM", "SYSTEM\\CasaIslandTest", RegistryView::Native)
                .expect("create key");
            ge.registry_create_key(
                "HKLM",
                "SYSTEM\\CasaIslandTest\\NestedKey",
                RegistryView::Native,
            )
            .expect("create nested key");
            ge.registry_set_value(
                "HKLM",
                "SYSTEM\\CasaIslandTest",
                "Dword",
                "REG_DWORD",
                json!(0x1122_3344_u32),
                RegistryView::Native,
            )
            .expect("dword");
            ge.registry_set_value(
                "HKLM",
                "SYSTEM\\CasaIslandTest",
                "Text",
                "REG_SZ",
                json!("Casa"),
                RegistryView::Native,
            )
            .expect("string");
        });
        let mut memory = MemoryImage::default();
        prepare_guest_memory(&mut runtime, &mut memory);
        let bytes = build_test_driver(false, false, false);
        let island = DriverIsland::load_and_start(&bytes, &mut runtime, &mut memory)
            .expect("DriverEntry must execute");
        let attributes = 0x50_000;
        let name = guest_unicode_string(
            &mut memory,
            0x50_100,
            "\\Registry\\Machine\\SYSTEM\\CasaIslandTest",
        );
        memory.map_bytes(attributes, &[0_u8; 0x40]);
        memory.write_u64(attributes + 8, 0);
        memory.write_u64(attributes + 16, name);
        let handle_out = 0x51_000;
        memory.map_bytes(handle_out, &[0_u8; 8]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[0, 0x1, attributes],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_SUCCESS
        );
        let key = memory.read_u64(handle_out).unwrap();
        assert_ne!(key, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x2, attributes],
            ),
            STATUS_ACCESS_DENIED
        );
        let value_name = guest_unicode_string(&mut memory, 0x51_100, "Dword");
        let buffer = 0x52_000;
        let result_length = 0x53_000;
        memory.map_bytes(buffer, &[0_u8; 0x80]);
        memory.map_bytes(result_length, &[0_u8; 8]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[
                    key,
                    value_name,
                    u64::from(KEY_VALUE_PARTIAL_INFORMATION),
                    buffer,
                    8,
                    result_length,
                ],
            ),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(memory.read_u64(result_length).unwrap(), 16);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[
                    key,
                    value_name,
                    u64::from(KEY_VALUE_PARTIAL_INFORMATION),
                    buffer,
                    12,
                    result_length,
                ],
            ),
            STATUS_BUFFER_OVERFLOW
        );
        assert_eq!(memory.read_u64(result_length).unwrap(), 16);
        assert_eq!(memory.read_u32(buffer + 4).unwrap(), 4);
        assert_eq!(memory.read_u32(buffer + 8).unwrap(), 4);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[
                    key,
                    value_name,
                    u64::from(KEY_VALUE_PARTIAL_INFORMATION),
                    buffer,
                    16,
                    result_length,
                ],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(buffer + 12).unwrap(), 0x1122_3344);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[
                    key,
                    value_name,
                    u64::from(KEY_VALUE_PARTIAL_INFORMATION),
                    buffer,
                    16,
                    0,
                ],
            ),
            STATUS_SUCCESS
        );
        let text_name = guest_unicode_string(&mut memory, 0x51_300, "Text");
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[
                    key,
                    text_name,
                    u64::from(KEY_VALUE_FULL_INFORMATION),
                    buffer,
                    0x80,
                    result_length,
                ],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(buffer + 4).unwrap(), 1);
        assert_eq!(memory.read_u32(buffer + 12).unwrap(), 10);
        assert_eq!(memory.read_u32(buffer + 16).unwrap(), 8);
        assert_eq!(
            &memory.read_bytes(buffer + 28, 10).unwrap(),
            b"C\0a\0s\0a\0\0\0"
        );
        let missing = guest_unicode_string(&mut memory, 0x51_400, "Nope");
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[
                    key,
                    missing,
                    u64::from(KEY_VALUE_PARTIAL_INFORMATION),
                    buffer,
                    0x80,
                    result_length,
                ],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        let user_path = 0x50_300;
        let user_name = guest_unicode_string(&mut memory, user_path, "\\Registry\\User\\Casa");
        memory.write_u64(attributes + 16, user_name);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_PATH_INVALID
        );
        let relative = guest_unicode_string(&mut memory, 0x50_500, "SYSTEM\\CasaIslandTest");
        memory.write_u64(attributes + 16, relative);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_PATH_INVALID
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwClose,
                &[key],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwClose,
                &[key],
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[
                    key,
                    value_name,
                    u64::from(KEY_VALUE_PARTIAL_INFORMATION),
                    buffer,
                    0x80,
                    result_length,
                ],
            ),
            STATUS_INVALID_HANDLE
        );
        let empty_name = guest_unicode_string(&mut memory, 0x50_700, "");
        memory.write_u64(attributes + 8, 0);
        memory.write_u64(attributes + 16, empty_name);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_INVALID_PARAMETER
        );
        let system_name =
            guest_unicode_string(&mut memory, 0x50_800, "\\Registry\\Machine\\SYSTEM");
        memory.write_u64(attributes + 16, system_name);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_SUCCESS
        );
        let system_key = memory.read_u64(handle_out).unwrap();
        let relative = guest_unicode_string(&mut memory, 0x50_A00, "CasaIslandTest");
        memory.write_u64(attributes + 8, system_key);
        memory.write_u64(attributes + 16, relative);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_SUCCESS
        );
        let relative_key = memory.read_u64(handle_out).unwrap();
        assert_ne!(relative_key, system_key);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwClose,
                &[relative_key],
            ),
            STATUS_SUCCESS
        );
        memory.write_u64(attributes + 8, 0xDEAD);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_PATH_INVALID
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwClose,
                &[system_key],
            ),
            STATUS_SUCCESS
        );
        let missing_nested = guest_unicode_string(
            &mut memory,
            0x50_C00,
            "\\Registry\\Machine\\SYSTEM\\Missing",
        );
        memory.write_u64(attributes + 8, 0);
        memory.write_u64(attributes + 16, missing_nested);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        let double_separator = guest_unicode_string(
            &mut memory,
            0x54_200,
            "\\Registry\\Machine\\SYSTEM\\\\CasaIslandTest",
        );
        memory.write_u64(attributes + 8, 0);
        memory.write_u64(attributes + 16, double_separator);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_PATH_INVALID
        );
        let missing_intermediate = guest_unicode_string(
            &mut memory,
            0x54_400,
            "\\Registry\\Machine\\SYSTEM\\Missing\\Child",
        );
        memory.write_u64(attributes + 16, missing_intermediate);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        let deep_existing = guest_unicode_string(
            &mut memory,
            0x54_600,
            "\\Registry\\Machine\\SYSTEM\\CasaIslandTest\\NestedKey",
        );
        memory.write_u64(attributes + 16, deep_existing);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_SUCCESS
        );
        let deep_key = memory.read_u64(handle_out).unwrap();
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwClose,
                &[deep_key],
            ),
            STATUS_SUCCESS
        );
        let machine_only = guest_unicode_string(&mut memory, 0x50_E00, "\\Registry\\Machine\\");
        memory.write_u64(attributes + 16, machine_only);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_PATH_INVALID
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_OBJECT_PATH_INVALID
        );
        let x86_attributes = 0x54_000;
        memory.map_bytes(x86_attributes, &[0_u8; 0x20]);
        memory.write_u32(x86_attributes + 4, 0x1234);
        memory.write_u32(x86_attributes + 8, 0x5678);
        assert_eq!(
            read_object_attributes(&memory, x86_attributes, GuestArch::X86).unwrap(),
            (0x1234, 0x5678)
        );
        let multi = StoredRegistryValue {
            value_type: "REG_MULTI_SZ".to_string(),
            data: json!(["A", "B"]),
        };
        assert_eq!(registry_value_bytes(&multi).unwrap().0, 7);
        let expected_multi = "A\0B\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(registry_value_bytes(&multi).unwrap().1, expected_multi);
        let qword = StoredRegistryValue {
            value_type: "REG_QWORD".to_string(),
            data: json!(0x1122_3344_5566_7788_u64),
        };
        assert_eq!(registry_value_bytes(&qword).unwrap().0, 11);
        assert_eq!(
            registry_value_bytes(&qword).unwrap().1,
            0x1122_3344_5566_7788_u64.to_le_bytes()
        );
        let big_endian = StoredRegistryValue {
            value_type: "REG_DWORD_BIG_ENDIAN".to_string(),
            data: json!(0x1122_3344_u32),
        };
        assert_eq!(registry_value_bytes(&big_endian).unwrap().0, 5);
        assert_eq!(
            registry_value_bytes(&big_endian).unwrap().1,
            [0x11, 0x22, 0x33, 0x44]
        );
        let binary = StoredRegistryValue {
            value_type: "REG_BINARY".to_string(),
            data: json!([1, 2, 255]),
        };
        assert_eq!(registry_value_bytes(&binary).unwrap(), (3, vec![1, 2, 255]));
        let malformed_binary = StoredRegistryValue {
            value_type: "REG_BINARY".to_string(),
            data: json!(["not-a-byte"]),
        };
        assert_eq!(registry_value_bytes(&malformed_binary), None);
        let unsupported = StoredRegistryValue {
            value_type: "REG_LINK".to_string(),
            data: json!("target"),
        };
        assert_eq!(registry_value_bytes(&unsupported), None);
        memory.write_u64(attributes + 8, 0);
        memory.write_u64(attributes + 16, system_name);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwOpenKey,
                &[handle_out, 0x1, attributes],
            ),
            STATUS_SUCCESS
        );
        let reopened = memory.read_u64(handle_out).unwrap();
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwQueryValueKey,
                &[reopened, value_name, 9, buffer, 0x80, result_length],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ZwClose,
                &[reopened],
            ),
            STATUS_SUCCESS
        );
    });
}

#[test]
fn lookaside_reuses_the_same_guest_buffer_and_rejects_stale_frees() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let lookaside = 0x59_000;
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExFreeToNPagedLookasideList,
                &[0xDEAD, 0x1000],
            ),
            STATUS_INVALID_HANDLE,
            "an unknown lookaside list is rejected"
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializeNPagedLookasideList,
                &[lookaside, 0, 0, 0, 0x40, 0x31747343, 4],
            ),
            STATUS_SUCCESS
        );
        let first = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::ExAllocateFromNPagedLookasideList,
            &[lookaside],
        );
        assert_ne!(first, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExFreeToNPagedLookasideList,
                &[lookaside, first],
            ),
            STATUS_SUCCESS
        );
        let reused = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::ExAllocateFromNPagedLookasideList,
            &[lookaside],
        );
        assert_eq!(reused, first);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExFreeToNPagedLookasideList,
                &[lookaside, 0xDEAD],
            ),
            STATUS_INVALID_ADDRESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializeNPagedLookasideList,
                &[0x59_100, 1, 0, 0, 0x40, 0x31747343, 4],
            ),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializePagedLookasideList,
                &[0x59_200, 0, 0, 0, 0, 0x31747343, 4],
            ),
            STATUS_INVALID_PARAMETER
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfRaiseIrql,
            &[u64::from(DISPATCH_LEVEL)],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializePagedLookasideList,
                &[0x59_300, 0, 0, 0, 0x40, 0x31747343, 4],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocateFromPagedLookasideList,
                &[lookaside],
            ),
            0
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
        let paged_lookaside = 0x59_200;
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializePagedLookasideList,
                &[paged_lookaside, 0, 0, 0, 0x40, 0x31747343, 2],
            ),
            STATUS_SUCCESS
        );
        let paged_first = call_kernel_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::ExAllocateFromPagedLookasideList,
            &[paged_lookaside],
        );
        assert_ne!(paged_first, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExFreeToPagedLookasideList,
                &[paged_lookaside, paged_first],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocateFromPagedLookasideList,
                &[paged_lookaside],
            ),
            paged_first
        );
        assert_eq!(
            call_kernel_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocateFromNPagedLookasideList,
                &[0xBAD0],
            ),
            0
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfRaiseIrql,
            &[u64::from(DISPATCH_LEVEL)],
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExFreeToPagedLookasideList,
                &[paged_lookaside, paged_first],
            ),
            STATUS_INVALID_DEVICE_STATE
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KfLowerIrql,
            &[0],
        );
        let budget_lookaside = 0x59_400;
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializeNPagedLookasideList,
                &[budget_lookaside, 0, 0, 0, 0x40, 0x31747343, 1],
            ),
            STATUS_SUCCESS
        );
        assert_ne!(
            call_kernel_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocateFromNPagedLookasideList,
                &[budget_lookaside],
            ),
            0
        );
        assert_eq!(
            call_kernel_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocateFromNPagedLookasideList,
                &[budget_lookaside],
            ),
            0
        );
        let exhausted_lookaside = 0x59_500;
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializeNPagedLookasideList,
                &[exhausted_lookaside, 0, 0, 0, 0x40, 0x31747343, 1],
            ),
            STATUS_SUCCESS
        );
        let saved_cursor = {
            let mut state = island.inner.borrow_mut();
            let saved = state.arena.cursor;
            state.arena.cursor = state.arena.end;
            saved
        };
        assert_eq!(
            call_kernel_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExAllocateFromNPagedLookasideList,
                &[exhausted_lookaside],
            ),
            0
        );
        island.inner.borrow_mut().arena.cursor = saved_cursor;
        let foreign_source = 0x59_600;
        let foreign_target = 0x59_700;
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializeNPagedLookasideList,
                &[foreign_source, 0, 0, 0, 0x40, 0x31747343, 1],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExInitializeNPagedLookasideList,
                &[foreign_target, 0, 0, 0, 0x40, 0x31747343, 1],
            ),
            STATUS_SUCCESS
        );
        let foreign_block = {
            let mut state = island.inner.borrow_mut();
            state
                .kernel
                .lookasides
                .get_mut(&foreign_source)
                .expect("foreign source list")
                .list
                .allocate(0x40)
                .expect("foreign block")
        };
        {
            let mut state = island.inner.borrow_mut();
            state
                .kernel
                .lookasides
                .get_mut(&foreign_target)
                .expect("foreign target list")
                .block_by_guest
                .insert(0xDEAD, foreign_block);
        }
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::ExFreeToNPagedLookasideList,
                &[foreign_target, 0xDEAD],
            ),
            STATUS_INVALID_ADDRESS
        );
    });
}

#[test]
fn host_limited_kernel_services_fail_closed_with_exact_statuses() {
    with_big_stack(|| {
        assert_eq!(DriverShim::EtwUnregister.x86_arg_bytes(), 4);
        assert_eq!(DriverShim::EtwWrite.x86_arg_bytes(), 16);
        assert_eq!(DriverShim::KeQueryInterruptTime.x86_arg_bytes(), 0);
        assert_eq!(DriverShim::IslandSafepoint.x86_arg_bytes(), 0);
        let (mut runtime, mut memory, island) = kernel_test_island();
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[0, 0, 0, 0, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterrupt,
                &[0; 11],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwRegister,
                &[0, 0, 0, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::NtAlpcConnectPort,
                &[0; 7],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsGetCurrentProcessId,
                &[],
            ) as u32,
            runtime.win32.current_process_id()
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsGetCurrentThreadId,
                &[],
            ) as u32,
            runtime.win32.current_thread_id()
        );
        let time_out = 0x5A_000;
        memory.map_bytes(time_out, &[0_u8; 8]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeQuerySystemTime,
                &[time_out],
            ),
            STATUS_SUCCESS
        );
        let first = memory.read_u64(time_out).unwrap();
        assert!(first > 116_444_736_000_000_000);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeQuerySystemTime,
                &[time_out],
            ),
            STATUS_SUCCESS
        );
        assert!(memory.read_u64(time_out).unwrap() >= first);
    });
}
fn x64_mov_rax(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn x64_mov_rcx(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x48, 0xB9]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn x64_mov_rdx(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x48, 0xBA]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn x64_mov_r8(code: &mut Vec<u8>, value: u64) {
    code.extend_from_slice(&[0x49, 0xB8]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn x64_call_rax(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0xFF, 0xD0]);
}

fn x64_store_rax_imm32(code: &mut Vec<u8>, value: u32) {
    code.extend_from_slice(&[0xC7, 0x00]);
    code.extend_from_slice(&value.to_le_bytes());
}

fn x64_stub(memory: &mut MemoryImage, island: &DriverIsland, code: &[u8]) -> u64 {
    let address = island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, code.len(), 16)
        .expect("stub allocation");
    memory.map_bytes(address, code);
    address
}

fn x64_thread_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    counter: u64,
    exit_status: u32,
    store_context: bool,
    terminate_status: Option<(u64, u32)>,
) -> u64 {
    let mut code = Vec::new();
    if store_context {
        x64_mov_rax(&mut code, counter);
        code.extend_from_slice(&[0x48, 0x89, 0x08]); // mov [rax], rcx
    }
    if let Some((shim, status)) = terminate_status {
        x64_mov_rcx(&mut code, u64::from(status));
        x64_mov_rax(&mut code, shim);
        x64_call_rax(&mut code);
    }
    code.extend_from_slice(&[0xB8]);
    code.extend_from_slice(&exit_status.to_le_bytes());
    code.push(0xC3);
    x64_stub(memory, island, &code)
}

fn x64_counter_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    counter: u64,
    marker: u32,
) -> u64 {
    let mut code = Vec::new();
    x64_mov_rax(&mut code, counter);
    x64_store_rax_imm32(&mut code, marker);
    code.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]);
    x64_stub(memory, island, &code)
}

fn x64_store_stack(code: &mut Vec<u8>, offset: u8, value: u64) {
    x64_mov_rax(code, value);
    code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, offset]);
}

fn x64_wait_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    shim: u64,
    object: u64,
    alertable: bool,
    timeout_pointer: u64,
) -> u64 {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
    x64_store_stack(&mut code, 0x20, timeout_pointer);
    x64_mov_rcx(&mut code, object);
    code.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx
    code.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d
    code.extend_from_slice(&[0x41, 0xB9]);
    code.extend_from_slice(&u32::from(alertable).to_le_bytes());
    x64_mov_rax(&mut code, shim);
    x64_call_rax(&mut code);
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    x64_stub(memory, island, &code)
}

fn x64_wait_indirect_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    shim: u64,
    object_slot: u64,
    alertable: bool,
    timeout_pointer: u64,
) -> u64 {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    x64_store_stack(&mut code, 0x20, timeout_pointer);
    x64_mov_rcx(&mut code, object_slot);
    code.extend_from_slice(&[0x48, 0x8B, 0x09]); // mov rcx, [rcx]
    code.extend_from_slice(&[0x31, 0xD2]);
    code.extend_from_slice(&[0x45, 0x31, 0xC0]);
    code.extend_from_slice(&[0x41, 0xB9]);
    code.extend_from_slice(&u32::from(alertable).to_le_bytes());
    x64_mov_rax(&mut code, shim);
    x64_call_rax(&mut code);
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
    x64_stub(memory, island, &code)
}

fn x64_signal_event_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    shim: u64,
    event: u64,
) -> u64 {
    let mut code = Vec::new();
    x64_mov_rcx(&mut code, event);
    x64_mov_rax(&mut code, shim);
    x64_call_rax(&mut code);
    code.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]);
    x64_stub(memory, island, &code)
}

fn x64_yield_loop_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    safepoint: u64,
    counter: u64,
    iterations: u32,
    final_sequence: u64,
) -> u64 {
    let mut code = vec![0x31, 0xDB]; // xor ebx, ebx
    let loop_start = code.len();
    code.extend_from_slice(&[0x48, 0xFF, 0xC3]); // inc rbx
    x64_mov_rax(&mut code, counter);
    code.extend_from_slice(&[0x48, 0x89, 0x18]); // mov [rax], rbx
    x64_mov_rax(&mut code, safepoint);
    x64_call_rax(&mut code);
    code.extend_from_slice(&[0x48, 0x81, 0xFB]);
    code.extend_from_slice(&iterations.to_le_bytes());
    let branch = code.len();
    code.extend_from_slice(&[0x72, 0x00]);
    let after_branch = code.len();
    code[branch + 1] = (loop_start as isize - after_branch as isize) as i8 as u8;
    if final_sequence != 0 {
        x64_mov_rax(&mut code, final_sequence);
        x64_store_rax_imm32(&mut code, 3);
    }
    code.extend_from_slice(&[0x89, 0xD8, 0xC3]); // mov eax, ebx; ret
    x64_stub(memory, island, &code)
}

fn x64_self_terminate_loop_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    safepoint: u64,
    terminate_shim: u64,
    counter: u64,
    exit_status: u32,
    terminate_at: u32,
) -> u64 {
    let mut code = vec![0x31, 0xDB]; // xor ebx, ebx
    let loop_start = code.len();
    code.extend_from_slice(&[0x48, 0xFF, 0xC3]); // inc rbx
    x64_mov_rax(&mut code, counter);
    code.extend_from_slice(&[0x48, 0x89, 0x18]); // mov [rax], rbx
    code.extend_from_slice(&[0x48, 0x81, 0xFB]);
    code.extend_from_slice(&terminate_at.to_le_bytes());
    let jne = code.len();
    code.extend_from_slice(&[0x75, 0x00]); // jne skip
    x64_mov_rcx(&mut code, u64::from(exit_status));
    x64_mov_rax(&mut code, terminate_shim);
    x64_call_rax(&mut code);
    let skip = code.len();
    code[jne + 1] = (skip as isize - (jne + 2) as isize) as i8 as u8;
    x64_mov_rax(&mut code, safepoint);
    x64_call_rax(&mut code);
    let jump = code.len();
    code.extend_from_slice(&[0xEB, 0x00]);
    code[jump + 1] = (loop_start as isize - (jump + 2) as isize) as i8 as u8;
    code.push(0xC3);
    x64_stub(memory, island, &code)
}

fn x64_isr_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    shim_irql: u64,
    shim_insert: u64,
    shim_disconnect: Option<u64>,
    object_store: u64,
    context_out: u64,
    irql_out: u64,
    sequence: u64,
    dpc: u64,
    arg1: u64,
    arg2: u64,
    handled: u32,
) -> u64 {
    let mut code = Vec::new();
    // Save the incoming RCX/RDX (interrupt object and service context).
    x64_mov_rax(&mut code, object_store);
    code.extend_from_slice(&[0x48, 0x89, 0x08]); // mov [rax], rcx
    x64_mov_rax(&mut code, context_out);
    code.extend_from_slice(&[0x48, 0x89, 0x10]); // mov [rax], rdx
    // Observe the ISR IRQL.
    x64_mov_rax(&mut code, shim_irql);
    x64_call_rax(&mut code);
    x64_mov_rdx(&mut code, irql_out);
    code.extend_from_slice(&[0x88, 0x02]); // mov [rdx], al
    if let Some(shim) = shim_disconnect {
        x64_mov_rax(&mut code, object_store);
        code.extend_from_slice(&[0x48, 0x8B, 0x08]); // mov rcx, [rax]
        x64_mov_rax(&mut code, shim);
        x64_call_rax(&mut code);
    }
    // Queue the associated DPC; it runs after the ISR at DISPATCH_LEVEL.
    x64_mov_rcx(&mut code, dpc);
    x64_mov_rdx(&mut code, arg1);
    x64_mov_r8(&mut code, arg2);
    x64_mov_rax(&mut code, shim_insert);
    x64_call_rax(&mut code);
    x64_mov_rax(&mut code, sequence);
    x64_store_rax_imm32(&mut code, 1);
    code.extend_from_slice(&[0xB8]);
    code.extend_from_slice(&handled.to_le_bytes());
    code.push(0xC3);
    x64_stub(memory, island, &code)
}

fn x64_dpc_stub(
    memory: &mut MemoryImage,
    island: &DriverIsland,
    shim_irql: u64,
    irql_out: u64,
    sequence: u64,
) -> u64 {
    let mut code = Vec::new();
    x64_mov_rax(&mut code, shim_irql);
    x64_call_rax(&mut code);
    x64_mov_rdx(&mut code, irql_out);
    code.extend_from_slice(&[0x88, 0x02]); // mov [rdx], al
    x64_mov_rax(&mut code, sequence);
    x64_store_rax_imm32(&mut code, 2);
    code.push(0xC3);
    x64_stub(memory, island, &code)
}

fn arena_block(memory: &mut MemoryImage, island: &DriverIsland, size: usize) -> u64 {
    island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, size, 8)
        .expect("arena block")
}

fn arena_u64(memory: &mut MemoryImage, island: &DriverIsland, value: u64) -> u64 {
    let address = island
        .inner
        .borrow_mut()
        .arena
        .alloc(memory, 8, 8)
        .expect("counter allocation");
    memory.write_u64(address, value);
    address
}

#[test]
fn system_threads_execute_guest_code_with_context_exit_apcs_and_handle_close() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let handle_out = 0x5D_000;
        memory.map_bytes(handle_out, &[0_u8; 8]);
        let counter = arena_u64(&mut memory, &island, 0);
        let context = 0x5D_100;
        memory.map_bytes(context, &[0_u8; 8]);
        let start = x64_thread_stub(&mut memory, &island, counter, 0x37, true, None);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start, context],
            ),
            STATUS_SUCCESS
        );
        let handle = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        assert_ne!(handle.0, 0);
        assert_eq!(
            island
                .inner
                .borrow()
                .system_threads
                .exit_status(handle)
                .unwrap(),
            None
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[handle.0, 0, 0, 0],
            ),
            STATUS_TIMEOUT
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap(),
            None
        );
        assert_eq!(island.pump_system_threads(&mut runtime, &mut memory), 1);
        assert_eq!(memory.read_u64(counter).unwrap(), context);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap(),
            Some(0x37)
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[handle.0, 0, 0, 0],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(island.inner.borrow().system_threads.started_count(), 1);
        assert_eq!(island.inner.borrow().system_threads.completed_count(), 1);

        // APCs run before the start routine, in queue order.
        let apc_counter = arena_u64(&mut memory, &island, 0);
        let apc_stub = x64_counter_stub(&mut memory, &island, apc_counter, 1);
        let start_marker = x64_counter_stub(&mut memory, &island, apc_counter, 2);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start_marker, context],
            ),
            STATUS_SUCCESS
        );
        let apc_handle = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        assert_ne!(apc_handle.0, 0);
        island
            .inner
            .borrow_mut()
            .system_threads
            .queue_apc(apc_handle, apc_stub, 0)
            .unwrap();
        assert_eq!(island.pump_system_threads(&mut runtime, &mut memory), 1);
        assert_eq!(memory.read_u32(apc_counter).unwrap(), 2);

        // Closing the handle does not terminate the thread.
        let close_counter = arena_u64(&mut memory, &island, 0);
        let close_start = x64_thread_stub(&mut memory, &island, close_counter, 0x44, true, None);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, close_start, context],
            ),
            STATUS_SUCCESS
        );
        let close_handle = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        island
            .inner
            .borrow_mut()
            .system_threads
            .close_handle(close_handle)
            .unwrap();
        assert_eq!(island.pump_system_threads(&mut runtime, &mut memory), 1);
        assert_eq!(memory.read_u64(close_counter).unwrap(), context);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, close_handle, 0)
                .unwrap_err(),
            crate::casak::status::STATUS_INVALID_HANDLE
        );

        // PsTerminateSystemThread overrides the routine's return code.
        let terminate_shim = allocate_shim(&mut runtime, DriverShim::PsTerminateSystemThread);
        let terminate_thread = x64_thread_stub(
            &mut memory,
            &island,
            counter,
            0x11,
            false,
            Some((terminate_shim, 0x77)),
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, terminate_thread, context],
            ),
            STATUS_SUCCESS
        );
        let terminate_handle = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        assert_eq!(island.pump_system_threads(&mut runtime, &mut memory), 1);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, terminate_handle, 0)
                .unwrap(),
            Some(0x77)
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsTerminateSystemThread,
                &[0x55],
            ),
            STATUS_INVALID_HANDLE
        );
    });
}

#[test]
fn system_threads_reject_invalid_handles_routines_contexts_and_termination_races() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let handle_out = 0x5D_200;
        memory.map_bytes(handle_out, &[0_u8; 8]);
        let counter = arena_u64(&mut memory, &island, 0);
        let start = x64_thread_stub(&mut memory, &island, counter, 0x37, false, None);
        for args in [
            vec![0, 0, 0, 0, start, 0],
            vec![handle_out, 0, 0, 0, 0, 0],
            vec![handle_out, 0, 0, 0, 0xDEAD_BEEF, 0],
            vec![handle_out, 0, 0, 0, start, 0xDEAD_BEEF],
            vec![0xDEAD_BEEF, 0, 0, 0, start, 0],
            vec![handle_out, 0, 0, 0x1234, start, 0],
        ] {
            let expected = if args[0] == 0 || args[4] == 0 {
                STATUS_INVALID_PARAMETER
            } else if args[0] == 0xDEAD_BEEF || args[4] == 0xDEAD_BEEF || args[5] == 0xDEAD_BEEF {
                STATUS_INVALID_ADDRESS
            } else {
                STATUS_INVALID_HANDLE
            };
            assert_eq!(
                call_kernel_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::PsCreateSystemThread,
                    &args,
                ),
                expected
            );
        }
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, SystemThreadHandle(0xDEAD), 0)
                .unwrap_err(),
            crate::casak::status::STATUS_INVALID_HANDLE
        );
        assert_eq!(
            island
                .terminate_system_thread(SystemThreadHandle(0xDEAD), 0)
                .unwrap_err(),
            crate::casak::status::STATUS_INVALID_HANDLE
        );
        // A ready thread terminated before its slice never runs.
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start, 0],
            ),
            STATUS_SUCCESS
        );
        let ready = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        assert_eq!(island.terminate_system_thread(ready, 0x55), Ok(()));
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, ready, 0)
                .unwrap(),
            Some(0x55)
        );
        assert_eq!(island.pump_system_threads(&mut runtime, &mut memory), 0);
        assert_eq!(memory.read_u32(counter).unwrap(), 0);
        // A running thread with no ready peer reports a timeout instead of
        // spinning the host.
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start, 0],
            ),
            STATUS_SUCCESS
        );
        let running = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        let run_id = island
            .inner
            .borrow_mut()
            .system_threads
            .take_next()
            .expect("thread is ready");
        assert_eq!(
            run_id.id,
            island.inner.borrow().system_threads.current().unwrap()
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, running, 1)
                .unwrap(),
            None
        );
        island
            .inner
            .borrow_mut()
            .system_threads
            .finish_current(0)
            .unwrap();
        island
            .inner
            .borrow_mut()
            .system_threads
            .restore_running(run_id.id);
        island.inner.borrow_mut().finish_system_thread(run_id.id, 0);

        // A wait with a positive timeout pumps a peer slice, then loops
        // again when the target is still live.
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start, 0],
            ),
            STATUS_SUCCESS
        );
        let target = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start, 0],
            ),
            STATUS_SUCCESS
        );
        let peer = SystemThreadHandle(memory.read_u64(handle_out).unwrap());
        let target_id = island
            .inner
            .borrow()
            .system_threads
            .handle_for_target(target);
        {
            let mut state = island.inner.borrow_mut();
            state.system_threads.park_for_wait_test(target_id);
        }
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, target, 5_000)
                .unwrap(),
            None
        );
        let _ = peer;

        let saved_cursor = island.inner.borrow().arena.cursor;
        let arena_end = island.inner.borrow().arena.end;
        island.inner.borrow_mut().arena.cursor = arena_end;
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start, 0],
            ),
            STATUS_INSUFFICIENT_RESOURCES
        );
        island.inner.borrow_mut().arena.cursor = saved_cursor;
        {
            let mut state = island.inner.borrow_mut();
            let IslandState {
                process,
                system_threads,
                current_process,
                ..
            } = &mut *state;
            let _ = process.terminate_process(system_threads, *current_process);
        }
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsCreateSystemThread,
                &[handle_out, 0, 0, 0, start, 0],
            ),
            crate::casak::status::STATUS_PROCESS_IS_TERMINATING
        );
    });
}

fn spawn_system_thread(
    island: &DriverIsland,
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    start: u64,
    context: u64,
) -> SystemThreadHandle {
    let out = arena_u64(memory, island, 0);
    assert_eq!(
        call_kernel_shim(
            island,
            runtime,
            memory,
            DriverShim::PsCreateSystemThread,
            &[out, 0, 0, 0, start, context],
        ),
        STATUS_SUCCESS
    );
    let handle = SystemThreadHandle(memory.read_u64(out).unwrap());
    assert_ne!(handle.0, 0);
    handle
}

#[test]
fn system_thread_quantum_preemption_preserves_register_stack_and_exit_state() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let safepoint = allocate_shim(&mut runtime, DriverShim::IslandSafepoint);
        let counter = arena_u64(&mut memory, &island, 0);
        let sequence = arena_u64(&mut memory, &island, 0);
        let start = x64_yield_loop_stub(&mut memory, &island, safepoint, counter, 8, sequence);
        island.set_thread_quantum(Duration::from_nanos(1));
        let handle = spawn_system_thread(&island, &mut runtime, &mut memory, start, 0);
        let thread_id = island
            .inner
            .borrow()
            .system_threads
            .query(handle)
            .unwrap()
            .id;
        let slices = island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(slices >= 2, true);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap(),
            Some(8)
        );
        assert_eq!(memory.read_u64(counter).unwrap(), 8);
        assert_eq!(memory.read_u32(sequence).unwrap(), 3);
        assert_eq!(
            island.system_thread_exit_status_by_id(thread_id).unwrap(),
            Some(8)
        );
        assert!(island.inner.borrow().thread_cpus.is_empty());
    });
}

#[test]
fn termination_during_running_loop_observes_safepoint_and_blocks_double_terminate() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let safepoint = allocate_shim(&mut runtime, DriverShim::IslandSafepoint);
        let terminate = allocate_shim(&mut runtime, DriverShim::PsTerminateSystemThread);
        let counter = arena_u64(&mut memory, &island, 0);
        let start = x64_self_terminate_loop_stub(
            &mut memory,
            &island,
            safepoint,
            terminate,
            counter,
            0x99,
            3,
        );
        island.set_thread_quantum(Duration::from_nanos(1));
        let handle = spawn_system_thread(&island, &mut runtime, &mut memory, start, 0);
        let thread_id = island
            .inner
            .borrow()
            .system_threads
            .query(handle)
            .unwrap()
            .id;
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island.system_thread_exit_status_by_id(thread_id).unwrap(),
            Some(0x99)
        );
        assert_eq!(memory.read_u64(counter).unwrap(), 3);
        assert_eq!(
            island.terminate_system_thread(handle, 0),
            Err(crate::casak::status::STATUS_THREAD_IS_TERMINATING)
        );
        assert_eq!(
            island
                .inner
                .borrow_mut()
                .system_threads
                .close_handle(handle),
            Ok(())
        );
        assert_eq!(
            island
                .inner
                .borrow_mut()
                .system_threads
                .close_handle(handle),
            Err(crate::casak::status::STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            island.system_thread_exit_status_by_id(thread_id).unwrap(),
            Some(0x99)
        );
    });
}

#[test]
fn infinite_waits_block_until_event_signal_thread_exit_or_cancel() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let wait_shim = allocate_shim(&mut runtime, DriverShim::KeWaitForSingleObject);
        let set_shim = allocate_shim(&mut runtime, DriverShim::KeSetEvent);
        let event = arena_block(&mut memory, &island, 0x40);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[event, u64::from(SYNCHRONIZATION_EVENT), 0],
            ),
            STATUS_SUCCESS
        );
        let waiter = x64_wait_stub(&mut memory, &island, wait_shim, event, false, 0);
        let signaler = x64_signal_event_stub(&mut memory, &island, set_shim, event);
        let waiter_handle = spawn_system_thread(&island, &mut runtime, &mut memory, waiter, 0);
        let signaler_handle = spawn_system_thread(&island, &mut runtime, &mut memory, signaler, 0);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, waiter_handle, 0)
                .unwrap(),
            None
        );
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, waiter_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, signaler_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );

        // A notification event stays signaled after waking a waiter.
        let notification = arena_block(&mut memory, &island, 0x40);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeInitializeEvent,
            &[notification, u64::from(NOTIFICATION_EVENT), 0],
        );
        let notif_wait = x64_wait_stub(&mut memory, &island, wait_shim, notification, false, 0);
        let notif_signal = x64_signal_event_stub(&mut memory, &island, set_shim, notification);
        let notif_wait_handle =
            spawn_system_thread(&island, &mut runtime, &mut memory, notif_wait, 0);
        let notif_signal_handle =
            spawn_system_thread(&island, &mut runtime, &mut memory, notif_signal, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, notif_wait_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, notif_signal_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        assert!(
            island
                .inner
                .borrow()
                .kernel
                .events
                .get(&notification)
                .unwrap()
                .signaled
        );

        // Waiting on a thread handle wakes when the target exits.
        let child_counter = arena_u64(&mut memory, &island, 0);
        let child = x64_thread_stub(&mut memory, &island, child_counter, 7, false, None);
        let child_handle = spawn_system_thread(&island, &mut runtime, &mut memory, child, 0);
        let parent = x64_wait_stub(&mut memory, &island, wait_shim, child_handle.0, false, 0);
        let parent_handle = spawn_system_thread(&island, &mut runtime, &mut memory, parent, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, parent_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, child_handle, 0)
                .unwrap(),
            Some(7)
        );
    });
}

#[test]
fn wait_timeout_cancel_and_apc_alertable_boundaries_are_exact() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let wait_shim = allocate_shim(&mut runtime, DriverShim::KeWaitForSingleObject);
        let set_shim = allocate_shim(&mut runtime, DriverShim::KeSetEvent);
        let event = arena_block(&mut memory, &island, 0x40);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeInitializeEvent,
            &[event, u64::from(SYNCHRONIZATION_EVENT), 0],
        );
        let timeout = arena_u64(&mut memory, &island, (-10_000_i64) as u64);
        let timed = x64_wait_stub(&mut memory, &island, wait_shim, event, false, timeout);
        let timed_handle = spawn_system_thread(&island, &mut runtime, &mut memory, timed, 0);
        let started = Instant::now();
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, timed_handle, 0)
                .unwrap(),
            Some(STATUS_TIMEOUT)
        );
        assert!(started.elapsed() >= Duration::from_millis(1));

        let canceled = x64_wait_stub(&mut memory, &island, wait_shim, event, false, 0);
        let canceled_handle = spawn_system_thread(&island, &mut runtime, &mut memory, canceled, 0);
        assert!(island.pump_one_system_slice(&mut runtime, &mut memory));
        assert_eq!(
            island.system_thread_state(canceled_handle),
            Some(crate::casak::threads::KernelThreadState::Waiting)
        );
        assert_eq!(island.cancel_system_thread_wait(canceled_handle), Ok(()));
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, canceled_handle, 0)
                .unwrap(),
            Some(crate::casak::status::STATUS_CANCELLED)
        );
        assert_eq!(
            island.cancel_system_thread_wait(canceled_handle),
            Err(crate::casak::status::STATUS_INVALID_PARAMETER)
        );

        // Alertable wait: a queued APC wakes the wait with USER_APC and
        // runs the APC before the wait call resumes.
        let apc_event = arena_block(&mut memory, &island, 0x40);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeInitializeEvent,
            &[apc_event, u64::from(SYNCHRONIZATION_EVENT), 0],
        );
        let apc_counter = arena_u64(&mut memory, &island, 0);
        let apc_stub = x64_counter_stub(&mut memory, &island, apc_counter, 1);
        let alertable = x64_wait_stub(&mut memory, &island, wait_shim, apc_event, true, 0);
        let alertable_handle =
            spawn_system_thread(&island, &mut runtime, &mut memory, alertable, 0);
        island
            .queue_system_thread_apc(alertable_handle, apc_stub, 0)
            .unwrap();
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(memory.read_u32(apc_counter).unwrap(), 1);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, alertable_handle, 0)
                .unwrap(),
            Some(crate::casak::status::STATUS_USER_APC)
        );

        // Non-alertable wait keeps blocking through the APC and wakes on
        // the event signal without delivering the APC.
        let busy_event = arena_block(&mut memory, &island, 0x40);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeInitializeEvent,
            &[busy_event, u64::from(SYNCHRONIZATION_EVENT), 0],
        );
        let busy_counter = arena_u64(&mut memory, &island, 0);
        let busy_apc = x64_counter_stub(&mut memory, &island, busy_counter, 1);
        let non_alertable = x64_wait_stub(&mut memory, &island, wait_shim, busy_event, false, 0);
        let busy_handle = spawn_system_thread(&island, &mut runtime, &mut memory, non_alertable, 0);
        island
            .queue_system_thread_apc(busy_handle, busy_apc, 0)
            .unwrap();
        assert!(island.pump_one_system_slice(&mut runtime, &mut memory));
        assert_eq!(
            island.system_thread_state(busy_handle),
            Some(crate::casak::threads::KernelThreadState::Waiting)
        );
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeSetEvent,
            &[busy_event, 0, 0],
        );
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(memory.read_u32(busy_counter).unwrap(), 0);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, busy_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        let _ = set_shim;
    });
}

#[test]
fn interrupt_preempts_running_thread_then_thread_resumes_intact() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let safepoint = allocate_shim(&mut runtime, DriverShim::IslandSafepoint);
        let shim_irql = allocate_shim(&mut runtime, DriverShim::KeGetCurrentIrql);
        let shim_insert = allocate_shim(&mut runtime, DriverShim::KeInsertQueueDpc);
        let dpc = arena_u64(&mut memory, &island, 0);
        let dpc_irql = arena_u64(&mut memory, &island, 0);
        let sequence = arena_u64(&mut memory, &island, 0);
        let dpc_stub = x64_dpc_stub(&mut memory, &island, shim_irql, dpc_irql, sequence);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeDpc,
                &[dpc, dpc_stub, 0],
            ),
            STATUS_SUCCESS
        );
        let object_store = arena_u64(&mut memory, &island, 0);
        let context_out = arena_u64(&mut memory, &island, 0);
        let isr_irql = arena_u64(&mut memory, &island, 0);
        let service_context = arena_u64(&mut memory, &island, 0);
        let isr = x64_isr_stub(
            &mut memory,
            &island,
            shim_irql,
            shim_insert,
            None,
            object_store,
            context_out,
            isr_irql,
            sequence,
            dpc,
            0,
            0,
            1,
        );
        let out = arena_u64(&mut memory, &island, 0);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                out,
                isr,
                service_context,
                0,
                0x70,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_SUCCESS
        );
        let counter = arena_u64(&mut memory, &island, 0);
        let thread_seq = arena_u64(&mut memory, &island, 0);
        let start = x64_yield_loop_stub(&mut memory, &island, safepoint, counter, 5, thread_seq);
        island.set_thread_quantum(Duration::from_nanos(1));
        let handle = spawn_system_thread(&island, &mut runtime, &mut memory, start, 0);
        island.queue_virtual_interrupt(0x70);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap(),
            Some(5)
        );
        assert_eq!(memory.read_u64(counter).unwrap(), 5);
        assert_eq!(memory.read_u32(sequence).unwrap(), 2);
        assert_eq!(memory.read_u32(thread_seq).unwrap(), 3);
        assert_eq!(island.inner.borrow().interrupts.isr_invocations(), 1);
        assert_eq!(island.inner.borrow().interrupts.dispatch_count(), 1);
    });
}

#[test]
fn handle_close_and_exit_code_visibility_across_slices_is_exact() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let safepoint = allocate_shim(&mut runtime, DriverShim::IslandSafepoint);
        let counter = arena_u64(&mut memory, &island, 0);
        let sequence = arena_u64(&mut memory, &island, 0);
        let start = x64_yield_loop_stub(&mut memory, &island, safepoint, counter, 10, sequence);
        island.set_thread_quantum(Duration::from_nanos(1));
        let handle = spawn_system_thread(&island, &mut runtime, &mut memory, start, 0);
        let thread_id = island
            .inner
            .borrow()
            .system_threads
            .query(handle)
            .unwrap()
            .id;
        assert!(island.pump_one_system_slice(&mut runtime, &mut memory));
        assert_eq!(
            island.system_thread_state(handle),
            Some(crate::casak::threads::KernelThreadState::Ready)
        );
        assert_eq!(
            island
                .inner
                .borrow_mut()
                .system_threads
                .close_handle(handle),
            Ok(())
        );
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island.system_thread_exit_status_by_id(thread_id).unwrap(),
            Some(10)
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap_err(),
            crate::casak::status::STATUS_INVALID_HANDLE
        );
        assert_eq!(island.system_thread_state(handle), None);
        assert_eq!(
            island.system_thread_exit_status_by_id(ThreadId(404)),
            Err(crate::casak::status::STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            island
                .inner
                .borrow_mut()
                .system_threads
                .close_handle(handle),
            Err(crate::casak::status::STATUS_INVALID_HANDLE)
        );
        assert_eq!(memory.read_u64(counter).unwrap(), 10);
    });
}

#[test]
fn system_wait_self_and_invalid_targets_report_exact_statuses() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let wait_shim = allocate_shim(&mut runtime, DriverShim::KeWaitForSingleObject);
        let handle_slot = arena_u64(&mut memory, &island, 0);
        let self_wait =
            x64_wait_indirect_stub(&mut memory, &island, wait_shim, handle_slot, false, 0);
        let handle =
            spawn_system_thread(&island, &mut runtime, &mut memory, self_wait, handle_slot);
        memory.write_u64(handle_slot, handle.0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap(),
            Some(STATUS_INVALID_PARAMETER)
        );

        let invalid_wait = x64_wait_stub(&mut memory, &island, wait_shim, 0xDEAD, false, 0);
        let invalid = spawn_system_thread(&island, &mut runtime, &mut memory, invalid_wait, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, invalid, 0)
                .unwrap(),
            Some(STATUS_INVALID_HANDLE)
        );

        // Immediate success on an already-terminated thread handle.
        let child_counter = arena_u64(&mut memory, &island, 0);
        let child = x64_thread_stub(&mut memory, &island, child_counter, 3, false, None);
        let child_handle = spawn_system_thread(&island, &mut runtime, &mut memory, child, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        let immediate = x64_wait_stub(&mut memory, &island, wait_shim, child_handle.0, false, 0);
        let immediate_handle =
            spawn_system_thread(&island, &mut runtime, &mut memory, immediate, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, immediate_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );

        // Immediate success on an already-signaled event.
        let event = arena_block(&mut memory, &island, 0x40);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeInitializeEvent,
            &[event, u64::from(SYNCHRONIZATION_EVENT), 1],
        );
        let signaled = x64_wait_stub(&mut memory, &island, wait_shim, event, false, 0);
        let signaled_handle = spawn_system_thread(&island, &mut runtime, &mut memory, signaled, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, signaled_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        assert!(
            !island
                .inner
                .borrow()
                .kernel
                .events
                .get(&event)
                .unwrap()
                .signaled
        );
    });
}

#[test]
fn slice_budget_and_guest_fault_are_observable_and_resumable() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let safepoint = allocate_shim(&mut runtime, DriverShim::IslandSafepoint);
        let counter = arena_u64(&mut memory, &island, 0);
        let sequence = arena_u64(&mut memory, &island, 0);
        let start = x64_yield_loop_stub(&mut memory, &island, safepoint, counter, 100, sequence);
        island.set_thread_quantum(Duration::from_nanos(1));
        let handle = spawn_system_thread(&island, &mut runtime, &mut memory, start, 0);
        assert_eq!(
            island.pump_system_threads(&mut runtime, &mut memory),
            MAX_THREAD_SLICES
        );
        assert_eq!(
            island.system_thread_state(handle),
            Some(crate::casak::threads::KernelThreadState::Ready)
        );
        let mut completed = None;
        for _ in 0..16 {
            island.pump_system_threads(&mut runtime, &mut memory);
            completed = island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap();
            if completed.is_some() {
                break;
            }
        }
        assert_eq!(completed, Some(100), "the loop finishes after its quanta");
        assert_eq!(memory.read_u64(counter).unwrap(), 100);

        let fault = x64_stub(&mut memory, &island, &[0x0F, 0x0B]);
        let fault_handle = spawn_system_thread(&island, &mut runtime, &mut memory, fault, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, fault_handle, 0)
                .unwrap(),
            Some(STATUS_UNSUCCESSFUL)
        );
    });
}

#[test]
fn pure_guest_loops_are_quantum_preempted_and_termination_race_is_exact() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        // Tight `jmp $` loop: no imports, no IRET, no host callback.
        let loop_stub = x64_stub(&mut memory, &island, &[0xEB, 0xFE]);
        island.set_thread_quantum(Duration::from_nanos(1));
        let handle = spawn_system_thread(&mut island, &mut runtime, &mut memory, loop_stub, 0);
        assert_eq!(
            island.pump_system_threads(&mut runtime, &mut memory),
            MAX_THREAD_SLICES,
            "each quantum expires at a block boundary"
        );
        assert_eq!(
            island.system_thread_state(handle),
            Some(crate::casak::threads::KernelThreadState::Ready),
            "the pure loop is requeued, not run to completion"
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap(),
            None,
            "the loop has not exited"
        );
        island
            .terminate_system_thread(handle, 0x55)
            .expect("termination request");
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, handle, 0)
                .unwrap(),
            Some(0x55),
            "termination is observed at the next safepoint with its exit code"
        );
    });
}

#[test]
fn preemption_gate_respects_irql_and_missing_thread_records() {
    with_big_stack(|| {
        let (mut runtime, _memory, mut island) = kernel_test_island();
        let mut state = island.inner.borrow_mut();
        state.current_system_thread = Some(ThreadId(404));
        state.kernel.irql = DISPATCH_LEVEL;
        state.maybe_preempt(&mut runtime);
        assert!(!runtime.yield_pumped_guest_thread);
        state.kernel.irql = 0;
        state.maybe_preempt(&mut runtime);
        assert!(!runtime.yield_pumped_guest_thread);
        state.current_system_thread = None;
        state.maybe_preempt(&mut runtime);
        assert!(!runtime.yield_pumped_guest_thread);
        drop(state);
        assert_eq!(
            island.queue_system_thread_apc(SystemThreadHandle(0xDEAD), 1, 0),
            Err(crate::casak::status::STATUS_INVALID_HANDLE)
        );
    });
}

#[test]
fn thread_target_wait_blocks_until_target_exits_and_wakes_exactly() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let wait_shim = allocate_shim(&mut runtime, DriverShim::KeWaitForSingleObject);
        let set_shim = allocate_shim(&mut runtime, DriverShim::KeSetEvent);
        let gate = arena_block(&mut memory, &island, 0x40);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[gate, u64::from(SYNCHRONIZATION_EVENT), 0],
            ),
            STATUS_SUCCESS
        );
        let target = x64_wait_stub(&mut memory, &island, wait_shim, gate, false, 0);
        let target_handle = spawn_system_thread(&island, &mut runtime, &mut memory, target, 0);
        let waiter = x64_wait_stub(&mut memory, &island, wait_shim, target_handle.0, false, 0);
        let waiter_handle = spawn_system_thread(&island, &mut runtime, &mut memory, waiter, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island.system_thread_state(target_handle),
            Some(crate::casak::threads::KernelThreadState::Waiting)
        );
        assert_eq!(
            island.system_thread_state(waiter_handle),
            Some(crate::casak::threads::KernelThreadState::Waiting)
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeSetEvent,
                &[gate, 0, 0],
            ),
            STATUS_SUCCESS
        );
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, target_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, waiter_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        let _ = set_shim;
        let fast_counter = arena_u64(&mut memory, &island, 0);
        let fast = x64_thread_stub(&mut memory, &island, fast_counter, 7, false, None);
        let fast_handle = spawn_system_thread(&island, &mut runtime, &mut memory, fast, 0);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, fast_handle, 1000)
                .unwrap(),
            Some(7)
        );
    });
}

#[test]
fn event_auto_reset_and_absolute_wait_timeouts_are_exact() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let wait_shim = allocate_shim(&mut runtime, DriverShim::KeWaitForSingleObject);
        let signaled = arena_block(&mut memory, &island, 0x40);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[signaled, u64::from(SYNCHRONIZATION_EVENT), 1],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[signaled, 0, 0, 0],
            ),
            STATUS_SUCCESS
        );
        assert!(
            !island
                .inner
                .borrow()
                .kernel
                .events
                .get(&signaled)
                .unwrap()
                .signaled
        );

        let notification = arena_block(&mut memory, &island, 0x40);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeEvent,
                &[notification, u64::from(NOTIFICATION_EVENT), 1],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeWaitForSingleObject,
                &[notification, 0, 0, 0],
            ),
            STATUS_SUCCESS
        );
        let notif_wait = x64_wait_stub(&mut memory, &island, wait_shim, notification, false, 0);
        let notif_handle = spawn_system_thread(&island, &mut runtime, &mut memory, notif_wait, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, notif_handle, 0)
                .unwrap(),
            Some(STATUS_SUCCESS)
        );
        {
            let mut state = island.inner.borrow_mut();
            let gate = state.kernel.events.get(&notification).unwrap().gate.clone();
            state.consume_event(NOTIFICATION_EVENT, notification, gate);
        }
        assert_eq!(island.inner.borrow().notification_waits, 3);
        assert!(
            island
                .inner
                .borrow()
                .kernel
                .events
                .get(&notification)
                .unwrap()
                .signaled
        );

        let event = arena_block(&mut memory, &island, 0x40);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeInitializeEvent,
            &[event, u64::from(SYNCHRONIZATION_EVENT), 0],
        );
        let absolute_future = system_time_100ns() + 10_000;
        let future_timeout = arena_u64(&mut memory, &island, absolute_future);
        let absolute = x64_wait_stub(
            &mut memory,
            &island,
            wait_shim,
            event,
            false,
            future_timeout,
        );
        let absolute_handle = spawn_system_thread(&island, &mut runtime, &mut memory, absolute, 0);
        let started = Instant::now();
        island.pump_system_threads(&mut runtime, &mut memory);
        assert!(started.elapsed() >= Duration::from_millis(1));
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, absolute_handle, 0)
                .unwrap(),
            Some(STATUS_TIMEOUT)
        );

        let past_timeout = arena_u64(&mut memory, &island, 1);
        let expired = x64_wait_stub(&mut memory, &island, wait_shim, event, false, past_timeout);
        let expired_handle = spawn_system_thread(&island, &mut runtime, &mut memory, expired, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, expired_handle, 0)
                .unwrap(),
            Some(STATUS_TIMEOUT)
        );

        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeQuerySystemTime,
                &[0],
            ),
            STATUS_INVALID_PARAMETER
        );
        let invalid = x64_wait_stub(&mut memory, &island, wait_shim, 0xDEAD, false, 0);
        let invalid_handle = spawn_system_thread(&island, &mut runtime, &mut memory, invalid, 0);
        island.pump_system_threads(&mut runtime, &mut memory);
        assert_eq!(
            island
                .wait_system_thread(&mut runtime, &mut memory, invalid_handle, 0)
                .unwrap(),
            Some(STATUS_INVALID_HANDLE)
        );
    });
}

fn connect_interrupt(
    island: &DriverIsland,
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    handle_out: u64,
    service: u64,
    context: u64,
    spin: u64,
    vector: u32,
    irql: u8,
    sync_irql: u8,
    mode: u32,
    share: bool,
    affinity: u64,
) -> i32 {
    call_kernel_shim(
        island,
        runtime,
        memory,
        DriverShim::IoConnectInterrupt,
        &[
            handle_out,
            service,
            context,
            spin,
            u64::from(vector),
            u64::from(irql),
            u64::from(sync_irql),
            u64::from(mode),
            u64::from(share),
            affinity,
            0,
        ],
    )
}

fn write_connect_ex_params(
    memory: &mut MemoryImage,
    address: u64,
    version: u32,
    handle_out: u64,
    service: u64,
    context: u64,
    spin: u64,
    vector: u32,
    irql: u8,
    sync_irql: u8,
    mode: u8,
    share: u8,
    affinity: u64,
) {
    memory.map_bytes(address, &[0_u8; 64]);
    memory.write_u32(address, version);
    memory.write_u64(address + 8, handle_out);
    memory.write_u64(address + 16, service);
    memory.write_u64(address + 24, context);
    memory.write_u64(address + 32, spin);
    memory.write_u32(address + 40, vector);
    memory.write_u8(address + 44, irql);
    memory.write_u8(address + 45, sync_irql);
    memory.write_u8(address + 46, mode);
    memory.write_u8(address + 47, share);
    memory.write_u64(address + 48, affinity);
}

#[test]
fn virtual_interrupts_run_isr_then_dpc_with_exact_context_and_irql() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let shim_irql = allocate_shim(&mut runtime, DriverShim::KeGetCurrentIrql);
        let shim_insert = allocate_shim(&mut runtime, DriverShim::KeInsertQueueDpc);
        let dpc = arena_u64(&mut memory, &island, 0);
        let dpc_irql = arena_u64(&mut memory, &island, 0xEE);
        let sequence = arena_u64(&mut memory, &island, 0);
        let dpc_stub = x64_dpc_stub(&mut memory, &island, shim_irql, dpc_irql, sequence);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeInitializeDpc,
                &[dpc, dpc_stub, 0],
            ),
            STATUS_SUCCESS
        );
        let object_store = arena_u64(&mut memory, &island, 0);
        let context_out = arena_u64(&mut memory, &island, 0);
        let isr_irql = arena_u64(&mut memory, &island, 0xEE);
        let service_context = arena_u64(&mut memory, &island, 0);
        let isr = x64_isr_stub(
            &mut memory,
            &island,
            shim_irql,
            shim_insert,
            None,
            object_store,
            context_out,
            isr_irql,
            sequence,
            dpc,
            0x11,
            0x22,
            1,
        );
        let handle_out = arena_u64(&mut memory, &island, 0);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                isr,
                service_context,
                0,
                0x40,
                5,
                7,
                0,
                false,
                1,
            ),
            STATUS_SUCCESS
        );
        let interrupt = memory.read_u64(handle_out).unwrap();
        assert_ne!(interrupt, 0);
        {
            let state = island.inner.borrow();
            let record = state.interrupts.query(interrupt).unwrap();
            assert_eq!(record.vector, 0x40);
            assert_eq!(record.irql, 5);
            assert_eq!(record.synchronize_irql, 7);
        }
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x40)
                .unwrap(),
            1
        );
        assert_eq!(memory.read_u64(context_out).unwrap(), service_context);
        assert_eq!(memory.read_u8(isr_irql).unwrap(), 5);
        assert_eq!(memory.read_u32(sequence).unwrap(), 2);
        assert_eq!(memory.read_u8(dpc_irql).unwrap(), 2);
        assert_eq!(island.inner.borrow().interrupts.isr_invocations(), 1);
        assert_eq!(island.inner.borrow().interrupts.dispatch_count(), 1);
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x99)
                .unwrap(),
            STATUS_NOT_FOUND
        );
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x40)
                .unwrap(),
            1
        );
    });
}

#[test]
fn interrupt_connection_rejects_duplicate_vector_affinity_irql_and_polarity() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let service_counter = arena_u64(&mut memory, &island, 0);
        let service = x64_counter_stub(&mut memory, &island, service_counter, 0);
        let handle_out = 0x5F_200;
        memory.map_bytes(handle_out, &[0_u8; 0x100]);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                0,
                service,
                0,
                0,
                0x40,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                0,
                0,
                0,
                0x40,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                0xDEAD_BEEF,
                service,
                0,
                0,
                0x40,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_INVALID_ADDRESS
        );
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                0xDEAD_BEEF,
                0,
                0,
                0x40,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_INVALID_ADDRESS
        );
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                service,
                0xDEAD_BEEF,
                0,
                0x40,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_INVALID_ADDRESS
        );
        for (vector, irql, sync_irql, mode, share, affinity, expected) in [
            (0, 5, 5, 0, false, 1, STATUS_INVALID_PARAMETER),
            (256, 5, 5, 0, false, 1, STATUS_INVALID_PARAMETER),
            (0x41, 2, 5, 0, false, 1, STATUS_INVALID_PARAMETER),
            (0x41, 16, 16, 0, false, 1, STATUS_INVALID_PARAMETER),
            (0x41, 5, 4, 0, false, 1, STATUS_INVALID_PARAMETER),
            (0x41, 5, 16, 0, false, 1, STATUS_INVALID_PARAMETER),
            (0x41, 5, 5, 2, false, 1, STATUS_INVALID_PARAMETER),
            (0x41, 5, 5, 0, false, 0, STATUS_INVALID_PARAMETER),
            (0x41, 5, 5, 0, false, 0x1_0000, STATUS_INVALID_PARAMETER),
            (0x41, 5, 5, 0, true, 1, STATUS_INVALID_PARAMETER),
        ] {
            assert_eq!(
                connect_interrupt(
                    &island,
                    &mut runtime,
                    &mut memory,
                    handle_out,
                    service,
                    0,
                    0,
                    vector,
                    irql,
                    sync_irql,
                    mode,
                    share,
                    affinity,
                ),
                expected
            );
        }
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                service,
                0,
                0,
                0x42,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_SUCCESS
        );
        memory.map_bytes(0x5F_300, &[0_u8; 8]);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                0x5F_300,
                service,
                0,
                0,
                0x42,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_OBJECT_NAME_COLLISION
        );
        let spin = arena_u64(&mut memory, &island, 0);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                service,
                0,
                spin,
                0x43,
                5,
                5,
                0,
                true,
                1,
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                service,
                0,
                0xDEAD_BEEF,
                0x43,
                5,
                5,
                1,
                true,
                1,
            ),
            STATUS_INVALID_ADDRESS
        );
        let saved_cursor = island.inner.borrow().arena.cursor;
        let arena_end = island.inner.borrow().arena.end;
        island.inner.borrow_mut().arena.cursor = arena_end;
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                service,
                0,
                0,
                0x44,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_INSUFFICIENT_RESOURCES
        );
        island.inner.borrow_mut().arena.cursor = saved_cursor;
    });
}

#[test]
fn interrupt_disconnect_during_isr_and_shared_vectors_are_synchronized() {
    with_big_stack(|| {
        let (mut runtime, mut memory, mut island) = kernel_test_island();
        let shim_irql = allocate_shim(&mut runtime, DriverShim::KeGetCurrentIrql);
        let shim_insert = allocate_shim(&mut runtime, DriverShim::KeInsertQueueDpc);
        let shim_disconnect = allocate_shim(&mut runtime, DriverShim::IoDisconnectInterrupt);
        let dpc = arena_u64(&mut memory, &island, 0);
        let dpc_irql_a = arena_u64(&mut memory, &island, 0);
        let dpc_seq_a = arena_u64(&mut memory, &island, 0);
        let dpc_stub = x64_dpc_stub(&mut memory, &island, shim_irql, dpc_irql_a, dpc_seq_a);
        call_kernel_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::KeInitializeDpc,
            &[dpc, dpc_stub, 0],
        );
        let object_store = arena_u64(&mut memory, &island, 0);
        let context_out = arena_u64(&mut memory, &island, 0);
        let isr_irql = arena_u64(&mut memory, &island, 0);
        let sequence = arena_u64(&mut memory, &island, 0);
        let service_context = arena_u64(&mut memory, &island, 0);
        let isr = x64_isr_stub(
            &mut memory,
            &island,
            shim_irql,
            shim_insert,
            Some(shim_disconnect),
            object_store,
            context_out,
            isr_irql,
            sequence,
            dpc,
            0x11,
            0x22,
            1,
        );
        let handle_out = arena_u64(&mut memory, &island, 0);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                handle_out,
                isr,
                service_context,
                0,
                0x50,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_SUCCESS
        );
        let interrupt = memory.read_u64(handle_out).unwrap();
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x50)
                .unwrap(),
            1
        );
        assert!(!island.inner.borrow().interrupts.is_connected(interrupt));
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x50)
                .unwrap(),
            STATUS_NOT_FOUND
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoDisconnectInterrupt,
                &[interrupt],
            ),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoDisconnectInterrupt,
                &[0],
            ),
            STATUS_INVALID_HANDLE
        );

        // Two shared ISRs on one vector are chained in connection order.
        let spin = arena_u64(&mut memory, &island, 0);
        let false_object_store = arena_u64(&mut memory, &island, 0);
        let false_context_out = arena_u64(&mut memory, &island, 0);
        let false_irql_out = arena_u64(&mut memory, &island, 0);
        let false_sequence = arena_u64(&mut memory, &island, 0);
        let first_false = x64_isr_stub(
            &mut memory,
            &island,
            shim_irql,
            shim_insert,
            None,
            false_object_store,
            false_context_out,
            false_irql_out,
            false_sequence,
            dpc,
            0,
            0,
            0,
        );
        let true_counter = arena_u64(&mut memory, &island, 0);
        let second_true = x64_thread_stub(&mut memory, &island, true_counter, 1, false, None);
        let out_a = arena_u64(&mut memory, &island, 0);
        let out_b = arena_u64(&mut memory, &island, 0);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                out_a,
                first_false,
                0,
                spin,
                0x51,
                5,
                5,
                1,
                true,
                1,
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                out_b,
                second_true,
                0,
                spin,
                0x51,
                5,
                5,
                1,
                true,
                1,
            ),
            STATUS_SUCCESS
        );
        let before = island.inner.borrow().interrupts.isr_invocations();
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x51)
                .unwrap(),
            1
        );
        assert_eq!(
            island.inner.borrow().interrupts.isr_invocations(),
            before + 2
        );
        let lone_false_out = arena_u64(&mut memory, &island, 0);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                lone_false_out,
                first_false,
                0,
                0,
                0x53,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x53)
                .unwrap(),
            0
        );
        // A stale vector entry is skipped without aborting the chain.
        let stale_out = arena_u64(&mut memory, &island, 0);
        let stale_counter = arena_u64(&mut memory, &island, 0);
        let stale_isr = x64_thread_stub(&mut memory, &island, stale_counter, 1, false, None);
        assert_eq!(
            connect_interrupt(
                &island,
                &mut runtime,
                &mut memory,
                stale_out,
                stale_isr,
                0,
                0,
                0x52,
                5,
                5,
                0,
                false,
                1,
            ),
            STATUS_SUCCESS
        );
        island
            .inner
            .borrow_mut()
            .interrupts
            .inject_stale_vector(0x52, 0x999);
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, 0x52)
                .unwrap(),
            1
        );
    });
}

#[test]
fn io_connect_interrupt_ex_versions_and_malformed_blocks_are_exact() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let service_counter = arena_u64(&mut memory, &island, 0);
        let service = x64_counter_stub(&mut memory, &island, service_counter, 0);
        let handle_out = arena_u64(&mut memory, &island, 0);
        let params = arena_block(&mut memory, &island, 64);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[0],
            ),
            STATUS_INVALID_PARAMETER
        );
        write_connect_ex_params(
            &mut memory,
            params,
            1,
            handle_out,
            service,
            0,
            0,
            0x60,
            5,
            5,
            0,
            0,
            1,
        );
        assert_eq!(memory.read_u32(params).unwrap(), 1);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[params],
            ),
            STATUS_NOT_SUPPORTED
        );
        write_connect_ex_params(
            &mut memory,
            params,
            99,
            handle_out,
            service,
            0,
            0,
            0x60,
            5,
            5,
            0,
            0,
            1,
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[params],
            ),
            STATUS_INVALID_PARAMETER
        );
        write_connect_ex_params(
            &mut memory,
            params,
            CONNECT_LINE_BASED,
            handle_out,
            service,
            0,
            0,
            0x60,
            5,
            5,
            0,
            0,
            1,
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[params],
            ),
            STATUS_SUCCESS
        );
        let line = memory.read_u64(handle_out).unwrap();
        assert_ne!(line, 0);
        write_connect_ex_params(
            &mut memory,
            params,
            CONNECT_FULLY_SPECIFIED,
            handle_out,
            service,
            0,
            0,
            0x61,
            5,
            5,
            0,
            0,
            1,
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[params],
            ),
            STATUS_SUCCESS
        );
        assert_ne!(memory.read_u64(handle_out).unwrap(), 0);
        write_connect_ex_params(
            &mut memory,
            params,
            CONNECT_LINE_BASED,
            handle_out,
            service,
            0,
            0,
            0,
            5,
            5,
            0,
            0,
            1,
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[params],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[0xDEAD_B000],
            ),
            STATUS_INVALID_PARAMETER
        );
        let zeroed = arena_block(&mut memory, &island, 64);
        memory.write_u32(zeroed, CONNECT_LINE_BASED);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[zeroed],
            ),
            STATUS_INVALID_PARAMETER
        );
        let truncated = 0x7000_0FF0;
        memory.map_bytes(truncated, &[0_u8; 8]);
        memory.write_u32(truncated, CONNECT_LINE_BASED);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterruptEx,
                &[truncated],
            ),
            STATUS_INVALID_PARAMETER
        );
    });
}

#[test]
fn island_process_identity_and_interrupt_time_reject_invalid_state() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let process = island.inner.borrow().current_process;
        let thread = island.inner.borrow().current_thread;
        {
            let state = island.inner.borrow();
            assert_eq!(state.process.process_count(), 1);
            assert_eq!(state.process.thread_count(), 1);
            assert_eq!(
                state.process.query_process(process).unwrap().image_name,
                "CasaDriver"
            );
            assert_eq!(state.process.query_thread(thread).unwrap().process, process);
        }
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsGetCurrentProcessId,
                &[],
            ) as u32,
            process.0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::PsGetCurrentThreadId,
                &[],
            ) as u32,
            thread.0
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeQueryInterruptTime,
                &[],
            ),
            1
        );
        island.inner.borrow_mut().executive.advance(5);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::KeQueryInterruptTime,
                &[],
            ),
            6
        );
        assert_eq!(
            island.inner.borrow().process.query_process(ProcessId(0)),
            Err(crate::casak::status::STATUS_INVALID_HANDLE)
        );
    });
}

#[test]
fn island_etw_registration_write_and_unregister_are_real() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        let guid_pointer = 0x5B_000;
        let handle_pointer = 0x5B_100;
        let descriptor_pointer = 0x5B_200;
        let data_pointer = 0x5B_300;
        memory.map_bytes(guid_pointer, &[0xAB; 16]);
        memory.map_bytes(handle_pointer, &[0_u8; 8]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwRegister,
                &[guid_pointer, 0, 0, handle_pointer],
            ),
            STATUS_SUCCESS
        );
        let handle = memory.read_u64(handle_pointer).unwrap();
        assert_ne!(handle, 0);
        assert_eq!(island.inner.borrow().diagnostics.provider_count(), 1);
        let provider = ProviderGuid([0xAB; 16]);
        island
            .inner
            .borrow_mut()
            .diagnostics
            .enable_provider(provider, EventLevel::Error, 0x1)
            .unwrap();
        memory.map_bytes(descriptor_pointer, &[0_u8; 16]);
        memory.write_u8(descriptor_pointer + 4, 2);
        memory.write_u64(descriptor_pointer + 8, 1);
        memory.map_bytes(data_pointer, &[1, 2, 3]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwWrite,
                &[handle, descriptor_pointer, data_pointer, 3],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(island.inner.borrow().diagnostics.events_written(), 1);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwRegister,
                &[guid_pointer, 0, 0, handle_pointer],
            ),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwRegister,
                &[0xDEAD_BEEF, 0, 0, handle_pointer],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwWrite,
                &[handle, 0, data_pointer, 3],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwWrite,
                &[handle, 0xDEAD_BEEF, data_pointer, 3],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwWrite,
                &[handle, descriptor_pointer, 0xDEAD_BEEF, 3],
            ),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u8(descriptor_pointer + 4, 0);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwWrite,
                &[handle, descriptor_pointer, data_pointer, 3],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwWrite,
                &[handle, descriptor_pointer, data_pointer, 64 * 1024 + 1],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwUnregister,
                &[handle],
            ),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwUnregister,
                &[handle],
            ),
            STATUS_INVALID_HANDLE
        );
        memory.write_u8(descriptor_pointer + 4, 2);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::EtwWrite,
                &[handle, descriptor_pointer, data_pointer, 3],
            ),
            STATUS_INVALID_HANDLE
        );
    });
}

#[test]
fn island_alpc_connect_uses_the_in_process_port_namespace() {
    with_big_stack(|| {
        let (mut runtime, mut memory, island) = kernel_test_island();
        island
            .inner
            .borrow_mut()
            .alpc
            .create_port("\\CasaPort", 4, 64)
            .unwrap();
        let handle_pointer = 0x5C_000;
        memory.map_bytes(handle_pointer, &[0_u8; 8]);
        let port_name = {
            let mut state = island.inner.borrow_mut();
            allocate_unicode_string(&mut state, &mut memory, "\\CasaPort").unwrap()
        };
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::NtAlpcConnectPort,
                &[handle_pointer, port_name, 0, 0, 0, 0, 0],
            ),
            STATUS_SUCCESS
        );
        let handle = memory.read_u64(handle_pointer).unwrap();
        assert_ne!(handle, 0);
        assert_eq!(island.inner.borrow().alpc_handles.len(), 1);
        let missing = {
            let mut state = island.inner.borrow_mut();
            allocate_unicode_string(&mut state, &mut memory, "\\Missing").unwrap()
        };
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::NtAlpcConnectPort,
                &[handle_pointer, missing, 0, 0, 0, 0, 0],
            ),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::NtAlpcConnectPort,
                &[0, port_name, 0, 0, 0, 0, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::NtAlpcConnectPort,
                &[handle_pointer, 0, 0, 0, 0, 0, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
        let malformed = 0x5C_100;
        memory.map_bytes(malformed, &[3_u8, 0, 4, 0, 0, 0, 0, 0]);
        assert_eq!(
            call_kernel_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::NtAlpcConnectPort,
                &[handle_pointer, malformed, 0, 0, 0, 0, 0],
            ),
            STATUS_INVALID_PARAMETER
        );
    });
}

#[test]
fn kmdf_spinlock_timer_workitem_lifecycles_reject_invalid_states() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfLifeEdge");
        let out = 0x41_000;
        memory.map_bytes(out, &[0_u8; 8]);

        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockCreate,
                &[0, out],
            )
            .expect("spin lock create"),
            STATUS_SUCCESS
        );
        let lock = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockAcquire,
                &[lock],
            )
            .expect("acquire"),
            STATUS_SUCCESS
        );
        assert_eq!(island.kmdf_spinlock_held(lock), Some(true));
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockAcquire,
                &[lock],
            )
            .expect("double acquire"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockRelease,
                &[lock],
            )
            .expect("release"),
            STATUS_SUCCESS
        );
        assert_eq!(island.kmdf_spinlock_held(lock), Some(false));
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockRelease,
                &[lock],
            )
            .expect("double release"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockAcquire,
                &[0xDEAD_0000],
            )
            .expect("stale lock"),
            STATUS_INVALID_HANDLE
        );

        let timer_counter = arena_counter(&mut memory, &island);
        let timer_stub = x64_marker_stub(&mut memory, &island, timer_counter);
        let config = 0x42_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        memory.write_u32(config, 0x18);
        memory.write_u64(config + 0x08, timer_stub);
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerCreate,
                &[config, 0, out],
            )
            .expect("timer create"),
            STATUS_SUCCESS
        );
        let timer = memory.read_u64(out).unwrap();
        let due = 0x43_000;
        memory.map_bytes(due, &[0_u8; 8]);
        memory.write_u64(due, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerStart,
                &[timer, due],
            )
            .expect("immediate timer"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(timer_counter).unwrap(), 1);
        assert_eq!(island.kmdf_timer_state(timer), Some((false, 1)));
        memory.write_u64(due, 100);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerStart,
                &[timer, due],
            )
            .expect("deferred timer"),
            STATUS_SUCCESS
        );
        assert_eq!(island.kmdf_timer_state(timer), Some((true, 1)));
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerStart,
                &[timer, due],
            )
            .expect("double start"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerStop,
                &[timer, 1],
            )
            .expect("stop running timer"),
            1
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerStop,
                &[timer, 1],
            )
            .expect("stop stopped timer"),
            0
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockAcquire,
                &[timer],
            )
            .expect("timer is not a spin lock"),
            STATUS_OBJECT_TYPE_MISMATCH
        );

        let item_counter = arena_counter(&mut memory, &island);
        let item_stub = x64_marker_stub(&mut memory, &island, item_counter);
        let item_config = 0x44_000;
        memory.map_bytes(item_config, &[0_u8; 0x20]);
        memory.write_u32(item_config, 0x18);
        memory.write_u64(item_config + 0x08, item_stub);
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemCreate,
                &[item_config, 0, out],
            )
            .expect("work item create"),
            STATUS_SUCCESS
        );
        let item = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemEnqueue,
                &[item],
            )
            .expect("work item enqueue"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(item_counter).unwrap(), 1);
        assert_eq!(island.kmdf_work_item_state(item), Some((false, 1)));
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemFlush,
                &[item],
            )
            .expect("work item flush"),
            STATUS_SUCCESS
        );
        island
            .inner
            .borrow_mut()
            .kmdf
            .work_items
            .get_mut(&item)
            .expect("work item")
            .queued = true;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemEnqueue,
                &[item],
            )
            .expect("double enqueue"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemEnqueue,
                &[0xDEAD_0000],
            )
            .expect("stale work item"),
            STATUS_INVALID_HANDLE
        );

        memory.write_u32(config, 8);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerCreate,
                &[config, 0, out],
            )
            .expect("short timer config"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u32(config, 0x18);
        memory.write_u64(config + 0x08, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerCreate,
                &[config, 0, out],
            )
            .expect("timer without callback"),
            STATUS_INVALID_PARAMETER
        );

        let driver = island.kmdf_driver_handle();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[driver],
            )
            .expect("delete driver"),
            STATUS_SUCCESS
        );
        let state = island.inner.borrow();
        assert!(state.kmdf.devices.is_empty());
        assert!(state.kmdf.spinlocks.is_empty());
        assert!(state.kmdf.timers.is_empty());
        assert!(state.kmdf.work_items.is_empty());
    });
}

#[test]
fn kmdf_request_format_cancel_and_status_reject_stale_transitions() {
    with_big_stack(|| {
        let image = build_kmdf_driver(true, false, false);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfRequestEdge");
        let device = island.kmdf_device_handles()[0];
        let out = 0x41_000;
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, out],
            )
            .expect("request create"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(out).unwrap();
        let descriptor = 0x42_000;
        let buffer = 0x43_000;
        memory.map_bytes(buffer, &[0_u8; 0x20]);
        write_descriptor(&mut memory, descriptor, buffer, 0x10);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForRead,
                &[request, device, descriptor, 4, 0],
            )
            .expect("format read"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let record = state.kmdf.requests.get(&request).expect("request");
            assert_eq!(record.major, IrpMajorFunction::Read);
            assert_eq!(record.input_len, 0);
            assert_eq!(record.output_len, 0x0C);
            assert_eq!(record.output_guest, buffer + 4);
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestMarkCancelable,
                &[request, 0x1000],
            )
            .expect("mark cancelable"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestMarkCancelable,
                &[request, 0x1000],
            )
            .expect("double mark"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestUnmarkCancelable,
                &[request],
            )
            .expect("unmark"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestUnmarkCancelable,
                &[request],
            )
            .expect("double unmark"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestGetStatus,
                &[request],
            )
            .expect("pending status"),
            STATUS_PENDING
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestIsCanceled,
                &[request],
            )
            .expect("not canceled"),
            0
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForRead,
                &[request, device, descriptor, 0x20, 0],
            )
            .expect("offset past descriptor"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForWrite,
                &[request, 0xDEAD_0000, descriptor, 0, 0],
            )
            .expect("unknown target"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[request, 0],
            )
            .expect("complete"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestGetStatus,
                &[request],
            )
            .expect("completed status"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForRead,
                &[request, device, descriptor, 0, 0],
            )
            .expect("format completed request"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestMarkCancelable,
                &[0xDEAD_0000, 0x1000],
            )
            .expect("stale request"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestGetStatus,
                &[device],
            )
            .expect("device is not a request"),
            STATUS_OBJECT_TYPE_MISMATCH
        );
    });
}

#[test]
fn kmdf_power_managed_queue_defers_until_device_exits_idle() {
    with_big_stack(|| {
        let (mut runtime, _directory, mut memory, island, _base, device_object) =
            pnp_load("CasaWdfPowerQueue");
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_START_DEVICE,
                )
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        let device = island.inner.borrow().kmdf.devices_by_object[&device_object];
        let callback_counter = arena_counter(&mut memory, &island);
        let callback_stub = x64_marker_stub(&mut memory, &island, callback_counter);
        let config = 0x41_000;
        let queue_out = 0x42_000;
        memory.map_bytes(config, &[0_u8; 0x40]);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(config, 0x20);
        memory.write_u32(config + 0x04, 0);
        memory.write_u32(config + 0x08, 1);
        memory.write_u8(config + 0x0D, 1);
        memory.write_u64(config + 0x10, callback_stub);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("power-managed queue"),
            STATUS_SUCCESS
        );
        let queue = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            island.kmdf_queue_state(queue),
            Some((0, 0, false, false, true))
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[device, 1],
            )
            .expect("stop idle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceResumeIdle,
                &[device],
            )
            .expect("resume idle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceResumeIdle,
                &[device],
            )
            .expect("unbalanced resume"),
            STATUS_INVALID_DEVICE_STATE
        );
        let request_out = 0x43_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request create"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, request],
            )
            .expect("enqueue while idle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_queue_state(queue),
            Some((1, 0, false, false, true))
        );
        assert_eq!(island.kmdf_counters().2, 1);
        assert_eq!(memory.read_u32(callback_counter).unwrap(), 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[device, 1],
            )
            .expect("return to D0"),
            STATUS_PENDING
        );
        assert_eq!(
            island.kmdf_queue_state(queue),
            Some((0, 1, false, false, true))
        );
        assert_eq!(memory.read_u32(callback_counter).unwrap(), 1);
        let (_, _, _, _, power_state, idle_refs) = island
            .kmdf_device_runtime_state(device)
            .expect("device state");
        assert_eq!(power_state, WDF_POWER_DEVICE_D0);
        assert_eq!(idle_refs, 1);
    });
}

#[test]
fn kmdf_request_forward_to_io_queue_rejects_cross_device_and_completed() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, true);
        let (mut runtime, _directory, mut memory, island) =
            load_staged_island_x64(&image, "CasaWdfForward");
        let devices = island.kmdf_device_handles();
        assert_eq!(devices.len(), 2);
        let (first, second) = (devices[0], devices[1]);
        let config = 0x41_000;
        let queue_out = 0x42_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        memory.write_u32(config, 0x18);
        memory.write_u32(config + 0x04, 2);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[second, config, 0, queue_out],
            )
            .expect("cross-device queue"),
            STATUS_SUCCESS
        );
        let cross_queue = memory.read_u64(queue_out).unwrap();
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(config + 0x04, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[first, config, 0, queue_out],
            )
            .expect("same-device queue"),
            STATUS_SUCCESS
        );
        let local_queue = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStopSynchronously,
                &[local_queue],
            )
            .expect("stop local queue"),
            STATUS_SUCCESS
        );
        let request_out = 0x43_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, first, request_out],
            )
            .expect("request create"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request, cross_queue],
            )
            .expect("cross-device forward"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request, local_queue],
            )
            .expect("forward to stopped queue"),
            STATUS_SUCCESS
        );
        assert_eq!(island.kmdf_queue_state(local_queue).unwrap().0, 1);
        assert_eq!(island.kmdf_counters().4, 1);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request, local_queue],
            )
            .expect("forward to same queue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request, 0xDEAD_0000],
            )
            .expect("forward to stale queue"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueStart,
                &[local_queue],
            )
            .expect("start queue drains forwarded request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_queue_state(local_queue),
            Some((0, 0, false, false, false))
        );
        let (completed, status, _, _) =
            island.kmdf_request_state(request).expect("forwarded state");
        assert_eq!(completed, true);
        assert_eq!(status, STATUS_INVALID_DEVICE_REQUEST);
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, first, request_out],
            )
            .expect("completed request create"),
            STATUS_SUCCESS
        );
        let completed = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[completed, 0],
            )
            .expect("complete"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[completed, local_queue],
            )
            .expect("forward completed request"),
            STATUS_INVALID_DEVICE_STATE
        );
    });
}

#[test]
fn kmdf_surprise_removal_cancels_inflight_irp_and_rejects_repeat() {
    with_big_stack(|| {
        let (mut runtime, _directory, mut memory, island, _base, device_object) =
            pnp_load("CasaWdfSurprise");
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_START_DEVICE,
                )
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        let device = island.inner.borrow().kmdf.devices_by_object[&device_object];
        let callback_counter = arena_counter(&mut memory, &island);
        let callback_stub = x64_marker_stub(&mut memory, &island, callback_counter);
        let config = 0x41_000;
        let queue_out = 0x42_000;
        memory.map_bytes(config, &[0_u8; 0x40]);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(config, 0x20);
        memory.write_u32(config + 0x04, 0);
        memory.write_u8(config + 0x0D, 1);
        memory.write_u64(config + 0x10, callback_stub);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("queue create"),
            STATUS_SUCCESS
        );
        let queue = memory.read_u64(queue_out).unwrap();
        let request_out = 0x43_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request create"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, request],
            )
            .expect("enqueue in flight"),
            STATUS_PENDING
        );
        assert_eq!(
            island.kmdf_queue_state(queue),
            Some((0, 1, false, false, false))
        );
        let surprise_counter = arena_counter(&mut memory, &island);
        let surprise_stub = x64_marker_stub(&mut memory, &island, surprise_counter);
        island
            .inner
            .borrow_mut()
            .kmdf
            .devices
            .get_mut(&device)
            .expect("device")
            .pnp_power
            .surprise_removal = surprise_stub;
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_SURPRISE_REMOVAL,
                )
                .expect("surprise removal")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(surprise_counter).unwrap(), 1);
        assert_eq!(
            island.kmdf_device_runtime_state(device),
            Some((false, false, true, true, WDF_POWER_DEVICE_D3, 0))
        );
        assert_eq!(
            island.kmdf_queue_state(queue),
            Some((0, 0, true, false, false))
        );
        let (completed, status, _, _) = island.kmdf_request_state(request).expect("request state");
        assert_eq!(completed, true);
        assert_eq!(status, STATUS_CANCELLED);
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_SURPRISE_REMOVAL,
                )
                .expect("double surprise removal")
                .0,
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_REMOVE_DEVICE,
                )
                .expect("remove after surprise")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(island.kmdf_device_runtime_state(device), None);
        assert!(
            island
                .inner
                .borrow()
                .removed_device_objects
                .contains(&device_object)
        );
    });
}

#[test]
fn kmdf_power_transition_failure_rolls_back_to_previous_state() {
    with_big_stack(|| {
        let (mut runtime, _directory, mut memory, island, base, device) =
            pnp_load("CasaWdfPowerFail");
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device, IRP_MN_START_DEVICE)
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        let handle = island.inner.borrow().kmdf.devices_by_object[&device];
        pnp_set_failure(&mut memory, base, 8, STATUS_UNSUCCESSFUL);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("failing D3")
                .0,
            STATUS_UNSUCCESSFUL
        );
        assert_eq!(
            island.kmdf_device_runtime_state(handle).expect("state").4,
            WDF_POWER_DEVICE_D0
        );
        assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 1);
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 2);

        pnp_set_failure(&mut memory, base, 0, 0);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D3)
                .expect("D3")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_device_runtime_state(handle).expect("state").4,
            WDF_POWER_DEVICE_D3
        );
        pnp_set_failure(&mut memory, base, 2, STATUS_UNSUCCESSFUL);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("failing D0")
                .0,
            STATUS_UNSUCCESSFUL
        );
        assert_eq!(
            island.kmdf_device_runtime_state(handle).expect("state").4,
            WDF_POWER_DEVICE_D3
        );
        assert_eq!(pnp_u32(&memory, base, P_D0ENTRY_COUNT), 3);
        assert_eq!(pnp_u32(&memory, base, P_D0EXIT_COUNT), 3);

        pnp_set_failure(&mut memory, base, 0, 0);
        assert_eq!(
            island
                .set_device_power(&mut runtime, &mut memory, device, WDF_POWER_DEVICE_D0)
                .expect("D0")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_device_runtime_state(handle).expect("state").4,
            WDF_POWER_DEVICE_D0
        );
    });
}

/// Collection semantics: duplicate add collides, missing remove fails,
/// out-of-range get returns NULL, and wrong-type/invalid handles are
/// rejected with the exact NTSTATUS.
#[test]
fn kmdf_collection_duplicate_add_and_stale_remove_reject_exact_status() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfC");
        let collection_out = 0x51_000;
        memory.map_bytes(collection_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, collection_out],
            )
            .expect("create collection"),
            STATUS_SUCCESS
        );
        let collection = memory.read_u64(collection_out).unwrap();
        assert_ne!(collection, 0);
        // Wrong-type handle: a driver handle is not a collection.
        let driver = island.kmdf_driver_handle();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[driver, 0x1000],
            )
            .expect("add on driver"),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        // Invalid handle: no such object.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[0xDEAD_BEEF, 0x1000],
            )
            .expect("add on missing"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[collection, 0x1111],
            )
            .expect("first add"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[collection, 0x1111],
            )
            .expect("duplicate add"),
            STATUS_OBJECT_NAME_COLLISION
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[collection, 0x2222],
            )
            .expect("second add"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionGetCount,
                &[collection],
            )
            .expect("count"),
            2
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionContains2,
                &[collection, 0x1111],
            )
            .expect("contains"),
            1
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionContains2,
                &[collection, 0x3333],
            )
            .expect("not contains"),
            0
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionGetItem,
                &[collection, 1],
            )
            .expect("item 1"),
            0x2222
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionGetItem,
                &[collection, 9],
            )
            .expect("item oob"),
            0
        );
        // Removing a member that is not in the collection is
        // STATUS_NOT_FOUND, matching the KMDF framework contract.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionRemove,
                &[collection, 0x4444],
            )
            .expect("stale remove"),
            STATUS_NOT_FOUND
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionRemove,
                &[collection, 0x1111],
            )
            .expect("remove member"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionGetCount,
                &[collection],
            )
            .expect("count after remove"),
            1
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionRemoveAll,
                &[collection],
            )
            .expect("remove all"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionGetCount,
                &[collection],
            )
            .expect("count after remove all"),
            0
        );
        // Null output pointer fails creation.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, 0],
            )
            .expect("null collection out"),
            STATUS_INVALID_PARAMETER
        );
        // Filling a collection past its maximum rejects the overflow.
        let full_out = 0x51_010;
        memory.map_bytes(full_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, full_out],
            )
            .expect("full collection create"),
            STATUS_SUCCESS
        );
        let full = memory.read_u64(full_out).unwrap();
        for index in 1..=1024u64 {
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfCollectionAdd,
                    &[full, index],
                )
                .unwrap_or_else(|error| panic!("add {index}: {error}")),
                STATUS_SUCCESS
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[full, 0x9999],
            )
            .expect("add past max"),
            STATUS_INSUFFICIENT_RESOURCES
        );
    });
}

/// Lookaside semantics: allocations reuse freed blocks by pointer,
/// oversize/pool-type errors are rejected, and lookaside memory cannot
/// be rebound by `WdfMemoryAssign`.
#[test]
fn kmdf_lookaside_reuse_after_free_and_oversize_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfL");
        let lookaside_out = 0x52_000;
        memory.map_bytes(lookaside_out, &[0_u8; 8]);
        // Zero size, oversize, and invalid pool type are rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfLookasideListCreate,
                &[0, 0, 0, 0, lookaside_out],
            )
            .expect("zero size"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfLookasideListCreate,
                &[0, 0, 0x2_0000, 0, lookaside_out],
            )
            .expect("oversize"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfLookasideListCreate,
                &[0, 2, 0x40, 0, lookaside_out],
            )
            .expect("bad pool type"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfLookasideListCreate,
                &[0, 0, 0x40, 0, lookaside_out],
            )
            .expect("create lookaside"),
            STATUS_SUCCESS
        );
        let lookaside = memory.read_u64(lookaside_out).unwrap();
        let memory_out = 0x52_010;
        memory.map_bytes(memory_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreateFromLookaside,
                &[lookaside, memory_out],
            )
            .expect("first allocation"),
            STATUS_SUCCESS
        );
        let first = memory.read_u64(memory_out).unwrap();
        let first_buffer = {
            let state = island.inner.borrow();
            state.kmdf.memories.get(&first).expect("memory").buffer
        };
        assert_ne!(first_buffer, 0);
        // Deleting the memory returns the block to the free list.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[first],
            )
            .expect("delete memory"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let lookaside_state = state
                .kmdf
                .lookasides
                .get(&lookaside)
                .expect("lookaside alive");
            assert_eq!(lookaside_state.free.len(), 1, "block returned");
            assert_eq!(lookaside_state.in_use, 0, "no blocks in use");
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[first],
            )
            .expect("double delete"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreateFromLookaside,
                &[lookaside, memory_out],
            )
            .expect("second allocation"),
            STATUS_SUCCESS
        );
        let second = memory.read_u64(memory_out).unwrap();
        let second_buffer = {
            let state = island.inner.borrow();
            state.kmdf.memories.get(&second).expect("memory").buffer
        };
        assert_eq!(
            first_buffer, second_buffer,
            "freed lookaside block must be reused by pointer"
        );
        {
            let state = island.inner.borrow();
            let lookaside_state = state.kmdf.lookasides.get(&lookaside).expect("lookaside");
            assert_eq!(lookaside_state.hits, 1, "second allocation is a hit");
            assert_eq!(lookaside_state.misses, 1, "first allocation is a miss");
        }
        // Lookaside memory cannot be reassigned.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryAssign,
                &[second, 0x53_000, 0x40],
            )
            .expect("assign lookaside memory"),
            STATUS_INVALID_DEVICE_STATE
        );
        // Deleting the lookaside drops its block bookkeeping.

        // Reference the surviving block first: the lookaside's child
        // cascade then defers it, so the block's record outlives the
        // lookaside itself...
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectReference,
                &[second],
            )
            .expect("reference second"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[lookaside],
            )
            .expect("delete lookaside with referenced block"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(!state.kmdf.lookasides.contains_key(&lookaside));
            assert!(
                state.kmdf.lookaside_blocks.contains_key(&second),
                "the referenced block's record outlives its lookaside"
            );
        }
        // ...and releasing the reference finalizes the block against a
        // lookaside that no longer exists.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDereference,
                &[second],
            )
            .expect("release second reference"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(!state.kmdf.lookaside_blocks.contains_key(&second));
            assert!(!state.kmdf.objects.contains_key(&second));
        }
    });
}

/// Memory copy/assign: overlap and overflow are rejected with the exact
/// status; assign rejects invalid buffers and non-preallocated memory.
#[test]
fn kmdf_memory_copy_overlap_and_assign_overflow_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfM");
        let buffer_a = 0x54_000;
        let buffer_b = 0x54_100;
        memory.map_bytes(buffer_a, &vec![0xAA_u8; 0x80]);
        memory.map_bytes(buffer_b, &vec![0_u8; 0x80]);
        let out = 0x55_000;
        memory.map_bytes(out, &[0_u8; 8]);
        // Preallocated memory over buffer A.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreatePreallocated,
                &[0, buffer_a, 0x80, out],
            )
            .expect("prealloc A"),
            STATUS_SUCCESS
        );
        let memory_a = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreatePreallocated,
                &[0, buffer_b, 0x80, out],
            )
            .expect("prealloc B"),
            STATUS_SUCCESS
        );
        let memory_b = memory.read_u64(out).unwrap();
        // Overflowing copy is STATUS_BUFFER_TOO_SMALL.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCopy,
                &[memory_a, memory_b, 0x81],
            )
            .expect("overflow copy"),
            STATUS_BUFFER_TOO_SMALL
        );
        // Overlapping copy is STATUS_INVALID_PARAMETER.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCopy,
                &[memory_a, memory_a, 0x40],
            )
            .expect("overlap copy"),
            STATUS_INVALID_PARAMETER
        );
        // Valid copy moves the bytes.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCopy,
                &[memory_a, memory_b, 0x80],
            )
            .expect("valid copy"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u8(buffer_b).unwrap(), 0xAA);
        // A zero-length copy succeeds without touching either buffer.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCopy,
                &[memory_a, memory_b, 0],
            )
            .expect("zero-size copy"),
            STATUS_SUCCESS
        );
        // Wrong object type.
        let driver = island.kmdf_driver_handle();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCopy,
                &[driver, memory_b, 8],
            )
            .expect("copy from driver"),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCopy,
                &[memory_a, driver, 8],
            )
            .expect("copy to driver"),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        // Assign an invalid buffer pointer.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryAssign,
                &[memory_a, 1, 0x40],
            )
            .expect("assign bad buffer"),
            STATUS_INVALID_PARAMETER
        );
        // Assign a valid new buffer to the preallocated object.
        let new_buffer = 0x56_000;
        memory.map_bytes(new_buffer, &vec![0_u8; 0x40]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryAssign,
                &[memory_a, new_buffer, 0x40],
            )
            .expect("assign ok"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let record = state.kmdf.memories.get(&memory_a).expect("memory");
            assert_eq!(record.buffer, new_buffer);
            assert_eq!(record.size, 0x40);
        }
    });
}

/// Interrupt semantics: disabling blocks ISR dispatch and DPC queueing,
/// recursive lock acquire and unheld release are rejected, and enable
/// without a matching disable fails.
#[test]
fn kmdf_interrupt_disable_blocks_dispatch_and_lock_recursion_rejects() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, mut island) =
            load_staged_island_x64(&image, "CasaKmdfI");
        let device = island.kmdf_device_handles()[0];
        let counter = arena_counter(&mut memory, &island);
        let isr = x64_claiming_isr_stub(&mut memory, &island, counter);
        let dpc_counter = arena_counter(&mut memory, &island);
        let dpc = x64_marker_stub(&mut memory, &island, dpc_counter);
        // Config: Size, EvtInterruptIsr@8, EvtInterruptDpc@16.
        let config = 0x57_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        memory.write_u32(config, 0x18);
        memory.write_u64(config + 16, dpc);
        let interrupt_out = 0x57_100;
        memory.map_bytes(interrupt_out, &[0_u8; 8]);
        // A null ISR is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, interrupt_out],
            )
            .expect("null isr"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u64(config + 8, isr);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, interrupt_out],
            )
            .expect("create interrupt"),
            STATUS_SUCCESS
        );
        let interrupt = memory.read_u64(interrupt_out).unwrap();
        let vector = {
            let state = island.inner.borrow();
            state
                .kmdf
                .interrupts
                .get(&interrupt)
                .expect("interrupt")
                .controller as u32
        };
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, vector)
                .expect("trigger"),
            1,
            "the ISR claimed the interrupt"
        );
        assert_eq!(
            { island.inner.borrow().kmdf.interrupts[&interrupt].dpc_queued },
            0,
            "triggering the ISR alone does not queue the DPC"
        );
        // Queue the DPC through the KMDF API.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptQueueDpcForIsr,
                &[interrupt],
            )
            .expect("queue dpc"),
            STATUS_SUCCESS
        );
        assert_eq!(
            { memory.read_u32(dpc_counter).unwrap() },
            1,
            "EvtInterruptDpc ran once"
        );
        // Recursive acquire is a driver bug: the real framework
        // deadlocks, the island fails closed.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptAcquireLock,
                &[interrupt],
            )
            .expect("acquire"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptAcquireLock,
                &[interrupt],
            )
            .expect("recursive acquire"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptReleaseLock,
                &[interrupt],
            )
            .expect("release"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptReleaseLock,
                &[interrupt],
            )
            .expect("unheld release"),
            STATUS_INVALID_DEVICE_STATE
        );
        // Disable blocks the ISR and DPC queueing; synchronize returns
        // FALSE.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptDisable,
                &[interrupt],
            )
            .expect("disable"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, vector)
                .expect("trigger disabled"),
            0,
            "a disabled interrupt does not dispatch its ISR"
        );
        assert_eq!(
            { memory.read_u32(counter).unwrap() },
            1,
            "the ISR did not run while disabled"
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptQueueDpcForIsr,
                &[interrupt],
            )
            .expect("queue dpc disabled"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptSynchronize,
                &[interrupt, dpc, 0],
            )
            .expect("sync disabled"),
            0,
            "synchronize on a disabled interrupt returns FALSE"
        );
        assert_eq!(
            { memory.read_u32(dpc_counter).unwrap() },
            1,
            "the synchronize callback did not run while disabled"
        );
        // Enable without a matching disable is a driver bug.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptEnable,
                &[interrupt],
            )
            .expect("enable"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptEnable,
                &[interrupt],
            )
            .expect("enable again"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            island
                .trigger_virtual_interrupt(&mut runtime, &mut memory, vector)
                .expect("trigger re-enabled"),
            1
        );
    });
}

/// Mini-DMA channel: profile caps, uninitialized execute, oversize
/// initialize, and double release are rejected with exact statuses;
/// executed transactions report transferred bytes.
#[test]
fn kmdf_dma_transfer_scenarios_reject_uninitialized_and_oversized() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfD");
        let device = island.kmdf_device_handles()[0];
        let enabler_out = 0x58_000;
        memory.map_bytes(enabler_out, &[0_u8; 8]);
        let config = 0x58_100;
        memory.map_bytes(config, &[0_u8; 0x20]);
        // Invalid profile is rejected.
        memory.write_u32(config, 0x10);
        memory.write_u32(config + 4, 9);
        memory.write_u64(config + 8, 0x2_0000);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, enabler_out],
            )
            .expect("bad profile"),
            STATUS_INVALID_PARAMETER
        );
        // Zero maximum length is rejected.
        memory.write_u32(config + 4, 0);
        memory.write_u64(config + 8, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, enabler_out],
            )
            .expect("zero max"),
            STATUS_INVALID_PARAMETER
        );
        // Short profile with a 128 KB limit caps at 64 KB.
        memory.write_u64(config + 8, 0x2_0000);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, enabler_out],
            )
            .expect("create enabler"),
            STATUS_SUCCESS
        );
        let enabler = memory.read_u64(enabler_out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCalculateMaximumTransferSize,
                &[enabler],
            )
            .expect("max transfer"),
            0x1_0000,
            "Short profile caps single-segment transfers at 64 KB"
        );
        let transaction_out = 0x58_200;
        memory.map_bytes(transaction_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionCreate,
                &[enabler, 0, transaction_out],
            )
            .expect("create transaction"),
            STATUS_SUCCESS
        );
        let transaction = memory.read_u64(transaction_out).unwrap();
        // Execute before initialize fails.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionExecute,
                &[transaction],
            )
            .expect("execute uninitialized"),
            STATUS_INVALID_DEVICE_STATE
        );
        // Zero-length initialize is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[transaction, 0, 0, 0, 0],
            )
            .expect("zero length"),
            STATUS_INVALID_PARAMETER
        );
        // Invalid direction is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[transaction, 2, 0, 0x1000, 0],
            )
            .expect("bad direction"),
            STATUS_INVALID_PARAMETER
        );
        // Oversize transfer for the Short profile is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[transaction, 0, 0, 0x2_0000, 0],
            )
            .expect("oversize"),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[transaction, 0, 0, 0x1_0000, 0],
            )
            .expect("initialize"),
            STATUS_SUCCESS
        );
        // Cancel on an initialized transaction returns TRUE.
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionCancel,
                &[transaction],
            )
            .expect("cancel initialized"),
            1
        );
        // Cancel on a created transaction returns FALSE.
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionCancel,
                &[transaction],
            )
            .expect("cancel created"),
            0
        );
        // Re-initialize after the cancel and execute.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[transaction, 1, 0, 0x800, 0],
            )
            .expect("reinitialize"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionExecute,
                &[transaction],
            )
            .expect("execute"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let record = state
                .kmdf
                .dma_transactions
                .get(&transaction)
                .expect("transaction");
            assert_eq!(record.transferred, 0x800);
            assert_eq!(record.phase, KmdfDmaPhase::Executed);
            let enabler_state = state.kmdf.dma_enablers.get(&enabler).expect("enabler");
            assert_eq!(enabler_state.completed_transactions, 1);
            assert_eq!(enabler_state.transferred_bytes, 0x800);
        }
        // Executing twice is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionExecute,
                &[transaction],
            )
            .expect("execute twice"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionRelease,
                &[transaction],
            )
            .expect("release"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionRelease,
                &[transaction],
            )
            .expect("double release"),
            STATUS_INVALID_DEVICE_STATE
        );
        // A released transaction can be re-initialized.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[transaction, 0, 0, 0x100, 0],
            )
            .expect("initialize after release"),
            STATUS_SUCCESS
        );
    });
}

/// USB target: real configuration descriptors are parsed, out-of-range
/// pipe indexes and direction mismatches are rejected, the staged
/// loopback moves data, and abort/stall/reset gate transfers.
#[test]
fn kmdf_usb_endpoint_out_of_range_and_stall_reject_transfers() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfU");
        let device = island.kmdf_device_handles()[0];
        // A real USB configuration descriptor: config(9) +
        // interface(9) + two bulk endpoints(7+7).
        let descriptor = 0x59_000;
        memory.map_bytes(descriptor, &vec![0_u8; 0x40]);
        memory.write_u8(descriptor, 9);
        memory.write_u8(descriptor + 1, 2);
        memory.write_u16(descriptor + 2, 32);
        memory.write_u8(descriptor + 4, 1);
        memory.write_u8(descriptor + 9, 9);
        memory.write_u8(descriptor + 10, 4);
        memory.write_u8(descriptor + 12, 2);
        // Endpoint 0x81 (IN, bulk, 512).
        memory.write_u8(descriptor + 18, 7);
        memory.write_u8(descriptor + 19, 5);
        memory.write_u8(descriptor + 20, 0x81);
        memory.write_u8(descriptor + 21, 0x02);
        memory.write_u16(descriptor + 22, 512);
        // Endpoint 0x02 (OUT, bulk, 512).
        memory.write_u8(descriptor + 25, 7);
        memory.write_u8(descriptor + 26, 5);
        memory.write_u8(descriptor + 27, 0x02);
        memory.write_u8(descriptor + 28, 0x02);
        memory.write_u16(descriptor + 29, 512);
        let config = 0x59_100;
        memory.map_bytes(config, &[0_u8; 0x20]);
        memory.write_u32(config, 0x18);
        memory.write_u16(config + 4, 0x0200);
        memory.write_u16(config + 6, 0x1234);
        memory.write_u16(config + 8, 0x5678);
        memory.write_u64(config + 16, descriptor);
        let usb_out = 0x59_200;
        memory.map_bytes(usb_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, usb_out],
            )
            .expect("create usb target"),
            STATUS_SUCCESS
        );
        let usb = memory.read_u64(usb_out).unwrap();
        // Malformed descriptor: bLength = 5 for the config header.
        memory.write_u8(descriptor, 5);
        let usb_bad_out = 0x59_210;
        memory.map_bytes(usb_bad_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, usb_bad_out],
            )
            .expect("malformed descriptor"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u8(descriptor, 9);
        // Endpoint zero is the control endpoint, never a pipe.
        memory.write_u8(descriptor + 20, 0x00);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, usb_bad_out],
            )
            .expect("control endpoint as pipe"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u8(descriptor + 20, 0x81);
        // Device information roundtrip.
        let info_out = 0x59_300;
        memory.map_bytes(info_out, &[0_u8; 16]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceGetInformation,
                &[usb, info_out],
            )
            .expect("get info"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u16(info_out).unwrap(), 0x0200);
        assert_eq!(memory.read_u16(info_out + 2).unwrap(), 0x1234);
        assert_eq!(memory.read_u32(info_out + 8).unwrap(), 2);
        // Configured pipes: index 0 = IN, index 1 = OUT; index 2 is out
        // of range.
        let pipe_out = 0x59_400;
        memory.map_bytes(pipe_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                &[usb, 0, pipe_out, 0],
            )
            .expect("pipe 0"),
            STATUS_SUCCESS
        );
        let in_pipe = memory.read_u64(pipe_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                &[usb, 1, pipe_out, 0],
            )
            .expect("pipe 1"),
            STATUS_SUCCESS
        );
        let out_pipe = memory.read_u64(pipe_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                &[usb, 2, pipe_out, 0],
            )
            .expect("pipe oob"),
            STATUS_INVALID_PARAMETER
        );
        // Bulk pipe type.
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeGetType,
                &[in_pipe],
            )
            .expect("pipe type"),
            3,
            "bulk endpoint reports WDF_USB_PIPE_TYPE_Bulk"
        );
        // Direction mismatch: read on an OUT pipe.
        let transfer_buffer = 0x59_500;
        memory.map_bytes(transfer_buffer, &vec![0_u8; 0x40]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeReadPipe,
                &[out_pipe, 0, transfer_buffer, 8],
            )
            .expect("read on out pipe"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // Direction mismatch: write on an IN pipe.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[in_pipe, 0, transfer_buffer, 8],
            )
            .expect("write on in pipe"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // Staged loopback: write to OUT, device data appears for the
        // next read on the same endpoint after a host-side stage.
        for (index, byte) in [0x10_u8, 0x20, 0x30].iter().enumerate() {
            memory.write_u8(transfer_buffer + index as u64, *byte);
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[out_pipe, 0, transfer_buffer, 3],
            )
            .expect("write"),
            STATUS_SUCCESS
        );
        // A read from the IN endpoint sees no staged device data yet:
        // a zero-length short packet.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeReadPipe,
                &[in_pipe, 0, transfer_buffer, 8],
            )
            .expect("empty read"),
            STATUS_SUCCESS
        );
        // Stall the IN pipe: transfers fail until reset.
        assert!(island.kmdf_usb_stall_pipe_for_test(in_pipe));
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeReadPipe,
                &[in_pipe, 0, transfer_buffer, 8],
            )
            .expect("stalled read"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeResetPipe,
                &[in_pipe],
            )
            .expect("reset"),
            STATUS_SUCCESS
        );
        // Abort cancels subsequent transfers until reset.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeAbortPipe,
                &[out_pipe],
            )
            .expect("abort"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[out_pipe, 0, transfer_buffer, 3],
            )
            .expect("write aborted"),
            STATUS_CANCELLED
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeResetPipe,
                &[out_pipe],
            )
            .expect("reset out"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[out_pipe, 0, transfer_buffer, 3],
            )
            .expect("write after reset"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let target = state.kmdf.usb_targets.get(&usb).expect("usb");
            assert_eq!(
                target.transfers, 3,
                "three transfers succeeded: write, empty read, write after reset"
            );
            assert_eq!(target.transferred_bytes, 6);
        }
    });
}

/// Registry: missing keys, invalid paths, value-type/size mismatches,
/// write-access enforcement, buffer-too-small, and double close all
/// fail with the exact NTSTATUS.
#[test]
fn kmdf_registry_value_type_mismatch_and_missing_key_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfR");
        let key_out = 0x5A_000;
        memory.map_bytes(key_out, &[0_u8; 8]);
        let key_name = guest_unicode_string(
            &mut memory,
            0x5A_100,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfR",
        );
        // KEY_QUERY_VALUE | KEY_SET_VALUE.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, key_name, 3, key_out],
            )
            .expect("open service key"),
            STATUS_SUCCESS
        );
        let key = memory.read_u64(key_out).unwrap();
        // A missing key is STATUS_OBJECT_NAME_NOT_FOUND.
        let missing = guest_unicode_string(
            &mut memory,
            0x5A_200,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfR\\Nope",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, missing, 3, key_out],
            )
            .expect("open missing"),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        // A non-`\Registry\Machine\` absolute path is rejected.
        let bad_path = guest_unicode_string(&mut memory, 0x5A_300, "\\Registry\\Hive\\Foo");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, bad_path, 3, key_out],
            )
            .expect("open bad path"),
            STATUS_OBJECT_PATH_INVALID
        );
        // Query ImagePath (REG_SZ).  `guest_unicode_string` places the
        // character buffer at header+0x100, so keep data buffers clear
        // of each header's 0x100-byte window.
        let value_name = guest_unicode_string(&mut memory, 0x5A_400, "ImagePath");
        let buffer = 0x5B_100;
        memory.map_bytes(buffer, &vec![0_u8; 0x100]);
        let length_out = 0x5B_300;
        memory.map_bytes(length_out, &[0_u8; 8]);
        let type_out = 0x5B_310;
        memory.map_bytes(type_out, &[0_u8; 4]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[key, value_name, buffer, 0x100, length_out, type_out],
            )
            .expect("query ImagePath"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(type_out).unwrap(), 1, "REG_SZ");
        let required = memory.read_u64(length_out).unwrap();
        assert!(required > 0);
        // A too-small buffer fails with STATUS_BUFFER_TOO_SMALL and
        // still reports the required length.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[key, value_name, buffer, 1, length_out, type_out],
            )
            .expect("query small buffer"),
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(memory.read_u64(length_out).unwrap(), required);
        // A missing value is STATUS_OBJECT_NAME_NOT_FOUND.
        let missing_value = guest_unicode_string(&mut memory, 0x5B_400, "NoSuchValue");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[key, missing_value, buffer, 0x100, length_out, type_out],
            )
            .expect("query missing value"),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        // Type/size mismatch: REG_DWORD must be exactly 4 bytes.
        let dword_name = guest_unicode_string(&mut memory, 0x5B_500, "TestDword");
        memory.map_bytes(0x5B_700, &[7, 0, 0, 0]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryAssignValue,
                &[key, dword_name, 4, 0x5B_700, 3],
            )
            .expect("dword wrong size"),
            STATUS_INVALID_PARAMETER
        );
        // Unsupported registry type is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryAssignValue,
                &[key, dword_name, 99, 0x5B_700, 4],
            )
            .expect("bad type"),
            STATUS_INVALID_PARAMETER
        );
        // A valid REG_DWORD writes and reads back.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryAssignValue,
                &[key, dword_name, 4, 0x5B_700, 4],
            )
            .expect("assign dword"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[key, dword_name, buffer, 0x100, length_out, type_out],
            )
            .expect("query dword"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u32(type_out).unwrap(), 4, "REG_DWORD");
        assert_eq!(memory.read_u64(length_out).unwrap(), 4);
        assert_eq!(memory.read_u32(buffer).unwrap(), 7);
        // A read-only key rejects writes with STATUS_ACCESS_DENIED.
        let readonly = guest_unicode_string(
            &mut memory,
            0x5C_000,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfR",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, readonly, 1, key_out],
            )
            .expect("open readonly"),
            STATUS_SUCCESS
        );
        let readonly_key = memory.read_u64(key_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryAssignValue,
                &[readonly_key, dword_name, 4, 0x5B_700, 4],
            )
            .expect("assign readonly"),
            STATUS_ACCESS_DENIED
        );
        // Deleting a missing value fails.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryDeleteValue,
                &[key, missing_value],
            )
            .expect("delete missing value"),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryDeleteValue,
                &[key, dword_name],
            )
            .expect("delete value"),
            STATUS_SUCCESS
        );
        // Double close is STATUS_INVALID_HANDLE.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryClose,
                &[key],
            )
            .expect("close"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryClose,
                &[key],
            )
            .expect("double close"),
            STATUS_INVALID_HANDLE
        );
    });
}

/// Child list: arrivals materialize child PDOs, removals run the PnP
/// remove path (queued requests cancel), iteration reflects the
/// description set, and stale iterators/list handles fail exactly.
#[test]
fn kmdf_child_list_arrival_removal_dispatch_pnp_transitions() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfB");
        let device = island.kmdf_device_handles()[0];
        let enumerate_counter = arena_counter(&mut memory, &island);
        let enumerate = x64_marker_stub(&mut memory, &island, enumerate_counter);
        let config = 0x5C_000;
        memory.map_bytes(config, &[0_u8; 0x10]);
        memory.write_u32(config, 0x10);
        memory.write_u64(config + 8, enumerate);
        let list_out = 0x5C_100;
        memory.map_bytes(list_out, &[0_u8; 8]);
        // A child list without an enumerate callback is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[device, 0, 0, list_out],
            )
            .expect("null enumerate"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[device, 0, config, list_out],
            )
            .expect("create child list"),
            STATUS_SUCCESS
        );
        let list = memory.read_u64(list_out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetChildCount,
                &[list],
            )
            .expect("initial count"),
            0
        );
        // An empty scan runs the enumerate callback and leaves the list
        // empty.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfEvtChildListScanDispatch,
                &[list],
            )
            .expect("empty scan"),
            STATUS_SUCCESS
        );
        assert_eq!(
            { memory.read_u32(enumerate_counter).unwrap() },
            1,
            "EvtChildListEnumerateChildren ran"
        );
        // Arrival: a scan whose collection holds two descriptions
        // materializes two child PDOs.
        let collection_out = 0x5C_200;
        memory.map_bytes(collection_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, collection_out],
            )
            .expect("scan collection"),
            STATUS_SUCCESS
        );
        let scan_collection = memory.read_u64(collection_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[scan_collection, 0xD1],
            )
            .expect("add child 1"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[scan_collection, 0xD2],
            )
            .expect("add child 2"),
            STATUS_SUCCESS
        );
        {
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            let pending = state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan {
                        list,
                        collection: scan_collection,
                    },
                    STATUS_SUCCESS,
                )
                .expect("scan completion");
            assert!(pending.is_none(), "no follow-up callbacks");
        }
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetChildCount,
                &[list],
            )
            .expect("count after arrival"),
            2
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.child_arrivals, 2);
            assert_eq!(state.kmdf.child_devices.len(), 2);
            assert!(state.kmdf.child_devices.contains_key(&0xD1));
            assert!(state.kmdf.child_devices.contains_key(&0xD2));
        }
        // Iterate the descriptions.
        let iterator_out = 0x5C_300;
        memory.map_bytes(iterator_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetFirst,
                &[list, iterator_out],
            )
            .expect("iterator"),
            STATUS_SUCCESS
        );
        let iterator = memory.read_u64(iterator_out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetNext,
                &[iterator, 0],
            )
            .expect("next 1"),
            1
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetNext,
                &[iterator, 0],
            )
            .expect("next 2"),
            1
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetNext,
                &[iterator, 0],
            )
            .expect("exhausted"),
            0
        );
        // Queue a request on the first child so the removal path must
        // cancel it.
        let child_device = { island.inner.borrow().kmdf.child_devices[&0xD1] };
        let queue_out = 0x5C_400;
        memory.map_bytes(queue_out, &[0_u8; 8]);
        let queue_config = 0x5C_500;
        memory.map_bytes(queue_config, &[0_u8; 0x20]);
        memory.write_u32(queue_config, 0x20);
        memory.write_u32(queue_config + 4, 2); // manual dispatch.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[child_device, queue_config, 0, queue_out],
            )
            .expect("child queue"),
            STATUS_SUCCESS
        );
        let child_queue = memory.read_u64(queue_out).unwrap();
        let request_out = 0x5C_600;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, child_device, request_out],
            )
            .expect("child request"),
            STATUS_SUCCESS
        );
        let child_request = memory.read_u64(request_out).unwrap();
        let child_irp = {
            let state = island.inner.borrow();
            state.kmdf.requests[&child_request].irp
        };
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[child_request, child_queue],
            )
            .expect("queue child request"),
            STATUS_SUCCESS
        );
        // Removal: a scan with an empty collection removes both
        // children through the PnP remove path.
        {
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            let scan_out = 0x5C_700;
            memory.map_bytes(scan_out, &[0_u8; 8]);
            let empty_collection = state
                .create_kmdf_object(&mut memory, KmdfObjectKind::Collection, 0)
                .expect("empty collection");
            state.kmdf.collections.insert(
                empty_collection,
                KmdfCollection {
                    items: Vec::new(),
                    max_size: 1024,
                },
            );
            let pending = state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan {
                        list,
                        collection: empty_collection,
                    },
                    STATUS_SUCCESS,
                )
                .expect("removal scan");
            assert!(pending.is_none());
        }
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetChildCount,
                &[list],
            )
            .expect("count after removal"),
            0
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.child_removals, 2);
            assert!(state.kmdf.child_devices.is_empty());
            // PnP removal ran: the child device's framework record is
            // purged with the delete cascade.
            assert!(!state.kmdf.devices.contains_key(&child_device));
            // The queued request was cancelled by the removal path.
            assert_eq!(
                state.io.irp_status(child_irp),
                Ok(STATUS_CANCELLED),
                "child request IRP cancelled by the PnP removal"
            );
        }
        // Deleting the list invalidates outstanding iterators.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[list],
            )
            .expect("delete list"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetNext,
                &[iterator, 0],
            )
            .expect("stale iterator"),
            STATUS_INVALID_HANDLE
        );
    });
}

/// CM resource lists: descriptor counts are bounded, out-of-range
/// descriptor lookups return NULL, and wrong-type handles fail.
#[test]
fn kmdf_cm_resource_list_out_of_range_descriptor_returns_null() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfQ");
        let list_out = 0x5D_000;
        memory.map_bytes(list_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCmResourceListCreate,
                &[0, 0, list_out],
            )
            .expect("zero descriptors"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCmResourceListCreate,
                &[0, 65, list_out],
            )
            .expect("too many descriptors"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCmResourceListCreate,
                &[0, 2, list_out],
            )
            .expect("create list"),
            STATUS_SUCCESS
        );
        let list = memory.read_u64(list_out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCmResourceListGetCount,
                &[list],
            )
            .expect("count"),
            2
        );
        let descriptor0 = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfCmResourceListGetDescriptor,
            &[list, 0],
        )
        .expect("descriptor 0");
        assert_ne!(descriptor0, 0);
        // The descriptor is guest-writable.
        memory.write_u8(descriptor0, 1);
        assert_eq!(memory.read_u8(descriptor0).unwrap(), 1);
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCmResourceListGetDescriptor,
                &[list, 2],
            )
            .expect("descriptor oob"),
            0,
            "out-of-range descriptor returns NULL"
        );
        let driver = island.kmdf_driver_handle();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCmResourceListGetCount,
                &[driver],
            )
            .expect("count on driver"),
            STATUS_OBJECT_TYPE_MISMATCH
        );
    });
}

/// Request extensions: CreateFromIrp wraps a WDM IRP exactly once,
/// impersonation requires ownership and valid levels, WdmGetIrp
/// round-trips the pointer, and SetInformation rejects completed
/// requests.
#[test]
fn kmdf_request_from_irp_impersonate_and_information_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfW");
        // Allocate a WDM IRP through the island.
        let irp = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoAllocateIrp,
            &[1, 0],
        )
        .expect("allocate irp");
        assert_ne!(irp, 0);
        let request_out = 0x5E_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreateFromIrp,
                &[0, irp, request_out],
            )
            .expect("wrap irp"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        // Wrapping the same IRP twice is STATUS_INVALID_DEVICE_REQUEST.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreateFromIrp,
                &[0, irp, request_out],
            )
            .expect("double wrap"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // An unknown IRP pointer is STATUS_INVALID_PARAMETER.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreateFromIrp,
                &[0, 0xBEEF, request_out],
            )
            .expect("wrap fake irp"),
            STATUS_INVALID_PARAMETER
        );
        // WdmGetIrp returns the original guest IRP pointer.
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestWdmGetIrp,
                &[request],
            )
            .expect("get irp"),
            irp
        );
        // Impersonation: invalid levels and unowned requests fail.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestImpersonate,
                &[request, 4],
            )
            .expect("bad level"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestImpersonate,
                &[request, 2],
            )
            .expect("unowned impersonate"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // Take ownership of the request (as a queue dispatch would).
        island.inner.borrow_mut().kmdf.current_request = request;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestImpersonate,
                &[request, 2],
            )
            .expect("impersonate"),
            STATUS_SUCCESS
        );
        // Double impersonation is STATUS_INVALID_DEVICE_STATE.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestImpersonate,
                &[request, 2],
            )
            .expect("double impersonate"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestStopImpersonating,
                &[request],
            )
            .expect("stop impersonating"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestStopImpersonating,
                &[request],
            )
            .expect("stop again"),
            STATUS_INVALID_DEVICE_STATE
        );
        // SetInformation on the live request.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSetInformation,
                &[request, 0x40],
            )
            .expect("set information"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let record = state.kmdf.requests.get(&request).expect("request");
            assert_eq!(record.information, 0x40);
        }
        // Completing the request freezes Information.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[request, STATUS_SUCCESS as u64],
            )
            .expect("complete"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestSetInformation,
                &[request, 0x80],
            )
            .expect("set information completed"),
            STATUS_INVALID_DEVICE_STATE
        );
    });
}

/// Forward-to-parent: only a child device's request can reach the
/// parent's queue, completed requests and mismatched queues fail with
/// exact statuses, and the forwarded request dispatches.
#[test]
fn kmdf_request_forward_to_parent_rejects_completed_and_foreign_queue() {
    with_big_stack(|| {
        let image = build_kmdf_full_driver(0, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfP");
        let parent = island.kmdf_device_handles()[0];
        // A manual parent queue so forwards defer instead of dispatching
        // into guest code during the test.
        let parent_queue_out = 0x5F_800;
        memory.map_bytes(parent_queue_out, &[0_u8; 8]);
        let parent_queue_config = 0x5F_900;
        memory.map_bytes(parent_queue_config, &[0_u8; 0x20]);
        memory.write_u32(parent_queue_config, 0x20);
        memory.write_u32(parent_queue_config + 4, 2); // manual dispatch.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[parent, parent_queue_config, 0, parent_queue_out],
            )
            .expect("parent manual queue"),
            STATUS_SUCCESS
        );
        let parent_queue = memory.read_u64(parent_queue_out).unwrap();
        // Create a child PDO under the parent.
        let pdo_init = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfPdoInitAllocate,
            &[parent],
        )
        .expect("pdo init");
        assert_ne!(pdo_init, 0);
        let child_out = 0x5F_000;
        memory.map_bytes(child_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[pdo_init, 0, child_out],
            )
            .expect("create child"),
            STATUS_SUCCESS
        );
        let child = memory.read_u64(child_out).unwrap();
        // A request on the child forwards to the parent's queue.
        let request_out = 0x5F_100;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, child, request_out],
            )
            .expect("child request"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        // Invalid forward action.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[request, parent_queue, 3],
            )
            .expect("bad action"),
            STATUS_INVALID_PARAMETER
        );
        let status = call_island_shim(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfRequestForwardToParentDeviceIoQueue,
            &[request, parent_queue, 0],
        )
        .expect("forward");
        assert_eq!(status, STATUS_SUCCESS);
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.parent_queue_forwards, 1);
            let record = state.kmdf.requests.get(&request).expect("request");
            assert_eq!(record.queue, Some(parent_queue));
            assert!(
                state.kmdf.queues[&parent_queue]
                    .in_flight
                    .contains(&request)
                    || state.kmdf.queues[&parent_queue].queued.contains(&request),
                "forwarded request is on the parent queue"
            );
        }
        // A queue on a different device is rejected.
        let request_out2 = 0x5F_200;
        memory.map_bytes(request_out2, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, child, request_out2],
            )
            .expect("child request 2"),
            STATUS_SUCCESS
        );
        let request2 = memory.read_u64(request_out2).unwrap();
        // A queue owned by a device other than the request's parent is
        // rejected with STATUS_INVALID_DEVICE_REQUEST.
        let child_queue_out = 0x5F_400;
        memory.map_bytes(child_queue_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[child, parent_queue_config, 0, child_queue_out],
            )
            .expect("child queue"),
            STATUS_SUCCESS
        );
        let child_queue = memory.read_u64(child_queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[request2, child_queue, 0],
            )
            .expect("foreign queue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // A completed request cannot be forwarded.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[request2, STATUS_SUCCESS as u64],
            )
            .expect("complete"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[request2, parent_queue, 0],
            )
            .expect("forward completed"),
            STATUS_INVALID_DEVICE_STATE
        );
        // A parent request (no parent device) cannot be forwarded up.
        let request_out3 = 0x5F_300;
        memory.map_bytes(request_out3, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, parent, request_out3],
            )
            .expect("parent request"),
            STATUS_SUCCESS
        );
        let request3 = memory.read_u64(request_out3).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[request3, parent_queue, 0],
            )
            .expect("forward parent request"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // A device-less request (wrapped from a raw WDM IRP) cannot be
        // forwarded up.
        let irp = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::IoAllocateIrp,
            &[1, 0],
        )
        .expect("allocate irp");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreateFromIrp,
                &[0, irp, request_out3],
            )
            .expect("wrap irp"),
            STATUS_SUCCESS
        );
        let wrapped = memory.read_u64(request_out3).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[wrapped, parent_queue, 0],
            )
            .expect("forward device-less request"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // A stale queue handle with a live request fails on the queue.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[request, 0xDEAD_BEEF, 0],
            )
            .expect("forward to stale queue"),
            STATUS_INVALID_HANDLE
        );
        // Double forward of a deferred child request: the source-queue
        // sweep runs against the queue the first forward recorded.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[request, parent_queue, 0],
            )
            .expect("double forward"),
            STATUS_SUCCESS
        );
        // A sequential parent queue with a live callback dispatches
        // immediately; one without a callback rejects with
        // STATUS_INVALID_DEVICE_REQUEST.
        let live_config = 0x5F_500;
        memory.map_bytes(live_config, &[0_u8; 0x40]);
        let counter = arena_counter(&mut memory, &island);
        let callback = x64_marker_stub(&mut memory, &island, counter);
        memory.write_u32(live_config, 0x40);
        memory.write_u32(live_config + 4, 0);
        memory.write_u64(live_config + 0x10, callback);
        let live_out = 0x5F_600;
        memory.map_bytes(live_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[parent, live_config, 0, live_out],
            )
            .expect("live parent queue"),
            STATUS_SUCCESS
        );
        let live_queue = memory.read_u64(live_out).unwrap();
        // Entry-equals-zero: a sequential queue with no callbacks.
        memory.write_u64(live_config + 0x10, 0);
        memory.map_bytes(live_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[parent, live_config, 0, live_out],
            )
            .expect("bare parent queue"),
            STATUS_SUCCESS
        );
        let bare_parent_queue = memory.read_u64(live_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, child, request_out],
            )
            .expect("child request bare"),
            STATUS_SUCCESS
        );
        let bare_child = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[bare_child, bare_parent_queue, 0],
            )
            .expect("forward to bare parent queue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // Immediate dispatch: forward into the live queue; the guest
        // callback runs and the request stays pending until completed.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, child, request_out],
            )
            .expect("child request live"),
            STATUS_SUCCESS
        );
        let live_child = memory.read_u64(request_out).unwrap();
        let runs_before = memory.read_u32(counter).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[live_child, live_queue, 0],
            )
            .expect("forward to live parent queue"),
            STATUS_PENDING,
            "the dispatched request pends until its callback completes it"
        );
        assert!(
            memory.read_u32(counter).unwrap() > runs_before,
            "the parent queue callback ran"
        );
        // A child request whose in-flight sibling holds the sequential
        // queue defers instead of dispatching.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, child, request_out],
            )
            .expect("child request deferred"),
            STATUS_SUCCESS
        );
        let deferred_child = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[deferred_child, live_queue, 0],
            )
            .expect("forward behind in-flight"),
            STATUS_SUCCESS,
            "a sequential queue with work in flight defers"
        );
        // Forwarding the request that is in flight on the live queue
        // sweeps it out of that queue's in-flight set before the new
        // defer.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                &[live_child, parent_queue, 0],
            )
            .expect("forward an in-flight request"),
            STATUS_SUCCESS,
            "the in-flight source queue is swept on re-forward"
        );
        {
            let state = island.inner.borrow();
            let live = state.kmdf.queues.get(&live_queue).expect("live queue");
            assert!(
                !live.in_flight.contains(&live_child),
                "the source queue released the swept request"
            );
            assert!(
                state.kmdf.queues[&parent_queue]
                    .queued
                    .contains(&live_child)
            );
        }
    });
}

/// Object references: an object with references survives
/// `WdfObjectDelete` until the last reference is dropped, other APIs
/// reject the handle while the delete is pending, and unbalanced
/// dereferences fail.
#[test]
fn kmdf_object_reference_defers_delete_until_last_dereference() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfO");
        let collection_out = 0x5E_000;
        memory.map_bytes(collection_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, collection_out],
            )
            .expect("create collection"),
            STATUS_SUCCESS
        );
        let collection = memory.read_u64(collection_out).unwrap();
        // Reference of an unknown object fails.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectReference,
                &[0xDEAD],
            )
            .expect("reference missing"),
            STATUS_INVALID_HANDLE
        );
        // Take two references.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectReference,
                &[collection],
            )
            .expect("reference 1"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectReference,
                &[collection],
            )
            .expect("reference 2"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert_eq!(
                state.kmdf.objects[&collection].references, 2,
                "two outstanding references"
            );
        }
        // Delete with references: the handle is invalid immediately but
        // the object survives for the outstanding references.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[collection],
            )
            .expect("delete referenced object"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(
                state.kmdf.objects.contains_key(&collection),
                "referenced object survives the delete"
            );
            assert!(state.kmdf.objects[&collection].delete_pending);
        }
        // The handle is rejected by other APIs while the delete is
        // pending.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionGetCount,
                &[collection],
            )
            .expect("use pending object"),
            STATUS_INVALID_HANDLE
        );
        // Double delete fails.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[collection],
            )
            .expect("double delete"),
            STATUS_INVALID_HANDLE
        );
        // Referencing a delete-pending object fails.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectReference,
                &[collection],
            )
            .expect("reference pending"),
            STATUS_INVALID_HANDLE
        );
        // First dereference: one reference remains.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDereference,
                &[collection],
            )
            .expect("deref 1"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(
                state.kmdf.objects.contains_key(&collection),
                "one reference remains"
            );
        }
        // Unbalanced dereference of a foreign object fails.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDereference,
                &[0xBAD],
            )
            .expect("deref missing"),
            STATUS_INVALID_HANDLE
        );
        // Final dereference completes the deferred deletion.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDereference,
                &[collection],
            )
            .expect("deref 2"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(
                !state.kmdf.objects.contains_key(&collection),
                "object purged after the last reference"
            );
            assert!(state.kmdf.collections.is_empty());
        }
        // Dereferencing again underflows the count.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDereference,
                &[collection],
            )
            .expect("deref after purge"),
            STATUS_INVALID_HANDLE
        );
        // An unreferenced object cannot be dereferenced at all.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, collection_out],
            )
            .expect("recreate"),
            STATUS_SUCCESS
        );
        let fresh = memory.read_u64(collection_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDereference,
                &[fresh],
            )
            .expect("unbalanced deref"),
            STATUS_INVALID_PARAMETER
        );
    });
}

/// Control devices: allocation requires the driver handle, finishing
/// twice or finishing a non-PnP device fails, and a `\DosDevices\`
/// name registers a symbolic link that the object manager resolves.
#[test]
fn kmdf_control_device_finish_rejects_double_and_symlink_resolves() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfS");
        let driver = island.kmdf_driver_handle();
        // A foreign driver handle is rejected.
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfControlDeviceInitAllocate,
                &[driver + 0x1000, 0],
            )
            .expect("wrong driver"),
            STATUS_INVALID_HANDLE as u64
        );
        let init = call_island_shim_raw(
            &island,
            &mut runtime,
            &mut memory,
            DriverShim::WdfControlDeviceInitAllocate,
            &[driver, 0],
        )
        .expect("allocate control init");
        assert_ne!(init, 0);
        let name = guest_unicode_string(&mut memory, 0x5E_000, "\\DosDevices\\CasaCtlLink");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitAssignName,
                &[init, name],
            )
            .expect("assign name"),
            STATUS_SUCCESS
        );
        let device_out = 0x5E_200;
        memory.map_bytes(device_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[init, 0, device_out],
            )
            .expect("create control device"),
            STATUS_SUCCESS
        );
        let device = memory.read_u64(device_out).unwrap();
        {
            let state = island.inner.borrow();
            assert!(
                state
                    .symbolic_links
                    .iter()
                    .any(|(link, target)| link == "\\DosDevices\\CasaCtlLink"
                        && target == "\\Device\\CasaCtlLink"),
                "control device name registers the symbolic link"
            );
            assert_eq!(state.kmdf.symbolic_links_created, 1);
        }
        // The object manager resolves the link.
        let handle_ptr = 0x5E_300;
        memory.map_bytes(handle_ptr, &[0_u8; 4]);
        assert_eq!(
            nt_open_island_device(&runtime, &mut memory, "\\??\\CasaCtlLink", handle_ptr),
            Some(STATUS_SUCCESS)
        );
        assert_eq!(
            nt_open_island_device(
                &runtime,
                &mut memory,
                "\\DosDevices\\CasaCtlLink",
                handle_ptr
            ),
            Some(STATUS_SUCCESS)
        );
        // Finishing the control device succeeds exactly once.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfControlFinishInitializing,
                &[device],
            )
            .expect("finish"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfControlFinishInitializing,
                &[device],
            )
            .expect("double finish"),
            STATUS_INVALID_DEVICE_STATE
        );
        // A non-PnP device cannot be finished.
        let fdo = island.kmdf_device_handles()[0];
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfControlFinishInitializing,
                &[fdo],
            )
            .expect("finish fdo"),
            STATUS_INVALID_DEVICE_STATE
        );
    });
}

/// Interrupt synchronization runs the callback at the interrupt's
/// synchronization IRQL and reports TRUE.
#[test]
fn kmdf_interrupt_synchronize_runs_callback_at_sync_irql() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfY");
        let device = island.kmdf_device_handles()[0];
        let counter = arena_counter(&mut memory, &island);
        let isr = x64_claiming_isr_stub(&mut memory, &island, counter);
        let sync = x64_marker_stub(&mut memory, &island, counter);
        let config = 0x5D_000;
        memory.map_bytes(config, &[0_u8; 0x10]);
        memory.write_u32(config, 0x10);
        memory.write_u64(config + 8, isr);
        let interrupt_out = 0x5D_100;
        memory.map_bytes(interrupt_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, interrupt_out],
            )
            .expect("create"),
            STATUS_SUCCESS
        );
        let interrupt = memory.read_u64(interrupt_out).unwrap();
        // A null callback is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptSynchronize,
                &[interrupt, 0, 0],
            )
            .expect("null sync callback"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptSynchronize,
                &[interrupt, sync, 0],
            )
            .expect("synchronize"),
            1,
            "synchronize on an enabled interrupt returns TRUE"
        );
        assert_eq!(
            { memory.read_u32(counter).unwrap() },
            1,
            "the synchronize callback ran"
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kernel.irql, 0, "IRQL restored after synchronize");
        }
    });
}

/// Every new guest-visible import name resolves to its shim, and an
/// unknown import stays missing.
#[test]
fn kmdf_import_lookup_new_names_resolve_and_unknown_rejects() {
    let expected = [
        ("WdfCollectionCreate", DriverShim::WdfCollectionCreate),
        ("WdfCollectionAdd", DriverShim::WdfCollectionAdd),
        ("WdfCollectionRemove", DriverShim::WdfCollectionRemove),
        ("WdfCollectionRemoveAll", DriverShim::WdfCollectionRemoveAll),
        ("WdfCollectionGetItem", DriverShim::WdfCollectionGetItem),
        ("WdfCollectionGetCount", DriverShim::WdfCollectionGetCount),
        ("WdfCollectionContains", DriverShim::WdfCollectionContains2),
        ("WdfCollectionContains2", DriverShim::WdfCollectionContains2),
        ("WdfLookasideListCreate", DriverShim::WdfLookasideListCreate),
        (
            "WdfMemoryCreateFromLookaside",
            DriverShim::WdfMemoryCreateFromLookaside,
        ),
        ("WdfInterruptCreate", DriverShim::WdfInterruptCreate),
        (
            "WdfInterruptQueueDpcForIsr",
            DriverShim::WdfInterruptQueueDpcForIsr,
        ),
        (
            "WdfInterruptAcquireLock",
            DriverShim::WdfInterruptAcquireLock,
        ),
        (
            "WdfInterruptReleaseLock",
            DriverShim::WdfInterruptReleaseLock,
        ),
        (
            "WdfInterruptSynchronize",
            DriverShim::WdfInterruptSynchronize,
        ),
        ("WdfInterruptDisable", DriverShim::WdfInterruptDisable),
        ("WdfInterruptEnable", DriverShim::WdfInterruptEnable),
        ("WdfDmaEnablerCreate", DriverShim::WdfDmaEnablerCreate),
        (
            "WdfDmaEnablerCalculateMaximumTransferSize",
            DriverShim::WdfDmaEnablerCalculateMaximumTransferSize,
        ),
        (
            "WdfDmaTransactionCreate",
            DriverShim::WdfDmaTransactionCreate,
        ),
        (
            "WdfDmaTransactionInitialize",
            DriverShim::WdfDmaTransactionInitialize,
        ),
        (
            "WdfDmaTransactionExecute",
            DriverShim::WdfDmaTransactionExecute,
        ),
        (
            "WdfDmaTransactionRelease",
            DriverShim::WdfDmaTransactionRelease,
        ),
        (
            "WdfDmaTransactionCancel",
            DriverShim::WdfDmaTransactionCancel,
        ),
        (
            "WdfUsbTargetDeviceCreate",
            DriverShim::WdfUsbTargetDeviceCreate,
        ),
        (
            "WdfUsbTargetDeviceGetInformation",
            DriverShim::WdfUsbTargetDeviceGetInformation,
        ),
        (
            "WdfUsbInterfaceGetConfiguredPipe",
            DriverShim::WdfUsbInterfaceGetConfiguredPipe,
        ),
        (
            "WdfUsbTargetPipeReadPipe",
            DriverShim::WdfUsbTargetPipeReadPipe,
        ),
        (
            "WdfUsbTargetPipeWritePipe",
            DriverShim::WdfUsbTargetPipeWritePipe,
        ),
        (
            "WdfUsbTargetPipeAbortPipe",
            DriverShim::WdfUsbTargetPipeAbortPipe,
        ),
        (
            "WdfUsbTargetPipeResetPipe",
            DriverShim::WdfUsbTargetPipeResetPipe,
        ),
        (
            "WdfUsbTargetPipeGetType",
            DriverShim::WdfUsbTargetPipeGetType,
        ),
        ("WdfRegistryOpenKey", DriverShim::WdfRegistryOpenKey),
        ("WdfRegistryCreateKey", DriverShim::WdfRegistryCreateKey),
        ("WdfRegistryClose", DriverShim::WdfRegistryClose),
        ("WdfRegistryQueryValue", DriverShim::WdfRegistryQueryValue),
        ("WdfRegistryAssignValue", DriverShim::WdfRegistryAssignValue),
        ("WdfRegistrySetValue", DriverShim::WdfRegistryAssignValue),
        ("WdfRegistryDeleteValue", DriverShim::WdfRegistryDeleteValue),
        ("WdfChildListCreate", DriverShim::WdfChildListCreate),
        ("WdfChildListGetFirst", DriverShim::WdfChildListGetFirst),
        ("WdfChildListGetNext", DriverShim::WdfChildListGetNext),
        (
            "WdfChildListGetChildCount",
            DriverShim::WdfChildListGetChildCount,
        ),
        (
            "WdfCmResourceListCreate",
            DriverShim::WdfCmResourceListCreate,
        ),
        (
            "WdfCmResourceListGetDescriptor",
            DriverShim::WdfCmResourceListGetDescriptor,
        ),
        (
            "WdfCmResourceListGetCount",
            DriverShim::WdfCmResourceListGetCount,
        ),
        ("WdfMemoryCopy", DriverShim::WdfMemoryCopy),
        ("WdfMemoryAssign", DriverShim::WdfMemoryAssign),
        (
            "WdfRequestCreateFromIrp",
            DriverShim::WdfRequestCreateFromIrp,
        ),
        ("WdfRequestImpersonate", DriverShim::WdfRequestImpersonate),
        (
            "WdfRequestStopImpersonating",
            DriverShim::WdfRequestStopImpersonating,
        ),
        ("WdfRequestWdmGetIrp", DriverShim::WdfRequestWdmGetIrp),
        (
            "WdfRequestSetInformation",
            DriverShim::WdfRequestSetInformation,
        ),
        (
            "WdfRequestForwardToParentDeviceIoQueue",
            DriverShim::WdfRequestForwardToParentDeviceIoQueue,
        ),
        ("WdfObjectReference", DriverShim::WdfObjectReference),
        ("WdfObjectDereference", DriverShim::WdfObjectDereference),
        (
            "WdfControlDeviceInitAllocate",
            DriverShim::WdfControlDeviceInitAllocate,
        ),
        (
            "WdfControlFinishInitializing",
            DriverShim::WdfControlFinishInitializing,
        ),
    ];
    for (name, shim) in expected {
        assert_eq!(
            DriverShim::for_import(name),
            Some(shim),
            "import {name} must resolve to {shim:?}"
        );
        // The lookup lowercases, so mixed case must resolve identically.
        let upper = name.to_uppercase();
        assert_eq!(
            DriverShim::for_import(&upper),
            Some(shim),
            "import {upper} must resolve case-insensitively"
        );
    }
    assert_eq!(
        DriverShim::for_import("WdfNoSuchApiAtAll"),
        None,
        "an unknown import name must stay unresolved"
    );
}

/// Stale and wrong-type handles across the new surface fail with the
/// exact NTSTATUS on every failure path.
#[test]
fn kmdf_new_shims_reject_stale_and_wrong_type_handles() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfH");
        // Scratch guest block for out-pointer arguments in the matrix.
        memory.map_bytes(0x44_000, &vec![0_u8; 0x40]);
        let driver = island.kmdf_driver_handle();
        let dead = 0xDEAD_BEEFu64;
        let stub = {
            let counter = arena_counter(&mut memory, &island);
            x64_marker_stub(&mut memory, &island, counter)
        };
        // (shim, args, pinned status) — a dead handle fails with
        // STATUS_INVALID_HANDLE before any other validation.
        let stale: [(DriverShim, [u64; 5], i32); 41] = [
            (
                DriverShim::WdfInterruptQueueDpcForIsr,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfInterruptAcquireLock,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfInterruptReleaseLock,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfInterruptSynchronize,
                [dead, stub, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfInterruptDisable,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfInterruptEnable,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfDmaEnablerCalculateMaximumTransferSize,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfDmaTransactionCreate,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfDmaTransactionInitialize,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfDmaTransactionExecute,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfDmaTransactionRelease,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfDmaTransactionCancel,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfUsbTargetDeviceGetInformation,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfUsbTargetPipeReadPipe,
                [dead, 0, 0, 8, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfUsbTargetPipeAbortPipe,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfUsbTargetPipeResetPipe,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfUsbTargetPipeGetType,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfChildListGetChildCount,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfChildListGetFirst,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfChildListGetNext,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfEvtChildListScanDispatch,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfCmResourceListGetDescriptor,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfCmResourceListGetCount,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfRequestImpersonate,
                [dead, 1, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfRequestStopImpersonating,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfRequestWdmGetIrp,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfRequestSetInformation,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfRequestForwardToParentDeviceIoQueue,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfControlFinishInitializing,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfMemoryCopy,
                [dead, 0, 8, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfMemoryAssign,
                [dead, 0, 8, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfMemoryCreateFromLookaside,
                [dead, 0x44_000, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfCollectionRemove,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfCollectionRemoveAll,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfCollectionGetItem,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfCollectionGetCount,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfCollectionContains2,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfSpinLockAcquire,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfSpinLockRelease,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
            (
                DriverShim::WdfTimerStop,
                [dead, 0, 0, 0, 0],
                STATUS_INVALID_HANDLE,
            ),
        ];
        for (shim, args, want) in stale {
            assert_eq!(
                call_island_shim(&island, &mut runtime, &mut memory, shim, &args)
                    .unwrap_or_else(|error| panic!("{shim:?} host error: {error}")),
                want,
                "{shim:?} with a stale handle"
            );
        }
        // Wrong-type: the driver object is never one of the child kinds.
        let wrong_type: [(DriverShim, [u64; 5]); 18] = [
            (DriverShim::WdfInterruptQueueDpcForIsr, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfInterruptAcquireLock, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfInterruptSynchronize, [driver, stub, 0, 0, 0]),
            (
                DriverShim::WdfDmaEnablerCalculateMaximumTransferSize,
                [driver, 0, 0, 0, 0],
            ),
            (DriverShim::WdfDmaTransactionExecute, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfUsbTargetPipeReadPipe, [driver, 0, 0, 8, 0]),
            (
                DriverShim::WdfUsbTargetDeviceGetInformation,
                [driver, 0, 0, 0, 0],
            ),
            (DriverShim::WdfChildListGetChildCount, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfCmResourceListGetCount, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfRequestImpersonate, [driver, 1, 0, 0, 0]),
            (DriverShim::WdfRequestWdmGetIrp, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfRequestSetInformation, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfMemoryCopy, [driver, driver, 8, 0, 0]),
            (DriverShim::WdfMemoryAssign, [driver, 0, 8, 0, 0]),
            (DriverShim::WdfCollectionRemove, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfCollectionGetItem, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfSpinLockRelease, [driver, 0, 0, 0, 0]),
            (DriverShim::WdfTimerStop, [driver, 0, 0, 0, 0]),
        ];
        for (shim, args) in wrong_type {
            assert_eq!(
                call_island_shim(&island, &mut runtime, &mut memory, shim, &args)
                    .unwrap_or_else(|error| panic!("{shim:?} host error: {error}")),
                STATUS_OBJECT_TYPE_MISMATCH,
                "{shim:?} with the driver handle"
            );
        }
        // Request-surface stale handles that use explicit match arms.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestGetStatus,
                &[dead],
            )
            .expect("get status stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestGetStatus,
                &[driver],
            )
            .expect("get status wrong type"),
            STATUS_OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestMarkCancelable,
                &[dead, stub],
            )
            .expect("mark cancelable stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestUnmarkCancelable,
                &[dead],
            )
            .expect("unmark cancelable stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForRead,
                &[dead, 0, 0, 0x10, 0],
            )
            .expect("format read stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[dead, 1],
            )
            .expect("stop idle stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceResumeIdle,
                &[dead],
            )
            .expect("resume idle stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[dead, 0],
            )
            .expect("forward stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemFlush,
                &[dead],
            )
            .expect("flush stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerStart,
                &[dead, 0, 0],
            )
            .expect("timer start stale"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[dead, 0],
            )
            .expect("enqueue stale device"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPowerPolicyOwnership,
                &[dead, 1],
            )
            .expect("policy ownership stale init"),
            STATUS_INVALID_PARAMETER
        );
    });
}

/// Null output pointers and null objects are rejected with the exact
/// status across the new create paths.
#[test]
fn kmdf_null_output_pointers_reject_exact_status() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfN");
        let device = island.kmdf_device_handles()[0];
        let stub = {
            let counter = arena_counter(&mut memory, &island);
            x64_marker_stub(&mut memory, &island, counter)
        };
        // A mapped-but-untouched config block for the create shims.
        let config = 0x44_000;
        memory.map_bytes(config, &[0_u8; 0x40]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, 0],
            )
            .expect("collection null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfLookasideListCreate,
                &[0, 0, 0x40, 0, 0],
            )
            .expect("lookaside null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfMemoryCreateFromLookaside,
                &[0, 0, 0],
            )
            .expect("lookaside memory null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, 0, 0],
            )
            .expect("interrupt null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, 0],
            )
            .expect("dma enabler null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, 0],
            )
            .expect("usb null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, 0, 3, 0],
            )
            .expect("registry null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, 0, 3, 0],
            )
            .expect("registry create null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[device, 0, 0, 0],
            )
            .expect("child list null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetFirst,
                &[0, 0],
            )
            .expect("iterator null out"),
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCmResourceListCreate,
                &[0, 1, 0],
            )
            .expect("cm list null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreateFromIrp,
                &[0, 0, 0],
            )
            .expect("request from irp null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerCreate,
                &[0, 0, 0],
            )
            .expect("timer null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemCreate,
                &[0, 0, 0],
            )
            .expect("work item null out"),
            STATUS_INVALID_PARAMETER
        );
        // Adding a NULL object to a collection is an invalid parameter.
        let collection_out = 0x44_100;
        memory.map_bytes(collection_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionCreate,
                &[0, 0, collection_out],
            )
            .expect("collection create"),
            STATUS_SUCCESS
        );
        let collection = memory.read_u64(collection_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[collection, 0],
            )
            .expect("add null object"),
            STATUS_INVALID_PARAMETER
        );
        // A DMA transaction with a null output pointer fails after the
        // enabler validates: use a valid enabler.
        memory.write_u32(config, 0x10);
        memory.write_u32(config + 4, 0);
        memory.write_u64(config + 8, 0x2_0000);
        let enabler_out = 0x44_110;
        memory.map_bytes(enabler_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, enabler_out],
            )
            .expect("dma enabler create"),
            STATUS_SUCCESS
        );
        let enabler = memory.read_u64(enabler_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionCreate,
                &[enabler, 0, 0],
            )
            .expect("transaction null out"),
            STATUS_INVALID_PARAMETER
        );
        // A child list with a null enumerate callback pointer is
        // rejected before any output write.
        memory.write_u32(config, 8);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[device, 0, config, collection_out],
            )
            .expect("child list without callback"),
            STATUS_INVALID_PARAMETER
        );
        // WdfDeviceInitSetPowerPolicyOwnership: valid init flips the
        // owner flag; a stale init fails.
        let init = *island
            .inner
            .borrow()
            .kmdf
            .device_inits
            .keys()
            .next()
            .expect("device init");
        // Null output pointer on the spin-lock create.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfSpinLockCreate,
                &[0, 0],
            )
            .expect("spin lock null out"),
            STATUS_INVALID_PARAMETER
        );
        // An unmapped timer/work-item config block fails its size probe.
        let out = 0x44_120;
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerCreate,
                &[0x1, 0, out],
            )
            .expect("timer unmapped config"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemCreate,
                &[0x1, 0, out],
            )
            .expect("work item unmapped config"),
            STATUS_INVALID_PARAMETER
        );
        // A config whose Size is below the minimum is rejected.
        let tiny_config = 0x44_130;
        memory.map_bytes(tiny_config, &[0_u8; 0x18]);
        memory.write_u32(tiny_config, 4);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemCreate,
                &[tiny_config, 0, out],
            )
            .expect("work item short size"),
            STATUS_INVALID_PARAMETER
        );
        // A sized config with a null callback is rejected.
        let bare_config = 0x44_140;
        memory.map_bytes(bare_config, &[0_u8; 0x18]);
        memory.write_u32(bare_config, 0x18);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemCreate,
                &[bare_config, 0, out],
            )
            .expect("work item without callback"),
            STATUS_INVALID_PARAMETER
        );
        // A timer with a null due-time pointer fails before arming.
        memory.write_u64(bare_config + 8, stub);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerCreate,
                &[bare_config, 0, out],
            )
            .expect("timer create"),
            STATUS_SUCCESS
        );
        let timer = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerStart,
                &[timer, 0],
            )
            .expect("timer start null due"),
            STATUS_INVALID_PARAMETER
        );
        // Idle references on a device that never started fail on state.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[device, 1],
            )
            .expect("stop idle unstarted"),
            STATUS_INVALID_DEVICE_STATE
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceResumeIdle,
                &[device],
            )
            .expect("resume idle unstarted"),
            STATUS_INVALID_DEVICE_STATE
        );
        // Format-for-read with an offset past the descriptor length is
        // rejected, and marking a request cancelable without a callback
        // is rejected.
        let request_out = 0x44_160;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        let descriptor = 0x44_180;
        write_descriptor(&mut memory, descriptor, 0x44_1A0, 4);
        memory.map_bytes(0x44_1A0, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForRead,
                &[request, 0, descriptor, 8, 0],
            )
            .expect("format offset past end"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestMarkCancelable,
                &[request, 0],
            )
            .expect("mark without callback"),
            STATUS_INVALID_PARAMETER
        );
        // An unmapped file-object out pointer fails the format probe.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForRead,
                &[request, 0, descriptor, 0, 1],
            )
            .expect("format with unmapped file out"),
            STATUS_INVALID_PARAMETER
        );
        // A request owned by the current dispatch reports PENDING.
        island.inner.borrow_mut().kmdf.current_request = request;
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestGetStatus,
                &[request],
            )
            .expect("status of in-flight request"),
            STATUS_PENDING as u64
        );
        island.inner.borrow_mut().kmdf.current_request = 0;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPowerPolicyOwnership,
                &[init, 1],
            )
            .expect("policy owner on"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitSetPowerPolicyOwnership,
                &[init, 0],
            )
            .expect("policy owner off"),
            STATUS_SUCCESS
        );
        assert_eq!(
            { island.inner.borrow().kmdf.device_inits[&init].power_policy_owner },
            false
        );
        let _ = stub;
    });
}

/// `WdfRegistryCreateKey` resolves parents case-insensitively, creates
/// the leaf, and rejects every invalid path shape.
#[test]
fn kmdf_registry_create_key_and_invalid_paths_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfK");
        let key_out = 0x45_000;
        memory.map_bytes(key_out, &[0_u8; 8]);
        let absolute = guest_unicode_string(
            &mut memory,
            0x45_100,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfK\\CoverageLeaf",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, absolute, 3, key_out],
            )
            .expect("create absolute leaf"),
            STATUS_SUCCESS
        );
        let leaf = memory.read_u64(key_out).unwrap();
        {
            let state = island.inner.borrow();
            let record = state
                .kmdf
                .registry_keys
                .get(&leaf)
                .expect("leaf key record");
            assert_eq!(
                record.path, "SYSTEM\\CurrentControlSet\\Services\\CasaKmdfK\\CoverageLeaf",
                "parents keep their stored case and the leaf keeps guest case"
            );
            assert_eq!(record.access, 3);
        }
        // Relative create under an open parent key.
        let relative = guest_unicode_string(&mut memory, 0x45_300, "RelativeLeaf");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[leaf, relative, 3, key_out],
            )
            .expect("create relative leaf"),
            STATUS_SUCCESS
        );
        let rel = memory.read_u64(key_out).unwrap();
        assert_eq!(
            {
                let state = island.inner.borrow();
                state.kmdf.registry_keys[&rel].path.clone()
            },
            "SYSTEM\\CurrentControlSet\\Services\\CasaKmdfK\\CoverageLeaf\\RelativeLeaf"
        );
        // A relative open of the new child resolves.
        let open_out = 0x45_440;
        memory.map_bytes(open_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[leaf, relative, 1, open_out],
            )
            .expect("open relative child"),
            STATUS_SUCCESS
        );
        // A relative open of a missing child fails.
        let missing = guest_unicode_string(&mut memory, 0x45_500, "NopeChild");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[leaf, missing, 1, open_out],
            )
            .expect("open missing child"),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        // Non-`\Registry\Machine\` absolute names are rejected.
        let user_path = guest_unicode_string(&mut memory, 0x45_700, "\\Registry\\User\\.Default");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, user_path, 3, key_out],
            )
            .expect("create under user hive"),
            STATUS_OBJECT_PATH_INVALID
        );
        // A relative name without a parent handle is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, relative, 3, key_out],
            )
            .expect("relative without parent"),
            STATUS_OBJECT_PATH_INVALID
        );
        // A relative name with a stale parent handle is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0xDEAD_BEEF, relative, 3, key_out],
            )
            .expect("relative with stale parent"),
            STATUS_INVALID_HANDLE
        );
        // An absolute open whose parent is stale fails on the name
        // shape first only for relative paths; here parent=0 and the
        // walk finds nothing more.
        let deep = guest_unicode_string(
            &mut memory,
            0x45_900,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaMissingKeyX\\Child",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, deep, 3, key_out],
            )
            .expect("open missing service"),
            STATUS_OBJECT_NAME_NOT_FOUND
        );
        // A relative open without a parent handle is rejected before
        // any walk.
        let rel_only = guest_unicode_string(&mut memory, 0x45_B00, "RelativeLeaf");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, rel_only, 1, key_out],
            )
            .expect("relative open without parent"),
            STATUS_OBJECT_PATH_INVALID
        );
        // Querying through a stale key handle fails.
        let value_name2 = guest_unicode_string(&mut memory, 0x45_D00, "ImagePath");
        let buffer2 = 0x45_F00;
        memory.map_bytes(buffer2, &vec![0_u8; 0x40]);
        let length_out2 = 0x46_100;
        memory.map_bytes(length_out2, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[0xDEAD_BEEF, value_name2, buffer2, 0x40, length_out2, 0],
            )
            .expect("query with stale key"),
            STATUS_INVALID_HANDLE
        );
        // A REG_QWORD assign writes eight bytes and reads back with
        // its exact type; a null data pointer is rejected first.
        let qword_name = guest_unicode_string(&mut memory, 0x46_300, "TestQword");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryAssignValue,
                &[leaf, qword_name, 11, 0, 8],
            )
            .expect("qword with null data"),
            STATUS_INVALID_PARAMETER
        );
        memory.map_bytes(0x46_500, &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryAssignValue,
                &[leaf, qword_name, 11, 0x46_500, 8],
            )
            .expect("assign qword"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[leaf, qword_name, buffer2, 0x40, length_out2, 0],
            )
            .expect("query qword"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u64(length_out2).unwrap(), 8);
        // A root-level key under \Registry\Machine resolves with an
        // empty parent prefix.
        let root = guest_unicode_string(&mut memory, 0x46_700, "\\Registry\\Machine\\CasaRootLeaf");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, root, 3, key_out],
            )
            .expect("root-level create"),
            STATUS_SUCCESS
        );
        assert_eq!(
            {
                let state = island.inner.borrow();
                state.kmdf.registry_keys[&memory.read_u64(key_out).unwrap()]
                    .path
                    .clone()
            },
            "CasaRootLeaf"
        );
        // Open edge cases: stale parent, machine-root path without a
        // key, empty segments, and an empty name.
        let stale_open = guest_unicode_string(&mut memory, 0x46_900, "RelativeLeaf");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0xDEAD_BEEF, stale_open, 1, key_out],
            )
            .expect("open with stale parent"),
            STATUS_INVALID_HANDLE
        );
        let machine_root = guest_unicode_string(&mut memory, 0x46_B00, "\\Registry\\Machine\\");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, machine_root, 1, key_out],
            )
            .expect("open machine root with empty key"),
            STATUS_OBJECT_PATH_INVALID
        );
        let double_slash = guest_unicode_string(
            &mut memory,
            0x46_D00,
            "\\Registry\\Machine\\System\\\\Broken",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, double_slash, 1, key_out],
            )
            .expect("open with empty path segment"),
            STATUS_OBJECT_PATH_INVALID
        );
        let empty_name = guest_unicode_string(&mut memory, 0x46_F00, "");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, empty_name, 1, key_out],
            )
            .expect("open empty name"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, empty_name, 3, key_out],
            )
            .expect("create empty name"),
            STATUS_INVALID_PARAMETER
        );
        let create_double = guest_unicode_string(
            &mut memory,
            0x47_100,
            "\\Registry\\Machine\\System\\\\Create",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, create_double, 3, key_out],
            )
            .expect("create with empty segment"),
            STATUS_OBJECT_PATH_INVALID
        );
        let missing_parent = guest_unicode_string(
            &mut memory,
            0x47_300,
            "\\Registry\\Machine\\NoSuchParent\\Leaf",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryCreateKey,
                &[0, missing_parent, 3, key_out],
            )
            .expect("create under missing parent"),
            STATUS_OBJECT_PATH_INVALID
        );
        // A null query buffer fails after the required length is
        // reported.
        let query_name = guest_unicode_string(&mut memory, 0x46_A00, "TestQword");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[leaf, query_name, 0, 0x40, length_out2, 0],
            )
            .expect("query with null buffer"),
            STATUS_INVALID_PARAMETER
        );
        // Writing through a stale key fails; a read-only key cannot
        // delete values either.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryAssignValue,
                &[0xDEAD_BEEF, qword_name, 11, 0x46_500, 8],
            )
            .expect("assign with stale key"),
            STATUS_INVALID_HANDLE
        );
        let readonly_path = guest_unicode_string(
            &mut memory,
            0x47_900,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaKmdfK",
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryOpenKey,
                &[0, readonly_path, 1, key_out],
            )
            .expect("open read-only for delete"),
            STATUS_SUCCESS
        );
        let readonly2 = memory.read_u64(key_out).unwrap();
        let any_value = guest_unicode_string(&mut memory, 0x47_B00, "Whatever");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryDeleteValue,
                &[readonly2, any_value],
            )
            .expect("delete from read-only key"),
            STATUS_ACCESS_DENIED
        );
        // A REG_MULTI_SZ stored in a shape the decoder cannot convert
        // fails the query exactly.
        runtime
            .win32
            .ge()
            .registry_set_value(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\CasaKmdfK\\CoverageLeaf",
                "BadMulti",
                "REG_MULTI_SZ",
                serde_json::json!("not-an-array"),
                RegistryView::Native,
            )
            .expect("plant mismatched multi-sz");
        let bad_multi = guest_unicode_string(&mut memory, 0x47_500, "BadMulti");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRegistryQueryValue,
                &[leaf, bad_multi, buffer2, 0x40, length_out2, 0],
            )
            .expect("query mismatched multi-sz"),
            STATUS_INVALID_PARAMETER
        );
        // A child list whose config block is unmapped fails the probe.
        let child_out = 0x47_710;
        memory.map_bytes(child_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[island.kmdf_device_handles()[0], 0, 0x1, child_out],
            )
            .expect("child list unmapped config"),
            STATUS_INVALID_PARAMETER
        );
    });
}

/// Interrupt config edge cases: missing Size room, no DPC, and a
/// vector collision at connect time.
#[test]
fn kmdf_interrupt_config_edges_and_vector_collision_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, mut island) =
            load_staged_island_x64(&image, "CasaKmdfE");
        let device = island.kmdf_device_handles()[0];
        let counter = arena_counter(&mut memory, &island);
        let isr = x64_claiming_isr_stub(&mut memory, &island, counter);
        let config = 0x46_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        let out = 0x46_100;
        memory.map_bytes(out, &[0_u8; 8]);
        // Null config: no ISR at all.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, 0, out],
            )
            .expect("null config"),
            STATUS_INVALID_PARAMETER
        );
        // An unmapped config block fails its first probe.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, 0x1, out],
            )
            .expect("unmapped config"),
            STATUS_INVALID_PARAMETER
        );
        // Size too small to hold the ISR pointer: skipped, no ISR.
        memory.write_u32(config, 4);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, out],
            )
            .expect("tiny size"),
            STATUS_INVALID_PARAMETER
        );
        // Size room for the ISR but not the DPC: create succeeds and
        // queueing the DPC fails because none was configured.
        memory.write_u32(config, 0x10);
        memory.write_u64(config + 8, isr);
        memory.write_u64(config + 16, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, out],
            )
            .expect("isr without dpc"),
            STATUS_SUCCESS
        );
        let bare = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptQueueDpcForIsr,
                &[bare],
            )
            .expect("queue dpc without config"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // A WDM interrupt holding vector 0x30 makes the KMDF connect
        // fail: the handle must not leak.
        let connect_out = 0x46_200;
        memory.map_bytes(connect_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::IoConnectInterrupt,
                &[connect_out, isr, 0, 0, 0x31, 3, 3, 0, 0, 1, 0],
            )
            .expect("wdm connect"),
            STATUS_SUCCESS
        );
        memory.write_u32(config, 0x18);
        memory.write_u64(config + 16, 0);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, out],
            )
            .expect("colliding kmDF interrupt"),
            STATUS_OBJECT_NAME_COLLISION
        );
        {
            let state = island.inner.borrow();
            assert_eq!(
                state.kmdf.interrupts.len(),
                1,
                "a failed connect does not leak the interrupt handle"
            );
        }
        // Synchronize with an explicit non-zero context argument.
        let sync = x64_marker_stub(&mut memory, &island, counter);
        memory.write_u64(config, 0);
        memory.write_u32(config, 0x18);
        memory.write_u64(config + 8, isr);
        memory.write_u64(config + 16, sync);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, out],
            )
            .expect("second interrupt"),
            STATUS_SUCCESS
        );
        let second = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptSynchronize,
                &[second, sync, 0x46_300],
            )
            .expect("sync with explicit context"),
            1
        );
        // Deleting the interrupt disconnects it from the virtual
        // controller.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[second],
            )
            .expect("delete interrupt"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(!state.kmdf.interrupts.contains_key(&second));
        }
        let _ = &mut island;
    });
}

/// DMA profile matrix: config validation failures, Long/ScatterGather
/// caps, segment accounting, and phase guards.
#[test]
fn kmdf_dma_profiles_and_phase_guards_reject_exact_status() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfF");
        let device = island.kmdf_device_handles()[0];
        let config = 0x47_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        let out = 0x47_100;
        memory.map_bytes(out, &[0_u8; 8]);
        // An unmapped config pointer is rejected before any read.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, 0x1, out],
            )
            .expect("unmapped config"),
            STATUS_INVALID_PARAMETER
        );
        // A Size below the config header minimum is rejected.
        memory.write_u32(config, 8);
        memory.write_u32(config + 4, 0);
        memory.write_u64(config + 8, 0x2_0000);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, out],
            )
            .expect("short size"),
            STATUS_INVALID_PARAMETER
        );
        // Long profile: the reported maximum is the configured length.
        memory.write_u32(config, 0x10);
        memory.write_u32(config + 4, 1);
        memory.write_u64(config + 8, 0x40_0000);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, out],
            )
            .expect("long enabler"),
            STATUS_SUCCESS
        );
        let long = memory.read_u64(out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCalculateMaximumTransferSize,
                &[long],
            )
            .expect("long max"),
            0x40_0000,
            "Long profile reports the configured maximum verbatim"
        );
        // Scatter/Gather: multi-segment transfers report ceil(len/64K).
        memory.write_u32(config + 4, 2);
        memory.write_u64(config + 8, 0x2_0000);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, out],
            )
            .expect("scatter gather enabler"),
            STATUS_SUCCESS
        );
        let sg = memory.read_u64(out).unwrap();
        let txn_out = 0x47_200;
        memory.map_bytes(txn_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionCreate,
                &[sg, 0, txn_out],
            )
            .expect("sg transaction"),
            STATUS_SUCCESS
        );
        let txn = memory.read_u64(txn_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[txn, 0, 0, 0x1_8000, 0],
            )
            .expect("sg initialize"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let record = state.kmdf.dma_transactions.get(&txn).expect("transaction");
            assert_eq!(record.segments, 2, "96 KB needs two 64 KB segments");
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionExecute,
                &[txn],
            )
            .expect("sg execute"),
            STATUS_SUCCESS
        );
        // Re-initializing an executed transaction fails on phase.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaTransactionInitialize,
                &[txn, 0, 0, 0x1000, 0],
            )
            .expect("re-init executed"),
            STATUS_INVALID_DEVICE_STATE
        );
    });
}

/// USB creation validation matrix plus transfer edges (zero length,
/// oversize, request Information reporting, and the control pipe type).
#[test]
fn kmdf_usb_descriptor_validation_and_transfer_edges_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfG");
        let device = island.kmdf_device_handles()[0];
        let config = 0x48_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        let out = 0x48_100;
        memory.map_bytes(out, &[0_u8; 8]);
        // Unmapped config block.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, 0x1, out],
            )
            .expect("unmapped config"),
            STATUS_INVALID_PARAMETER
        );
        // Size below the header minimum.
        memory.write_u32(config, 8);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("short size"),
            STATUS_INVALID_PARAMETER
        );
        // Size fits the header but not the descriptor pointer: no
        // endpoints are parsed, so the device cannot be created.
        memory.write_u32(config, 0x10);
        memory.write_u16(config + 4, 0x0200);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("no descriptor pointer"),
            STATUS_INVALID_DEVICE_STATE
        );
        // Null config: no endpoints either.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, 0, out],
            )
            .expect("null config"),
            STATUS_INVALID_DEVICE_STATE
        );
        // A descriptor pointer outside guest memory is rejected by the
        // parser's first validation.
        memory.write_u32(config, 0x18);
        memory.write_u64(config + 16, 0xF000);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("unmapped descriptor"),
            STATUS_INVALID_PARAMETER
        );
        // A short interface descriptor is rejected.
        let descriptor = 0x48_400;
        memory.map_bytes(descriptor, &vec![0_u8; 0x100]);
        memory.write_u8(descriptor, 9);
        memory.write_u8(descriptor + 1, 2);
        memory.write_u16(descriptor + 2, 20);
        memory.write_u8(descriptor + 4, 1);
        memory.write_u8(descriptor + 9, 5); // interface bLength = 5
        memory.write_u8(descriptor + 10, 4);
        memory.write_u64(config + 16, descriptor);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("short interface"),
            STATUS_INVALID_PARAMETER
        );
        // A short endpoint descriptor is rejected.
        memory.write_u8(descriptor + 9, 9);
        memory.write_u8(descriptor + 18, 5); // endpoint bLength = 5
        memory.write_u8(descriptor + 19, 5);
        memory.write_u16(descriptor + 2, 24);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("short endpoint"),
            STATUS_INVALID_PARAMETER
        );
        // More than sixteen endpoints are rejected.
        memory.write_u16(descriptor + 2, 9 + 9 + 17 * 7);
        memory.write_u8(descriptor + 18, 7);
        memory.write_u8(descriptor + 19, 5);
        memory.write_u8(descriptor + 20, 0x81);
        memory.write_u8(descriptor + 21, 0x02);
        memory.write_u16(descriptor + 22, 64);
        for index in 0..17u64 {
            let base = descriptor + 25 + index * 7;
            memory.write_u8(base, 7);
            memory.write_u8(base + 1, 5);
            memory.write_u8(base + 2, 0x02 | ((index as u8 + 1) << 4));
            memory.write_u8(base + 3, 0x02);
            memory.write_u16(base + 4, 64);
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("too many endpoints"),
            STATUS_INVALID_PARAMETER
        );
        // An unknown descriptor type is skipped without failing.
        memory.write_u16(descriptor + 2, 9 + 9 + 7 + 4);
        memory.write_u8(descriptor + 18, 4); // extra record length
        memory.write_u8(descriptor + 19, 0x21); // unknown type
        memory.write_u8(descriptor + 22, 7);
        memory.write_u8(descriptor + 23, 5);
        memory.write_u8(descriptor + 24, 0x81);
        memory.write_u8(descriptor + 25, 0x02);
        memory.write_u16(descriptor + 26, 512);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("unknown descriptor type skipped"),
            STATUS_SUCCESS
        );
        // Two more parser edges: a zero-length descriptor record and a
        // wTotalLength that overruns the actual content.
        memory.write_u16(descriptor + 2, 9 + 9 + 7);
        memory.write_u8(descriptor + 18, 7);
        memory.write_u8(descriptor + 19, 5);
        memory.write_u8(descriptor + 20, 0x81);
        memory.write_u8(descriptor + 21, 0x02);
        memory.write_u16(descriptor + 22, 512);
        memory.write_u8(descriptor + 25, 1); // endpoint bLength = 1
        memory.write_u8(descriptor + 26, 5);
        memory.write_u16(descriptor + 2, 40);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("zero-length descriptor record"),
            STATUS_INVALID_PARAMETER
        );
        memory.write_u8(descriptor + 25, 7);
        memory.write_u16(descriptor + 2, 30); // content ends at 25 < 30
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("wTotalLength overruns content"),
            STATUS_INVALID_PARAMETER
        );
        // A wTotalLength that runs past the mapped window is rejected
        // by the region probe even though the header itself is valid.
        let near_edge = 0x5F_FE0;
        memory.map_bytes(near_edge, &[0_u8; 0x20]);
        memory.write_u8(near_edge, 9);
        memory.write_u8(near_edge + 1, 2);
        memory.write_u16(near_edge + 2, 0x200);
        memory.write_u64(config + 16, near_edge);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("wTotalLength past mapped window"),
            STATUS_INVALID_PARAMETER
        );
        // A config header with wTotalLength below its own size is
        // rejected before any walk.
        memory.write_u64(config + 16, descriptor);
        memory.write_u16(descriptor + 2, 5);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("wTotalLength below header"),
            STATUS_INVALID_PARAMETER
        );
        // Four typed endpoints: control OUT, bulk IN, isochronous,
        // interrupt.
        memory.write_u16(descriptor + 2, 9 + 9 + 4 * 7);
        let endpoints = [(0x03u8, 0x00u8), (0x81, 0x02), (0x05, 0x01), (0x07, 0x03)];
        for (index, (address, attributes)) in endpoints.iter().enumerate() {
            let base = descriptor + 18 + index as u64 * 7;
            memory.write_u8(base, 7);
            memory.write_u8(base + 1, 5);
            memory.write_u8(base + 2, *address);
            memory.write_u8(base + 3, *attributes);
            memory.write_u16(base + 4, 64);
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, config, out],
            )
            .expect("control endpoint device"),
            STATUS_SUCCESS
        );
        let usb = memory.read_u64(out).unwrap();
        let pipe_out = 0x48_200;
        memory.map_bytes(pipe_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                &[usb, 0, pipe_out, 0],
            )
            .expect("control pipe"),
            STATUS_SUCCESS
        );
        let pipe = memory.read_u64(pipe_out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeGetType,
                &[pipe],
            )
            .expect("control pipe type"),
            1,
            "bmAttributes 0 reports Control"
        );
        // A null pipe out pointer is rejected; the remaining typed
        // endpoints resolve and report their exact pipe types.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                &[usb, 0, 0, 0],
            )
            .expect("pipe null out"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceGetInformation,
                &[usb, 0],
            )
            .expect("info null out"),
            STATUS_INVALID_PARAMETER
        );
        let type_expect = [(1u64, 3u64), (2, 2), (3, 4)];
        for (index, expected) in type_expect {
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                    &[usb, index, pipe_out, 0],
                )
                .expect("typed pipe"),
                STATUS_SUCCESS
            );
            let typed = memory.read_u64(pipe_out).unwrap();
            assert_eq!(
                call_island_shim_raw(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfUsbTargetPipeGetType,
                    &[typed],
                )
                .expect("typed pipe type"),
                expected
            );
        }
        // The bulk IN pipe drains staged device data and zero-fills a
        // short read.
        let in_pipe = {
            assert_eq!(
                call_island_shim(
                    &island,
                    &mut runtime,
                    &mut memory,
                    DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                    &[usb, 1, pipe_out, 0],
                )
                .expect("bulk in pipe"),
                STATUS_SUCCESS
            );
            memory.read_u64(pipe_out).unwrap()
        };
        assert!(island.kmdf_usb_stage_in_for_test(in_pipe, &[0xA1, 0xB2, 0xC3]));
        let read_buffer = 0x48_360;
        memory.map_bytes(read_buffer, &vec![0xFF_u8; 0x10]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeReadPipe,
                &[in_pipe, 0, read_buffer, 8],
            )
            .expect("staged read"),
            STATUS_SUCCESS
        );
        assert_eq!(memory.read_u8(read_buffer).unwrap(), 0xA1);
        assert_eq!(memory.read_u8(read_buffer + 2).unwrap(), 0xC3);
        assert_eq!(
            memory.read_u8(read_buffer + 3).unwrap(),
            0,
            "a short device packet zero-fills the rest"
        );
        // A null transfer buffer fails after the length checks.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[pipe, 0, 0, 8],
            )
            .expect("null transfer buffer"),
            STATUS_INVALID_PARAMETER
        );
        // Zero-length and oversize transfers are rejected before any
        // buffer validation.
        let buffer = 0x48_300;
        memory.map_bytes(buffer, &vec![0_u8; 0x40]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[pipe, 0, buffer, 0],
            )
            .expect("zero length"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[pipe, 0, buffer, 0x2_0000],
            )
            .expect("oversize"),
            STATUS_INVALID_PARAMETER
        );
        // A transfer bound to a live request reports the transferred
        // length through `Information`; completing the request first
        // leaves `Information` alone.
        let request_out = 0x48_210;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[pipe, request, buffer, 0x10],
            )
            .expect("write with request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_request_state(request).expect("request").2,
            0x10,
            "the transfer length lands in Information"
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[request, STATUS_SUCCESS as u64],
            )
            .expect("complete"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_request_state(request).expect("request").2,
            0,
            "completion rewrites Information with its own value"
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetPipeWritePipe,
                &[pipe, request, buffer, 8],
            )
            .expect("write on completed request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_request_state(request).expect("request").2,
            0,
            "a completed request keeps its frozen Information"
        );
        // Reference one pipe first: the child cascade defers it, so the
        // target's own removal block sweeps the pipe map itself.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectReference,
                &[in_pipe],
            )
            .expect("reference pipe"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[usb],
            )
            .expect("delete usb target"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(!state.kmdf.usb_targets.contains_key(&usb));
            assert!(
                !state.kmdf.usb_pipes.contains_key(&in_pipe),
                "the target's own removal block swept the deferred pipe"
            );
            assert!(
                state.kmdf.objects.contains_key(&in_pipe),
                "the referenced pipe defers its destruction"
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDereference,
                &[in_pipe],
            )
            .expect("release pipe reference"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert!(
                !state.kmdf.objects.contains_key(&in_pipe),
                "the pipe completes its deferred delete"
            );
        }
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbInterfaceGetConfiguredPipe,
                &[usb, 0, pipe_out, 0],
            )
            .expect("pipe after target delete"),
            STATUS_INVALID_HANDLE
        );
    });
}

/// Child-list scan edges: dead list handles, a missing scan collection,
/// and a PnP arrival whose PDO name collides with a live device.
#[test]
fn kmdf_child_scan_dead_handles_and_pdo_collision_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfJ");
        let device = island.kmdf_device_handles()[0];
        let enumerate_counter = arena_counter(&mut memory, &island);
        let enumerate = x64_marker_stub(&mut memory, &island, enumerate_counter);
        let config = 0x49_000;
        memory.map_bytes(config, &[0_u8; 0x10]);
        memory.write_u32(config, 0x10);
        memory.write_u64(config + 8, enumerate);
        let list_out = 0x49_100;
        memory.map_bytes(list_out, &[0_u8; 8]);
        // A child list on a non-device handle is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[island.kmdf_driver_handle(), 0, config, list_out],
            )
            .expect("child list on driver"),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[device, 0, config, list_out],
            )
            .expect("child list create"),
            STATUS_SUCCESS
        );
        let list = memory.read_u64(list_out).unwrap();
        // Pre-create the PDO name an arrival of description 0xD1 would
        // claim; the scan must abort with the collision status.
        let colliding_init = *island
            .inner
            .borrow()
            .kmdf
            .device_inits
            .keys()
            .next()
            .expect("device init");
        let colliding_name = guest_unicode_string(&mut memory, 0x49_300, "\\Device\\CasaChildD1");
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceInitAssignName,
                &[colliding_init, colliding_name],
            )
            .expect("assign colliding name"),
            STATUS_SUCCESS
        );
        let collide_out = 0x49_500;
        memory.map_bytes(collide_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceCreate,
                &[colliding_init, 0, collide_out],
            )
            .expect("colliding device"),
            STATUS_SUCCESS
        );
        // A null iterator out pointer on a live list is rejected.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetFirst,
                &[list, 0],
            )
            .expect("iterator null out"),
            STATUS_INVALID_PARAMETER
        );
        // Iteration writes the description through the out pointer.
        let desc_out = 0x49_210;
        memory.map_bytes(desc_out, &[0_u8; 8]);
        let iter_out = 0x49_218;
        memory.map_bytes(iter_out, &[0_u8; 8]);
        {
            // Seed one description without a scan: a collection that
            // is not attached to any parent exercises the scan's
            // parentless-collection path.
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            let collection = state
                .create_kmdf_object(&mut memory, KmdfObjectKind::Collection, 0)
                .expect("parentless collection");
            assert!(
                state.kmdf.objects[&collection].parent.is_none(),
                "the seed collection has no parent"
            );
            state.kmdf.collections.insert(
                collection,
                KmdfCollection {
                    items: vec![0xD3],
                    max_size: 1024,
                },
            );
            state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan { list, collection },
                    STATUS_SUCCESS,
                )
                .expect("parentless collection scan");
        }
        // The seeded arrival failed (no EvtChildListEnumerateChildren
        // produced it through the guest path) only if the list saw the
        // change; the diff recorded it either way.
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetChildCount,
                &[list],
            )
            .expect("count after parentless seed"),
            1
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetFirst,
                &[list, iter_out],
            )
            .expect("iterator over seeded child"),
            STATUS_SUCCESS
        );
        let seeded_iter = memory.read_u64(iter_out).unwrap();
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetNext,
                &[seeded_iter, desc_out],
            )
            .expect("seeded child next"),
            1
        );
        assert_eq!(memory.read_u64(desc_out).unwrap(), 0xD3);
        // Drop the seeded child again so the dead-list phases below see
        // an empty list.
        {
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            let empty = state
                .create_kmdf_object(&mut memory, KmdfObjectKind::Collection, 0)
                .expect("empty collection");
            state.kmdf.collections.insert(
                empty,
                KmdfCollection {
                    items: Vec::new(),
                    max_size: 1024,
                },
            );
            state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan {
                        list,
                        collection: empty,
                    },
                    STATUS_SUCCESS,
                )
                .expect("drop seeded child");
        }
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetChildCount,
                &[list],
            )
            .expect("count after drop"),
            0
        );
        // A description that never materialized a child device is
        // removed without any device teardown to run.
        {
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            let collection = state
                .create_kmdf_object(&mut memory, KmdfObjectKind::Collection, 0)
                .expect("phantom collection");
            state.kmdf.collections.insert(
                collection,
                KmdfCollection {
                    items: vec![0xDA, 0xDB],
                    max_size: 1024,
                },
            );
            // Seed one description directly (no PDO) and one as a
            // materialized child so both removal branches run.
            if let Some(record) = state.kmdf.child_lists.get_mut(&list) {
                record.descriptions = vec![0xDA, 0xDB];
            }
            let child_collection = state
                .create_kmdf_object(&mut memory, KmdfObjectKind::Collection, 0)
                .expect("child collection");
            state.kmdf.collections.insert(
                child_collection,
                KmdfCollection {
                    items: Vec::new(),
                    max_size: 1024,
                },
            );
            let materialized = state
                .create_kmdf_child_pdo(&mut memory, list, 0xDB)
                .expect("materialize child")
                .expect("materialize succeeds");
            state.kmdf.child_devices.insert(0xDB, materialized);
            state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan {
                        list,
                        collection: child_collection,
                    },
                    STATUS_SUCCESS,
                )
                .expect("remove phantom and materialized child");
        }
        {
            let state = island.inner.borrow();
            assert!(!state.kmdf.child_devices.contains_key(&0xDB));
            assert!(!state.kmdf.child_lists[&list].descriptions.contains(&0xDA));
        }
        // Each scan completion consumes its temporary collection, so
        // every phase builds a fresh one.  Dead list first: the diff
        // reports no changes.
        let collection_out = 0x49_200;
        memory.map_bytes(collection_out, &[0_u8; 8]);
        macro_rules! new_collection {
            () => {{
                assert_eq!(
                    call_island_shim(
                        &island,
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfCollectionCreate,
                        &[0, 0, collection_out],
                    )
                    .expect("scan collection"),
                    STATUS_SUCCESS
                );
                memory.read_u64(collection_out).unwrap()
            }};
        }
        let dead_collection = new_collection!();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[dead_collection, 0xD1],
            )
            .expect("add description"),
            STATUS_SUCCESS
        );
        {
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan {
                        list: 0xDEAD_0001,
                        collection: dead_collection,
                    },
                    STATUS_SUCCESS,
                )
                .expect("dead list scan");
            assert_eq!(
                cpu.get(Register::Rax) as u32 as i32,
                STATUS_SUCCESS,
                "a dead list reports no changes"
            );
        }
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListGetChildCount,
                &[list],
            )
            .expect("count after dead scan"),
            0
        );
        // The dead-list phase consumed its collection, so this scan
        // sees a collection handle that is not a live framework object
        // and skips the detach step.
        {
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan {
                        list,
                        collection: dead_collection,
                    },
                    STATUS_SUCCESS,
                )
                .expect("missing collection scan");
        }
        // Fresh collection: the arrival of 0xD1 aborts on the name
        // collision.
        let collection = new_collection!();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfCollectionAdd,
                &[collection, 0xD1],
            )
            .expect("add colliding description"),
            STATUS_SUCCESS
        );
        {
            let mut state = island.inner.borrow_mut();
            let mut cpu = CpuState::new(GuestArch::X64);
            state
                .finish_pending(
                    &mut cpu,
                    &mut memory,
                    PendingPurpose::ChildListScan { list, collection },
                    STATUS_SUCCESS,
                )
                .expect("colliding scan");
            assert_eq!(
                cpu.get(Register::Rax) as u32 as i32,
                STATUS_OBJECT_NAME_COLLISION,
                "a colliding child PDO aborts the scan"
            );
        }
        {
            let state = island.inner.borrow();
            assert!(
                state.kmdf.child_devices.is_empty(),
                "the aborted scan inserts no child devices"
            );
            assert_eq!(
                state.kmdf.child_arrivals, 1,
                "only the seeded arrival materialized a child; the aborted scan added none"
            );
        }
    });
}

/// Request edges: impersonation on a completed request, formatted
/// read/write with a live file-object out pointer, and stale queue
/// forwarding.
#[test]
fn kmdf_request_completed_impersonate_and_format_edges_reject() {
    with_big_stack(|| {
        let image = build_kmdf_driver(false, false, false);
        let (mut runtime, _dir, mut memory, island) = load_staged_island_x64(&image, "CasaKmdfT2");
        let device = island.kmdf_device_handles()[0];
        let request_out = 0x4A_000;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        // Impersonating a completed request fails on state; ownership
        // is taken the way an active dispatch would hold it.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[request, STATUS_SUCCESS as u64],
            )
            .expect("complete"),
            STATUS_SUCCESS
        );
        island.inner.borrow_mut().kmdf.current_request = request;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestImpersonate,
                &[request, 2],
            )
            .expect("impersonate completed"),
            STATUS_INVALID_DEVICE_STATE
        );
        // Format-for-read takes a memory descriptor; the read fills
        // the OUTPUT side and reports NULL file objects.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request 2"),
            STATUS_SUCCESS
        );
        let request2 = memory.read_u64(request_out).unwrap();
        let buffer = 0x4A_100;
        memory.map_bytes(buffer, &vec![0_u8; 0x40]);
        let descriptor = 0x4A_300;
        write_descriptor(&mut memory, descriptor, buffer, 0x40);
        let file_out = 0x4A_320;
        memory.map_bytes(file_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForRead,
                &[request2, 0, descriptor, 4, file_out],
            )
            .expect("format read"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let record = state.kmdf.requests.get(&request2).expect("request");
            assert_eq!(record.major, IrpMajorFunction::Read);
            assert_eq!(record.output_guest, buffer + 4);
            assert_eq!(record.output_len, 0x40 - 4);
            assert_eq!(record.input_len, 0);
        }
        assert_eq!(
            memory.read_u64(file_out).unwrap(),
            0,
            "the file-object out pointer reports NULL for a device request"
        );
        // Format-for-write routes the descriptor buffer as the input
        // side.
        let write_desc = 0x4A_340;
        write_descriptor(&mut memory, write_desc, buffer, 0x20);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestFormatRequestForWrite,
                &[request2, 0, write_desc, 0, 0],
            )
            .expect("format write"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            let record = state.kmdf.requests.get(&request2).expect("request");
            assert_eq!(record.major, IrpMajorFunction::Write);
            assert_eq!(record.input_guest, buffer);
            assert_eq!(record.input_len, 0x20);
            assert_eq!(record.output_len, 0);
        }
    });
}

/// Forward-to-queue paths: a power-managed idle queue defers with the
/// power counter, a manual queue defers without it, a live callback
/// queue dispatches, and a callback-less queue rejects.
#[test]
fn kmdf_forward_to_queue_defer_dispatch_and_missing_callback_paths() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, _base, device_object) =
            pnp_load("CasaWdfFwdPower");
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_START_DEVICE,
                )
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        let device = island.inner.borrow().kmdf.devices_by_object[&device_object];
        let config = 0x4B_000;
        memory.map_bytes(config, &[0_u8; 0x40]);
        let queue_out = 0x4B_100;
        memory.map_bytes(queue_out, &[0_u8; 8]);
        let counter = arena_counter(&mut memory, &island);
        let callback = x64_marker_stub(&mut memory, &island, counter);
        // Power-managed queue (PowerManaged field at +0x08).
        memory.write_u32(config, 0x40);
        memory.write_u32(config + 0x04, 0);
        memory.write_u32(config + 0x08, 1);
        memory.write_u64(config + 0x10, callback);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("power-managed queue"),
            STATUS_SUCCESS
        );
        let pm_queue = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[device, 1],
            )
            .expect("stop idle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceResumeIdle,
                &[device],
            )
            .expect("resume into idle"),
            STATUS_SUCCESS
        );
        let defers_before = island.kmdf_counters().2;
        let request_out = 0x4B_200;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request, pm_queue],
            )
            .expect("forward to idle power queue"),
            STATUS_SUCCESS,
            "the forward defers onto the non-ready power queue"
        );
        assert_eq!(
            island.kmdf_counters().2,
            defers_before + 1,
            "the power-managed defer bumps the shared counter"
        );
        {
            let state = island.inner.borrow();
            let queue = state.kmdf.queues.get(&pm_queue).expect("queue");
            assert!(
                queue.queued.contains(&request),
                "the forward deferred while the device was idle"
            );
        }
        // Balancing the idle reference wakes the device through D0
        // entry, which dispatches the deferred request into the
        // callback (the same drain the idle tests pin).
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[device, 1],
            )
            .expect("balance idle"),
            STATUS_PENDING
        );
        {
            let state = island.inner.borrow();
            let queue = state.kmdf.queues.get(&pm_queue).expect("queue");
            assert!(
                !queue.queued.contains(&request),
                "the deferred request left the queue once the device was ready"
            );
        }
        // A manual queue defers without touching the power counter.
        memory.write_u32(config + 0x08, 0);
        memory.write_u32(config + 0x04, 2);
        memory.write_u64(config + 0x10, 0);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("manual queue"),
            STATUS_SUCCESS
        );
        let manual = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request 2"),
            STATUS_SUCCESS
        );
        let request2 = memory.read_u64(request_out).unwrap();
        let defers_before = island.kmdf_counters().2;
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request2, manual],
            )
            .expect("forward to manual queue"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_counters().2,
            defers_before,
            "a manual-queue defer is not a power defer"
        );
        // Forwarding a request back onto the queue it already occupies
        // is rejected instead of enqueueing it twice.
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request2, manual],
            )
            .expect("forward to own queue"),
            STATUS_INVALID_DEVICE_REQUEST
        );
        // Moving the queued request to a different queue sweeps it out
        // of the source queue first; the live destination then dispatches
        // it (the request pends until its callback completes it).
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request2, pm_queue],
            )
            .expect("move between queues"),
            STATUS_SUCCESS,
            "the sweep runs before the destination defers behind its in-flight sibling"
        );
        {
            let state = island.inner.borrow();
            let source = state.kmdf.queues.get(&manual).expect("manual queue");
            assert!(
                !source.queued.contains(&request2),
                "the source queue released the swept request"
            );
        }
        // A sequential queue with no callbacks rejects the forwarded
        // request with STATUS_INVALID_DEVICE_REQUEST (the request is
        // completed by the framework).
        memory.write_u32(config + 0x04, 0);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("callback-less queue"),
            STATUS_SUCCESS
        );
        let bare = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request 3"),
            STATUS_SUCCESS
        );
        let request3 = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request3, bare],
            )
            .expect("forward without callback"),
            STATUS_INVALID_DEVICE_REQUEST
        );

        // A live callback queue dispatches immediately: the marker
        // stub runs and the forwarded request completes.
        memory.write_u64(config + 0x10, callback);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("callback queue"),
            STATUS_SUCCESS
        );
        let live = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request 4"),
            STATUS_SUCCESS
        );
        let request4 = memory.read_u64(request_out).unwrap();
        let runs_before = memory.read_u32(counter).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[request4, live],
            )
            .expect("forward to live queue"),
            STATUS_PENDING,
            "the dispatched request stays pending until its callback completes it"
        );
        assert!(
            memory.read_u32(counter).unwrap() > runs_before,
            "the queue callback ran for the dispatched forward"
        );
    });
}

/// An IRP arriving while the chosen power-managed queue is idle defers
/// with the power counter instead of dispatching.
#[test]
fn kmdf_irp_dispatch_defers_on_idle_power_managed_queue() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, _base, device_object) =
            pnp_load("CasaWdfIdleDispatch");
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_START_DEVICE,
                )
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        let device = island.inner.borrow().kmdf.devices_by_object[&device_object];
        let config = 0x4C_000;
        let queue_out = 0x4C_100;
        memory.map_bytes(config, &[0_u8; 0x40]);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(config, 0x40);
        memory.write_u32(config + 0x04, 0);
        memory.write_u32(config + 0x08, 1);
        let counter = arena_counter(&mut memory, &island);
        let callback = x64_marker_stub(&mut memory, &island, counter);
        memory.write_u64(config + 0x10, callback);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("power queue"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[device, 1],
            )
            .expect("stop idle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceResumeIdle,
                &[device],
            )
            .expect("resume into idle"),
            STATUS_SUCCESS
        );
        let defers_before = island.kmdf_counters().2;
        let (status, _) = island
            .dispatch_irp(
                &mut runtime,
                &mut memory,
                device_object,
                IrpMajorFunction::DeviceControl,
                0x22_0000,
                0,
                0,
                0,
                0,
                0,
            )
            .expect("dispatch while idle");
        assert_eq!(
            status, STATUS_PENDING,
            "an idle power-managed queue defers the IRP"
        );
        assert_eq!(
            island.kmdf_counters().2,
            defers_before + 1,
            "the dispatch-time power defer bumps the counter"
        );
    });
}

/// PnP and power guards after a surprise removal: STOP and both power
/// targets fail with STATUS_INVALID_DEVICE_STATE.
#[test]
fn kmdf_stop_and_power_after_surprise_reject_invalid_state() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, _base, device_object) =
            pnp_load("CasaWdfSurpriseStop");
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_START_DEVICE,
                )
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        // Two queues: one with a cancel-on-queue callback, one without;
        // each holds a completed request so the surprise-removal quiesce
        // walks both callback branches.
        let device = island.inner.borrow().kmdf.devices_by_object[&device_object];
        let cancel_counter = arena_counter(&mut memory, &island);
        let cancel_stub = x64_marker_stub(&mut memory, &island, cancel_counter);
        let queue_out = 0x4E_100;
        memory.map_bytes(queue_out, &[0_u8; 8]);
        let queue_config = 0x4E_200;
        memory.map_bytes(queue_config, &[0_u8; 0x80]);
        memory.write_u32(queue_config, 0x80);
        memory.write_u32(queue_config + 4, 2); // manual queue
        // Callback slots start at config+0x10; canceled-on-queue is
        // the eighth slot (+0x38) relative to that base.
        memory.write_u64(queue_config + 0x48, cancel_stub);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, queue_config, 0, queue_out],
            )
            .expect("cancel-callback queue"),
            STATUS_SUCCESS
        );
        let cancel_queue = memory.read_u64(queue_out).unwrap();
        {
            let state = island.inner.borrow();
            assert_eq!(
                state.kmdf.queues[&cancel_queue].callbacks.canceled_on_queue, cancel_stub,
                "cancel-on-queue callback parsed from config+0x38"
            );
        }
        memory.write_u64(queue_config + 0x48, 0);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, queue_config, 0, queue_out],
            )
            .expect("plain queue"),
            STATUS_SUCCESS
        );
        let plain_queue = memory.read_u64(queue_out).unwrap();
        let request_out = 0x4E_300;
        memory.map_bytes(request_out, &[0_u8; 8]);
        macro_rules! queued_request {
            () => {{
                assert_eq!(
                    call_island_shim(
                        &island,
                        &mut runtime,
                        &mut memory,
                        DriverShim::WdfRequestCreate,
                        &[0, device, request_out],
                    )
                    .expect("queued request"),
                    STATUS_SUCCESS
                );
                let request = memory.read_u64(request_out).unwrap();
                request
            }};
        }
        // (a) pending request on the cancel-on-queue queue: the quiesce
        //     pushes EvtIoCanceledOnQueue for it.
        let on_cancel_queue = queued_request!();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[on_cancel_queue, cancel_queue],
            )
            .expect("queue for cancel callback"),
            STATUS_SUCCESS
        );
        // (b) pending request with its own cancel callback: the quiesce
        //     pushes EvtRequestCancel.
        let with_cancel_cb = queued_request!();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestMarkCancelable,
                &[with_cancel_cb, cancel_stub],
            )
            .expect("mark cancelable"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[with_cancel_cb, plain_queue],
            )
            .expect("queue with cancel callback"),
            STATUS_SUCCESS
        );
        // (c) pending request with no callbacks at all: the quiesce
        //     force-cancels it.
        let bare_request = queued_request!();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[bare_request, plain_queue],
            )
            .expect("queue bare request"),
            STATUS_SUCCESS
        );
        // (d) a completed request stays in the queued list and is
        //     skipped by the quiesce.
        let completed_request = queued_request!();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[completed_request, plain_queue],
            )
            .expect("queue completed-to-be"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestComplete,
                &[completed_request, STATUS_SUCCESS as u64],
            )
            .expect("complete in queue"),
            STATUS_SUCCESS
        );
        // (e) deleting a queued request leaves a stale handle for the
        //     quiesce to skip.
        let deleted_request = queued_request!();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestForwardToIoQueue,
                &[deleted_request, plain_queue],
            )
            .expect("queue to-be-deleted"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfObjectDelete,
                &[deleted_request],
            )
            .expect("delete queued request"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_SURPRISE_REMOVAL,
                )
                .expect("surprise")
                .0,
            STATUS_SUCCESS
        );
        assert_eq!(
            island
                .dispatch_pnp(&mut runtime, &mut memory, device_object, IRP_MN_STOP_DEVICE,)
                .expect("stop after surprise")
                .0,
            STATUS_INVALID_DEVICE_STATE,
            "STOP on a surprised device fails exactly"
        );
        assert!(
            memory.read_u32(cancel_counter).unwrap() >= 1,
            "EvtIoCanceledOnQueue ran for the pending request"
        );
        assert_eq!(
            island
                .set_device_power(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    WDF_POWER_DEVICE_D0
                )
                .expect("D0 after surprise")
                .0,
            STATUS_INVALID_DEVICE_STATE,
            "a power transition on a surprised device fails exactly"
        );
        assert_eq!(
            island
                .set_device_power(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    WDF_POWER_DEVICE_D3
                )
                .expect("D3 after surprise")
                .0,
            STATUS_INVALID_DEVICE_STATE,
            "the D3 target has the same guard"
        );
    });
}

/// `dispatch_next_queued` skips a power-managed queue whose device is
/// not ready, and the preemption tick with no active island is a no-op.
#[test]
fn kmdf_dispatch_next_power_guard_and_off_island_tick_are_safe() {
    with_big_stack(|| {
        let (mut runtime, _dir, mut memory, island, _base, device_object) =
            pnp_load("CasaWdfNextGuard");
        assert_eq!(
            island
                .dispatch_pnp(
                    &mut runtime,
                    &mut memory,
                    device_object,
                    IRP_MN_START_DEVICE,
                )
                .expect("start")
                .0,
            STATUS_SUCCESS
        );
        let device = island.inner.borrow().kmdf.devices_by_object[&device_object];
        let config = 0x4D_000;
        let queue_out = 0x4D_100;
        memory.map_bytes(config, &[0_u8; 0x40]);
        memory.map_bytes(queue_out, &[0_u8; 8]);
        memory.write_u32(config, 0x40);
        memory.write_u32(config + 0x04, 0);
        memory.write_u32(config + 0x08, 1);
        let counter = arena_counter(&mut memory, &island);
        let callback = x64_marker_stub(&mut memory, &island, counter);
        memory.write_u64(config + 0x10, callback);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfIoQueueCreate,
                &[device, config, 0, queue_out],
            )
            .expect("power queue"),
            STATUS_SUCCESS
        );
        let queue = memory.read_u64(queue_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceStopIdle,
                &[device, 1],
            )
            .expect("stop idle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceResumeIdle,
                &[device],
            )
            .expect("resume into idle"),
            STATUS_SUCCESS
        );
        let request_out = 0x4D_200;
        memory.map_bytes(request_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfRequestCreate,
                &[0, device, request_out],
            )
            .expect("request"),
            STATUS_SUCCESS
        );
        let request = memory.read_u64(request_out).unwrap();
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDeviceEnqueueRequest,
                &[device, request],
            )
            .expect("enqueue while idle"),
            STATUS_SUCCESS
        );
        assert_eq!(
            island.kmdf_queue_state(queue),
            Some((1, 0, false, false, true))
        );
        // The dispatch loop skips the power-managed queue outright.
        let dispatched = {
            let mut state = island.inner.borrow_mut();
            state
                .dispatch_next_queued(&mut memory)
                .expect("dispatch next")
        };
        assert!(
            dispatched.is_none(),
            "a non-power-ready queue yields no dispatch"
        );
        assert_eq!(
            island.kmdf_queue_state(queue),
            Some((1, 0, false, false, true))
        );
        // The preemption tick with no installed island returns without
        // touching any state.
        crate::driver_island::tick_active_island_preemption(&mut runtime);
    });
}

/// x86 guests exercise the pointer-width branches of the new parsers:
/// interrupt config offsets, DMA maximum width, child-list callbacks,
/// and the USB descriptor pointer.
#[test]
fn kmdf_x86_config_width_branches_parse_reject_none() {
    with_big_stack(|| {
        let image = build_kmdf_driver_pe32();
        let (mut runtime, _dir, mut memory, island) =
            load_staged_island_x86(&image, "CasaKmdfX86N");
        let device = island.kmdf_device_handles()[0];
        // The x86 ISR is never dispatched by this test, so a plain
        // non-zero code address is enough for the config parse.
        let isr = 0x1000u64;
        // Interrupt: x86 stores EvtInterruptIsr at +4 and DPC at +8.
        let config = 0x41_000;
        memory.map_bytes(config, &[0_u8; 0x20]);
        memory.write_u32(config, 0x10);
        memory.write_u32(config + 4, isr as u32);
        memory.write_u32(config + 8, isr as u32);
        let out = 0x41_100;
        memory.map_bytes(out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfInterruptCreate,
                &[device, 0, config, out],
            )
            .expect("x86 interrupt"),
            STATUS_SUCCESS
        );
        let interrupt = memory.read_u32(out).unwrap() as u64;
        assert!(
            island
                .inner
                .borrow()
                .kmdf
                .interrupts
                .contains_key(&interrupt)
        );
        // DMA: x86 reads MaximumLength as a u32 at +8.
        memory.write_u32(config, 0x10);
        memory.write_u32(config + 4, 0);
        memory.write_u32(config + 8, 0x2_0000);
        memory.write_u32(config + 12, 0);
        let enabler_out = 0x41_200;
        memory.map_bytes(enabler_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCreate,
                &[device, 0, config, enabler_out],
            )
            .expect("x86 dma"),
            STATUS_SUCCESS
        );
        let x86_enabler = u64::from(memory.read_u32(enabler_out).unwrap());
        assert_eq!(
            call_island_shim_raw(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfDmaEnablerCalculateMaximumTransferSize,
                &[x86_enabler],
            )
            .expect("x86 short max"),
            0x1_0000,
            "the x86 width read yields the Short-profile cap"
        );
        // Child list: the enumerate callback sits at +4 on x86.
        let child_config = 0x41_300;
        memory.map_bytes(child_config, &[0_u8; 0x10]);
        memory.write_u32(child_config, 0x0C);
        memory.write_u32(child_config + 4, isr as u32);
        let list_out = 0x41_400;
        memory.map_bytes(list_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfChildListCreate,
                &[device, 0, child_config, list_out],
            )
            .expect("x86 child list"),
            STATUS_SUCCESS
        );
        // USB: the descriptor pointer follows a 4-byte x86 header at
        // +16 and requires Size >= 20.
        let descriptor = 0x41_500;
        memory.map_bytes(descriptor, &vec![0_u8; 0x40]);
        memory.write_u8(descriptor, 9);
        memory.write_u8(descriptor + 1, 2);
        memory.write_u16(descriptor + 2, 25);
        memory.write_u8(descriptor + 4, 1);
        memory.write_u8(descriptor + 9, 9);
        memory.write_u8(descriptor + 10, 4);
        memory.write_u8(descriptor + 12, 1);
        memory.write_u8(descriptor + 18, 7);
        memory.write_u8(descriptor + 19, 5);
        memory.write_u8(descriptor + 20, 0x81);
        memory.write_u8(descriptor + 21, 0x02);
        memory.write_u16(descriptor + 22, 512);
        let usb_config = 0x41_600;
        memory.map_bytes(usb_config, &[0_u8; 0x20]);
        memory.write_u32(usb_config, 0x18);
        memory.write_u16(usb_config + 4, 0x0200);
        memory.write_u16(usb_config + 6, 0x0001);
        memory.write_u16(usb_config + 8, 0x0002);
        memory.write_u32(usb_config + 16, descriptor as u32);
        let usb_out = 0x41_700;
        memory.map_bytes(usb_out, &[0_u8; 8]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfUsbTargetDeviceCreate,
                &[device, 0, usb_config, usb_out],
            )
            .expect("x86 usb target"),
            STATUS_SUCCESS
        );
        let usb = memory.read_u32(usb_out).unwrap() as u64;
        assert!(island.inner.borrow().kmdf.usb_targets.contains_key(&usb));
        // Timer and work-item configs use the x86 offsets (callback at
        // +4, serialization at +8).
        let x86_config = 0x41_800;
        memory.map_bytes(x86_config, &[0_u8; 0x0C]);
        memory.write_u32(x86_config, 0x0C);
        memory.write_u32(x86_config + 4, 0x1000);
        let x86_out = 0x41_900;
        memory.map_bytes(x86_out, &[0_u8; 4]);
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfTimerCreate,
                &[x86_config, 0, x86_out],
            )
            .expect("x86 timer"),
            STATUS_SUCCESS
        );
        assert_eq!(
            call_island_shim(
                &island,
                &mut runtime,
                &mut memory,
                DriverShim::WdfWorkItemCreate,
                &[x86_config, 0, x86_out],
            )
            .expect("x86 work item"),
            STATUS_SUCCESS
        );
        {
            let state = island.inner.borrow();
            assert_eq!(state.kmdf.timers.len(), 1);
            assert_eq!(state.kmdf.work_items.len(), 1);
        }
    });
}
