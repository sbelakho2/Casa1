#![allow(dead_code)]

use casa1::oracle_model::LifecycleLogEntry;
use casa1::pe::{LifecyclePlan, LifecycleStage};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SAMPLE_IMAGE_BASE: u64 = 0x0000_0001_4000_0000;
pub const SAMPLE_ENTRY_RVA: u32 = 0x1000;
pub const SAMPLE_TLS_CALLBACK_RVA: u32 = 0x1010;
pub const SAMPLE_RELOC_TARGET_RVA: u32 = 0x3000;
pub const SAMPLE_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Debug, Clone)]
struct TestSection {
    name: [u8; 8],
    virtual_address: u32,
    characteristics: u32,
    data: Vec<u8>,
    raw_pointer: u32,
}

impl TestSection {
    fn new(name: &str, virtual_address: u32, characteristics: u32) -> Self {
        let mut name_bytes = [0_u8; 8];
        let copy = name.as_bytes();
        name_bytes[..copy.len().min(8)].copy_from_slice(&copy[..copy.len().min(8)]);
        Self {
            name: name_bytes,
            virtual_address,
            characteristics,
            data: Vec::new(),
            raw_pointer: 0,
        }
    }

    fn alloc(&mut self, bytes: &[u8], alignment: usize) -> u32 {
        align_vec(&mut self.data, alignment);
        let rva = self.virtual_address + self.data.len() as u32;
        self.data.extend_from_slice(bytes);
        rva
    }

    fn reserve(&mut self, size: usize, alignment: usize) -> u32 {
        align_vec(&mut self.data, alignment);
        let rva = self.virtual_address + self.data.len() as u32;
        self.data.resize(self.data.len() + size, 0);
        rva
    }

    fn patch_u16(&mut self, rva: u32, value: u16) {
        let offset = (rva - self.virtual_address) as usize;
        self.data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn patch_u32(&mut self, rva: u32, value: u32) {
        let offset = (rva - self.virtual_address) as usize;
        self.data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn patch_u64(&mut self, rva: u32, value: u64) {
        let offset = (rva - self.virtual_address) as usize;
        self.data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn raw_size_aligned(&self, file_alignment: u32) -> u32 {
        align_u32(self.data.len() as u32, file_alignment)
    }

    fn virtual_size_aligned(&self, section_alignment: u32) -> u32 {
        align_u32(self.data.len() as u32, section_alignment)
    }
}

pub fn sample_pe_bytes() -> Vec<u8> {
    let file_alignment = 0x200;
    let section_alignment = 0x1000;

    let mut text = TestSection::new(".text", 0x1000, 0x6000_0020);
    let entry_rva = text.alloc(&[0xc3], 1);
    assert_eq!(entry_rva, SAMPLE_ENTRY_RVA);
    let tls_callback_rva = text.alloc(&[0x90, 0xc3], 0x10);
    assert_eq!(tls_callback_rva, SAMPLE_TLS_CALLBACK_RVA);

    let mut rdata = TestSection::new(".rdata", 0x2000, 0x4000_0040);
    let mut data = TestSection::new(".data", 0x3000, 0xc000_0040);
    let mut reloc = TestSection::new(".reloc", 0x4000, 0x4200_0040);

    let reloc_target_rva = data.alloc(&(SAMPLE_IMAGE_BASE + 0x1234).to_le_bytes(), 8);
    assert_eq!(reloc_target_rva, SAMPLE_RELOC_TARGET_RVA);
    let tls_index_rva = data.alloc(&0_u32.to_le_bytes(), 4);
    let callback_array_rva = data.reserve(16, 8);
    data.patch_u64(callback_array_rva, SAMPLE_IMAGE_BASE + SAMPLE_TLS_CALLBACK_RVA as u64);
    data.patch_u64(callback_array_rva + 8, 0);

    let export_directory_rva = rdata.reserve(40, 4);
    let export_dll_name_rva = rdata.alloc(b"sample.dll\0", 1);
    let named_export_name_rva = rdata.alloc(b"Named\0", 1);
    let forwarded_export_name_rva = rdata.alloc(b"Forwarded\0", 1);
    let forwarder_target_rva = rdata.alloc(b"KERNELBASE.Sleep\0", 1);
    let functions_rva = rdata.reserve(8, 4);
    let names_rva = rdata.reserve(8, 4);
    let ordinals_rva = rdata.reserve(4, 2);
    rdata.patch_u32(functions_rva, SAMPLE_ENTRY_RVA);
    rdata.patch_u32(functions_rva + 4, forwarder_target_rva);
    rdata.patch_u32(names_rva, named_export_name_rva);
    rdata.patch_u32(names_rva + 4, forwarded_export_name_rva);
    rdata.patch_u16(ordinals_rva, 0);
    rdata.patch_u16(ordinals_rva + 2, 1);
    let export_directory_start = export_directory_rva;
    rdata.patch_u32(export_directory_rva + 12, export_dll_name_rva);
    rdata.patch_u32(export_directory_rva + 16, 1);
    rdata.patch_u32(export_directory_rva + 20, 2);
    rdata.patch_u32(export_directory_rva + 24, 2);
    rdata.patch_u32(export_directory_rva + 28, functions_rva);
    rdata.patch_u32(export_directory_rva + 32, names_rva);
    rdata.patch_u32(export_directory_rva + 36, ordinals_rva);
    let export_directory_size = rdata.virtual_address + rdata.data.len() as u32 - export_directory_start;

    let import_dll_name_rva = rdata.alloc(b"api-ms-win-core-file-l1-1-0.dll\0", 1);
    let create_file_name_rva = rdata.alloc(&hint_name_bytes("CreateFileW"), 2);
    let import_int_rva = rdata.reserve(24, 8);
    let import_iat_rva = rdata.reserve(24, 8);
    rdata.patch_u64(import_int_rva, create_file_name_rva as u64);
    rdata.patch_u64(import_int_rva + 8, 0x8000_0000_0000_0011);
    rdata.patch_u64(import_iat_rva, create_file_name_rva as u64);
    rdata.patch_u64(import_iat_rva + 8, 0x8000_0000_0000_0011);
    let import_descriptor_rva = rdata.reserve(40, 4);
    rdata.patch_u32(import_descriptor_rva, import_int_rva);
    rdata.patch_u32(import_descriptor_rva + 12, import_dll_name_rva);
    rdata.patch_u32(import_descriptor_rva + 16, import_iat_rva);

    let delay_dll_name_rva = rdata.alloc(b"kernel32.dll\0", 1);
    let forwarded_name_rva = rdata.alloc(&hint_name_bytes("Forwarded"), 2);
    let delay_int_rva = rdata.reserve(16, 8);
    let delay_iat_rva = rdata.reserve(16, 8);
    rdata.patch_u64(delay_int_rva, forwarded_name_rva as u64);
    rdata.patch_u64(delay_iat_rva, forwarded_name_rva as u64);
    let delay_descriptor_rva = rdata.reserve(64, 4);
    rdata.patch_u32(delay_descriptor_rva + 4, delay_dll_name_rva);
    rdata.patch_u32(delay_descriptor_rva + 12, delay_iat_rva);
    rdata.patch_u32(delay_descriptor_rva + 16, delay_int_rva);

    let load_config_rva = rdata.reserve(0x94, 8);
    rdata.patch_u32(load_config_rva, 0x94);
    rdata.patch_u64(load_config_rva + 0x60, SAMPLE_IMAGE_BASE + SAMPLE_RELOC_TARGET_RVA as u64);
    rdata.patch_u64(load_config_rva + 0x68, 1);
    rdata.patch_u64(load_config_rva + 0x70, SAMPLE_IMAGE_BASE + SAMPLE_ENTRY_RVA as u64);
    rdata.patch_u64(load_config_rva + 0x78, SAMPLE_IMAGE_BASE + SAMPLE_TLS_CALLBACK_RVA as u64);
    rdata.patch_u64(load_config_rva + 0x80, SAMPLE_IMAGE_BASE + 0x2080);
    rdata.patch_u64(load_config_rva + 0x88, 2);
    rdata.patch_u32(load_config_rva + 0x90, 0x500);

    let debug_directory_rva = rdata.reserve(28, 4);
    rdata.patch_u32(debug_directory_rva + 12, 2);
    rdata.patch_u32(debug_directory_rva + 16, 0x20);
    rdata.patch_u32(debug_directory_rva + 20, SAMPLE_ENTRY_RVA);

    let tls_directory_rva = rdata.reserve(40, 8);
    rdata.patch_u64(tls_directory_rva, SAMPLE_IMAGE_BASE + reloc_target_rva as u64);
    rdata.patch_u64(tls_directory_rva + 8, SAMPLE_IMAGE_BASE + reloc_target_rva as u64 + 8);
    rdata.patch_u64(tls_directory_rva + 16, SAMPLE_IMAGE_BASE + tls_index_rva as u64);
    rdata.patch_u64(tls_directory_rva + 24, SAMPLE_IMAGE_BASE + callback_array_rva as u64);

    reloc.alloc(&relocation_block(SAMPLE_RELOC_TARGET_RVA & !0xfff, SAMPLE_RELOC_TARGET_RVA & 0xfff), 4);

    let manifest = embedded_manifest_xml().into_bytes();
    let version = version_resource_blob("Casa1 Demo", "1.2.3.4");
    let mut rsrc = TestSection::new(".rsrc", 0x5000, 0x4000_0040);
    rsrc.data = build_resource_section(rsrc.virtual_address, vec![(16, version), (24, manifest)]);

    let mut sections = vec![text, rdata, data, reloc, rsrc];

    let dos_stub_size = 0x80;
    let optional_header_size = 0xf0;
    let nt_headers_size = 4 + 20 + optional_header_size;
    let section_headers_size = sections.len() as u32 * 40;
    let size_of_headers = align_u32(dos_stub_size + nt_headers_size + section_headers_size, file_alignment);

    let mut raw_pointer = size_of_headers;
    for section in &mut sections {
        section.raw_pointer = raw_pointer;
        raw_pointer += section.raw_size_aligned(file_alignment);
    }
    let size_of_image = sections
        .last()
        .map(|section| section.virtual_address + section.virtual_size_aligned(section_alignment))
        .unwrap_or(section_alignment);

    let mut directories = BTreeMap::new();
    directories.insert(0_u32, (export_directory_rva, export_directory_size));
    directories.insert(1_u32, (import_descriptor_rva, 40));
    directories.insert(2_u32, (0x5000, sections.last().expect("resource section").data.len() as u32));
    directories.insert(5_u32, (0x4000, sections[3].data.len() as u32));
    directories.insert(6_u32, (debug_directory_rva, 28));
    directories.insert(9_u32, (tls_directory_rva, 40));
    directories.insert(10_u32, (load_config_rva, 0x94));
    directories.insert(13_u32, (delay_descriptor_rva, 64));

    let mut bytes = vec![0_u8; raw_pointer as usize];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    write_u32(&mut bytes, 0x3c, dos_stub_size);
    let pe_offset = dos_stub_size as usize;
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    write_u16(&mut bytes, pe_offset + 4, 0x8664);
    write_u16(&mut bytes, pe_offset + 6, sections.len() as u16);
    write_u32(&mut bytes, pe_offset + 16, 0);
    write_u16(&mut bytes, pe_offset + 20, optional_header_size as u16);
    write_u16(&mut bytes, pe_offset + 22, 0x2022);

    let optional = pe_offset + 24;
    write_u16(&mut bytes, optional, 0x20b);
    bytes[optional + 2] = 14;
    bytes[optional + 3] = 0;
    write_u32(&mut bytes, optional + 4, sections[0].raw_size_aligned(file_alignment));
    write_u32(&mut bytes, optional + 8, sections[1..].iter().map(|section| section.raw_size_aligned(file_alignment)).sum());
    write_u32(&mut bytes, optional + 16, SAMPLE_ENTRY_RVA);
    write_u32(&mut bytes, optional + 20, 0x1000);
    write_u64(&mut bytes, optional + 24, SAMPLE_IMAGE_BASE);
    write_u32(&mut bytes, optional + 32, section_alignment);
    write_u32(&mut bytes, optional + 36, file_alignment);
    write_u32(&mut bytes, optional + 56, size_of_image);
    write_u32(&mut bytes, optional + 60, size_of_headers);
    write_u16(&mut bytes, optional + 68, 3);
    write_u16(&mut bytes, optional + 70, 0x8140);
    write_u64(&mut bytes, optional + 72, 0x20_0000);
    write_u64(&mut bytes, optional + 80, 0x4000);
    write_u64(&mut bytes, optional + 88, 0x20_0000);
    write_u64(&mut bytes, optional + 96, 0x4000);
    write_u32(&mut bytes, optional + 108, 16);
    for index in 0..16_u32 {
        if let Some((rva, size)) = directories.get(&index) {
            let offset = optional + 112 + index as usize * 8;
            write_u32(&mut bytes, offset, *rva);
            write_u32(&mut bytes, offset + 4, *size);
        }
    }

    let mut section_header_offset = optional + optional_header_size as usize;
    for section in &sections {
        bytes[section_header_offset..section_header_offset + 8].copy_from_slice(&section.name);
        write_u32(&mut bytes, section_header_offset + 8, section.data.len() as u32);
        write_u32(&mut bytes, section_header_offset + 12, section.virtual_address);
        write_u32(&mut bytes, section_header_offset + 16, section.raw_size_aligned(file_alignment));
        write_u32(&mut bytes, section_header_offset + 20, section.raw_pointer);
        write_u32(&mut bytes, section_header_offset + 36, section.characteristics);
        section_header_offset += 40;
    }

    for section in &sections {
        let start = section.raw_pointer as usize;
        bytes[start..start + section.data.len()].copy_from_slice(&section.data);
    }
    bytes
}

pub fn external_manifest_xml() -> String {
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <assemblyIdentity type="win32" name="Casa1.External" version="2.0.0.0" processorArchitecture="amd64"/>
    <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
            <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">System</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#
    .to_string()
}

pub fn embedded_manifest_xml() -> String {
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <assemblyIdentity type="win32" name="Casa1.Sample" version="1.0.0.0" processorArchitecture="amd64"/>
  <dependency>
    <dependentAssembly>
            <assemblyIdentity type="win32" name="Microsoft.VC143.CRT" version="14.36.32532.0" processorArchitecture="amd64" publicKeyToken="1fc8b3b9a1e18e3b"/>
    </dependentAssembly>
  </dependency>
    <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
            <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
    <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
            <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#
    .to_string()
}

fn hint_name_bytes(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    bytes
}

fn relocation_block(page_rva: u32, offset: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&page_rva.to_le_bytes());
    bytes.extend_from_slice(&(12_u32).to_le_bytes());
    let dir64 = ((10_u16) << 12) | (offset as u16 & 0x0fff);
    bytes.extend_from_slice(&dir64.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

fn build_resource_section(section_rva: u32, entries: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    let root_size = 16 + entries.len() * 8;
    let tree_size = root_size + entries.len() * 64;
    let mut bytes = vec![0_u8; tree_size];
    write_directory_header(&mut bytes, 0, entries.len() as u16);

    let mut blob_offset = align_usize(tree_size, 4);
    bytes.resize(blob_offset, 0);
    for (index, (type_id, blob)) in entries.into_iter().enumerate() {
        let type_dir_offset = root_size + index * 64;
        let name_dir_offset = type_dir_offset + 24;
        let data_entry_offset = type_dir_offset + 48;

        write_u32(&mut bytes, 16 + index * 8, type_id);
        write_u32(&mut bytes, 20 + index * 8, 0x8000_0000 | type_dir_offset as u32);

        write_directory_header(&mut bytes, type_dir_offset, 1);
        write_u32(&mut bytes, type_dir_offset + 16, 1);
        write_u32(&mut bytes, type_dir_offset + 20, 0x8000_0000 | name_dir_offset as u32);

        write_directory_header(&mut bytes, name_dir_offset, 1);
        write_u32(&mut bytes, name_dir_offset + 16, 1033);
        write_u32(&mut bytes, name_dir_offset + 20, data_entry_offset as u32);

        let data_rva = section_rva + blob_offset as u32;
        write_u32(&mut bytes, data_entry_offset, data_rva);
        write_u32(&mut bytes, data_entry_offset + 4, blob.len() as u32);
        write_u32(&mut bytes, data_entry_offset + 8, 1200);

        let end = blob_offset + blob.len();
        bytes.resize(end, 0);
        bytes[blob_offset..end].copy_from_slice(&blob);
        blob_offset = align_usize(end, 4);
        bytes.resize(blob_offset, 0);
    }
    bytes
}

fn write_directory_header(bytes: &mut [u8], offset: usize, id_entries: u16) {
    write_u16(bytes, offset + 12, 0);
    write_u16(bytes, offset + 14, id_entries);
}

fn version_resource_blob(product_name: &str, file_version: &str) -> Vec<u8> {
    let fixed_info = fixed_file_info(file_version);
    let string_table = version_block(
        "040904b0",
        1,
        &[],
        0,
        vec![
            string_block("ProductName", product_name),
            string_block("FileVersion", file_version),
        ],
    );
    let string_file_info = version_block("StringFileInfo", 1, &[], 0, vec![string_table]);
    version_block(
        "VS_VERSION_INFO",
        0,
        &fixed_info,
        fixed_info.len() as u16,
        vec![string_file_info],
    )
}

fn string_block(key: &str, value: &str) -> Vec<u8> {
    let value_bytes = utf16z_bytes(value);
    version_block(
        key,
        1,
        &value_bytes,
        (value.encode_utf16().count() + 1) as u16,
        Vec::new(),
    )
}

fn version_block(key: &str, ty: u16, value: &[u8], value_length: u16, children: Vec<Vec<u8>>) -> Vec<u8> {
    let mut bytes = vec![0_u8; 6];
    bytes.extend_from_slice(&utf16z_bytes(key));
    align_vec(&mut bytes, 4);
    bytes.extend_from_slice(value);
    align_vec(&mut bytes, 4);
    for child in children {
        bytes.extend_from_slice(&child);
        align_vec(&mut bytes, 4);
    }
    let length = bytes.len() as u16;
    bytes[0..2].copy_from_slice(&length.to_le_bytes());
    bytes[2..4].copy_from_slice(&value_length.to_le_bytes());
    bytes[4..6].copy_from_slice(&ty.to_le_bytes());
    bytes
}

fn fixed_file_info(version: &str) -> Vec<u8> {
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u16>().expect("version part"))
        .collect::<Vec<_>>();
    while parts.len() < 4 {
        parts.push(0);
    }
    let ms = ((parts[0] as u32) << 16) | parts[1] as u32;
    let ls = ((parts[2] as u32) << 16) | parts[3] as u32;
    let mut bytes = Vec::new();
    for value in [
        0xfeef04bd,
        0x0001_0000,
        ms,
        ls,
        ms,
        ls,
        0x0000_003f,
        0,
        0x0004_0004,
        1,
        0,
        0,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn utf16z_bytes(value: &str) -> Vec<u8> {
    let mut bytes = value
        .encode_utf16()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

fn align_vec(bytes: &mut Vec<u8>, alignment: usize) {
    let aligned = align_usize(bytes.len(), alignment);
    bytes.resize(aligned, 0);
}

fn align_usize(value: usize, alignment: usize) -> usize {
    if value % alignment == 0 {
        value
    } else {
        value + (alignment - (value % alignment))
    }
}

fn align_u32(value: u32, alignment: u32) -> u32 {
    if value % alignment == 0 {
        value
    } else {
        value + (alignment - (value % alignment))
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn build_real_windows_sleep_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_sleep_probe.c");
    fs::write(
        &source_path,
        r#"__attribute__((dllimport)) void __stdcall Sleep(unsigned long);
__attribute__((dllimport)) void __stdcall ExitProcess(unsigned int);
void mainCRTStartup(void) {
    Sleep(1);
    ExitProcess(0);
}
"#,
    )
    .expect("write probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,console")
        .arg("-lkernel32")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_real_windows_ui_audio_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_ui_audio_probe.c");
    fs::write(
        &source_path,
        r#"__attribute__((dllimport)) int __stdcall MessageBoxW(void*, const unsigned short*, const unsigned short*, unsigned int);
__attribute__((dllimport)) int __stdcall Beep(unsigned int, unsigned int);
__attribute__((dllimport)) void __stdcall ExitProcess(unsigned int);
static const unsigned short TITLE[] = {'C','a','s','a','1',0};
static const unsigned short TEXT[] = {'P','r','o','b','e',0};
void mainCRTStartup(void) {
    MessageBoxW(0, TEXT, TITLE, 0);
    Beep(440, 120);
    ExitProcess(0);
}
"#,
    )
    .expect("write probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-fno-sanitize=undefined")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,windows")
        .arg("-lkernel32")
        .arg("-luser32")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_real_windows_crt_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_crt_probe.c");
    fs::write(
        &source_path,
        r#"#include <windows.h>
int main(void) {
    return 0;
}
"#,
    )
    .expect("write CRT probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_real_windows_indirect_import_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_indirect_import_probe.c");
    fs::write(
        &source_path,
        r#"__attribute__((dllimport)) void __stdcall Sleep(unsigned long);
__attribute__((dllimport)) void __stdcall ExitProcess(unsigned int);
typedef void (__stdcall *sleep_fn)(unsigned long);
__attribute__((noinline)) sleep_fn resolve_sleep(void) {
    return Sleep;
}
void mainCRTStartup(void) {
    sleep_fn fn = resolve_sleep();
    fn(1);
    ExitProcess(0);
}
"#,
    )
    .expect("write indirect-import probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,console")
        .arg("-lkernel32")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_real_windows_user32_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_user32_probe.s");
    fs::write(
        &source_path,
        r#".intel_syntax noprefix
.globl mainCRTStartup
.extern RegisterClassExW
.extern CreateWindowExW
.extern PeekMessageW
.extern DispatchMessageW
.extern ExitProcess

.section .rdata,"dr"
.align 8
CLASS_NAME:
    .short 'C','a','s','a','1','W','n','d',0
WINDOW_TITLE:
    .short 'C','a','s','a','1',' ','P','E',0

.align 8
KLASS:
    .long 80
    .long 0
    .quad 0
    .long 0
    .long 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad CLASS_NAME
    .quad 0

.section .bss,"bw"
.align 8
MSG_SLOT:
    .zero 48

.section .text,"xr"
mainCRTStartup:
    sub rsp, 0x68

    lea rcx, [rip + KLASS]
    call RegisterClassExW
    cmp eax, 0
    je exit_one

    xor ecx, ecx
    lea rdx, [rip + CLASS_NAME]
    lea r8, [rip + WINDOW_TITLE]
    mov r9d, 0x10000000
    mov qword ptr [rsp + 0x20], 0
    mov qword ptr [rsp + 0x28], 0
    mov qword ptr [rsp + 0x30], 320
    mov qword ptr [rsp + 0x38], 240
    mov qword ptr [rsp + 0x40], 0
    mov qword ptr [rsp + 0x48], 0
    mov qword ptr [rsp + 0x50], 0
    mov qword ptr [rsp + 0x58], 0
    call CreateWindowExW
    cmp rax, 0
    je exit_two

    lea rcx, [rip + MSG_SLOT]
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp + 0x20], 1
    call PeekMessageW
    cmp eax, 0
    je exit_three

    lea rcx, [rip + MSG_SLOT]
    call DispatchMessageW

    xor ecx, ecx
    call ExitProcess

exit_one:
    mov ecx, 1
    call ExitProcess

exit_two:
    mov ecx, 2
    call ExitProcess

exit_three:
    mov ecx, 3
    call ExitProcess
"#,
    )
    .expect("write user32 probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,windows")
        .arg("-lkernel32")
        .arg("-luser32")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_real_windows_xaudio2_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_xaudio2_probe.s");
    fs::write(
        &source_path,
        r#".intel_syntax noprefix
.globl mainCRTStartup
.extern XAudio2Create
.extern ExitProcess

.section .data,"dw"
.align 8
engine_ptr:
    .quad 0
mastering_ptr:
    .quad 0
source_ptr:
    .quad 0

.align 8
wave_format:
    .short 1
    .short 2
    .long 48000
    .long 192000
    .short 4
    .short 16
    .short 0

.align 8
audio_data:
    .short 16384, -16384, 8192, -8192

.align 8
xaudio2_buffer:
    .long 0
    .long 8
    .quad audio_data
    .long 0
    .long 0
    .long 0
    .long 0
    .long 0
    .long 0
    .quad 0

.section .text,"xr"
mainCRTStartup:
    sub rsp, 0x48

    lea rcx, [rip + engine_ptr]
    xor edx, edx
    mov r8d, 1
    call XAudio2Create
    test eax, eax
    jne exit_one

    mov rcx, qword ptr [rip + engine_ptr]
    lea rdx, [rip + mastering_ptr]
    mov r8d, 2
    mov r9d, 48000
    mov dword ptr [rsp + 0x20], 0
    mov qword ptr [rsp + 0x28], 0
    mov qword ptr [rsp + 0x30], 0
    mov dword ptr [rsp + 0x38], 6
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 56]
    test eax, eax
    jne exit_two

    mov rcx, qword ptr [rip + engine_ptr]
    lea rdx, [rip + source_ptr]
    lea r8, [rip + wave_format]
    xor r9d, r9d
    mov dword ptr [rsp + 0x20], 0x3f800000
    mov qword ptr [rsp + 0x28], 0
    mov qword ptr [rsp + 0x30], 0
    mov qword ptr [rsp + 0x38], 0
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 40]
    test eax, eax
    jne exit_three

    mov rcx, qword ptr [rip + source_ptr]
    lea rdx, [rip + xaudio2_buffer]
    xor r8d, r8d
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 168]
    test eax, eax
    jne exit_four

    mov rcx, qword ptr [rip + source_ptr]
    xor edx, edx
    xor r8d, r8d
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 152]
    test eax, eax
    jne exit_five

    mov rcx, qword ptr [rip + source_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 144]

    mov rcx, qword ptr [rip + mastering_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 144]

    mov rcx, qword ptr [rip + engine_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    xor ecx, ecx
    call ExitProcess

exit_one:
    mov ecx, 1
    call ExitProcess

exit_two:
    mov ecx, 2
    call ExitProcess

exit_three:
    mov ecx, 3
    call ExitProcess

exit_four:
    mov ecx, 4
    call ExitProcess

exit_five:
    mov ecx, 5
    call ExitProcess
"#,
    )
    .expect("write xaudio2 probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,console")
        .arg("-lkernel32")
        .arg("-lxaudio2_9")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_real_windows_d3d11_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_d3d11_probe.s");
    fs::write(
        &source_path,
        r#".intel_syntax noprefix
.globl mainCRTStartup
.extern RegisterClassExW
.extern CreateWindowExW
.extern D3D11CreateDeviceAndSwapChain
.extern ExitProcess

.section .data,"dw"
.align 8
window_handle:
    .quad 0
device_ptr:
    .quad 0
context_ptr:
    .quad 0
swapchain_ptr:
    .quad 0
texture_ptr:
    .quad 0
feature_level:
    .long 0
    .long 0

class_name:
    .short 'C','a','s','a','1','D','3','D',0
window_title:
    .short 'C','a','s','a','1',' ','D','3','D',0

.align 8
wnd_class:
    .long 80
    .long 0
    .quad 0
    .long 0
    .long 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad class_name
    .quad 0

.align 8
feature_levels:
    .long 0x0000a100

.align 8
swapchain_desc:
    .long 2
    .long 2
    .long 0
    .long 0
    .long 87
    .long 0
    .long 0
    .long 1
    .long 0
    .long 32
    .long 2
    .long 0
    .quad 0
    .long 1
    .long 0
    .long 0

.align 8
pixel_data:
    .byte 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    .byte 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10

.section .text,"xr"
mainCRTStartup:
    sub rsp, 0x68

    lea rcx, [rip + wnd_class]
    call RegisterClassExW
    test eax, eax
    je exit_one

    xor ecx, ecx
    lea rdx, [rip + class_name]
    lea r8, [rip + window_title]
    mov r9d, 0x10000000
    mov qword ptr [rsp + 0x20], 0
    mov qword ptr [rsp + 0x28], 0
    mov qword ptr [rsp + 0x30], 2
    mov qword ptr [rsp + 0x38], 2
    mov qword ptr [rsp + 0x40], 0
    mov qword ptr [rsp + 0x48], 0
    mov qword ptr [rsp + 0x50], 0
    mov qword ptr [rsp + 0x58], 0
    call CreateWindowExW
    test rax, rax
    je exit_two
    mov qword ptr [rip + window_handle], rax
    mov qword ptr [rip + swapchain_desc + 48], rax

    xor rcx, rcx
    mov edx, 1
    xor r8d, r8d
    xor r9d, r9d
    lea rax, [rip + feature_levels]
    mov qword ptr [rsp + 0x20], rax
    mov qword ptr [rsp + 0x28], 1
    mov qword ptr [rsp + 0x30], 7
    lea rax, [rip + swapchain_desc]
    mov qword ptr [rsp + 0x38], rax
    lea rax, [rip + swapchain_ptr]
    mov qword ptr [rsp + 0x40], rax
    lea rax, [rip + device_ptr]
    mov qword ptr [rsp + 0x48], rax
    lea rax, [rip + feature_level]
    mov qword ptr [rsp + 0x50], rax
    mov qword ptr [rsp + 0x58], 0
    call D3D11CreateDeviceAndSwapChain
    test eax, eax
    jne exit_three

    mov rcx, qword ptr [rip + device_ptr]
    lea rdx, [rip + context_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 320]

    mov rcx, qword ptr [rip + swapchain_ptr]
    xor edx, edx
    xor r8d, r8d
    lea r9, [rip + texture_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 72]
    test eax, eax
    jne exit_four

    mov rcx, qword ptr [rip + context_ptr]
    mov rdx, qword ptr [rip + texture_ptr]
    xor r8d, r8d
    xor r9d, r9d
    lea rax, [rip + pixel_data]
    mov qword ptr [rsp + 0x20], rax
    mov qword ptr [rsp + 0x28], 8
    mov qword ptr [rsp + 0x30], 0
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 384]

    mov rcx, qword ptr [rip + swapchain_ptr]
    mov edx, 1
    xor r8d, r8d
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 64]
    test eax, eax
    jne exit_five

    mov rcx, qword ptr [rip + texture_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + context_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + swapchain_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + device_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    xor ecx, ecx
    call ExitProcess

exit_one:
    mov ecx, 1
    call ExitProcess

exit_two:
    mov ecx, 2
    call ExitProcess

exit_three:
    mov ecx, 3
    call ExitProcess

exit_four:
    mov ecx, 4
    call ExitProcess

exit_five:
    mov ecx, 5
    call ExitProcess
"#,
    )
    .expect("write d3d11 probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,windows")
        .arg("-lkernel32")
        .arg("-luser32")
        .arg("-ld3d11")
        .arg("-ldxgi")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

fn build_test_root_signature(root_constants: u32, descriptors: &[(u8, u8, u8, u8, u8, u8)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&(descriptors.len() as u32).to_le_bytes());
    bytes.extend(&root_constants.to_le_bytes());
    for descriptor in descriptors {
        bytes.extend([
            descriptor.0,
            descriptor.1,
            descriptor.2,
            descriptor.3,
            descriptor.4,
            descriptor.5,
        ]);
    }
    bytes
}

fn build_test_program_part(
    instruction_count: u32,
    ir_size: u32,
    threadgroup_size: (u32, u32, u32),
    uses: &[(u8, u8, u8, u8, u8, u16)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&instruction_count.to_le_bytes());
    bytes.extend(&ir_size.to_le_bytes());
    bytes.extend(&threadgroup_size.0.to_le_bytes());
    bytes.extend(&threadgroup_size.1.to_le_bytes());
    bytes.extend(&threadgroup_size.2.to_le_bytes());
    bytes.extend(&(uses.len() as u32).to_le_bytes());
    for entry in uses {
        bytes.extend([
            entry.0,
            entry.1,
            entry.2,
            entry.3,
            entry.4,
            entry.5 as u8,
            (entry.5 >> 8) as u8,
            0,
        ]);
    }
    bytes
}

fn build_test_reflection_part(
    resources: &[(u8, u8, u8, u8, u8, u8, u8)],
    cbuffers: &[(u8, u8, u16, u32)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&(resources.len() as u32).to_le_bytes());
    for resource in resources {
        bytes.extend([
            resource.0,
            resource.1,
            resource.2,
            resource.3,
            resource.4,
            resource.5,
            resource.6,
        ]);
    }
    bytes.extend(&(cbuffers.len() as u32).to_le_bytes());
    for cbuffer in cbuffers {
        bytes.extend([
            cbuffer.0,
            cbuffer.1,
            cbuffer.2 as u8,
            (cbuffer.2 >> 8) as u8,
            cbuffer.3 as u8,
            (cbuffer.3 >> 8) as u8,
            (cbuffer.3 >> 16) as u8,
            (cbuffer.3 >> 24) as u8,
        ]);
    }
    bytes
}

fn build_test_dxil_container(entry_name: &str, parts: Vec<([u8; 4], Vec<u8>)>) -> Vec<u8> {
    let header_size = 12 + parts.len() * 12;
    let mut offset = header_size as u32;
    let descriptors = parts
        .iter()
        .map(|(kind, payload)| {
            let descriptor = (*kind, offset, payload.len() as u32);
            offset += payload.len() as u32;
            descriptor
        })
        .collect::<Vec<_>>();
    let mut bytes = Vec::new();
    bytes.extend(b"DXIL");
    bytes.extend(&1_u32.to_le_bytes());
    bytes.extend(&(parts.len() as u32).to_le_bytes());
    for (kind, offset, size) in &descriptors {
        bytes.extend(kind);
        bytes.extend(&offset.to_le_bytes());
        bytes.extend(&size.to_le_bytes());
    }
    for (_, payload) in parts {
        bytes.extend(payload);
    }
    let mut meta = vec![entry_name.len() as u8];
    meta.extend(entry_name.as_bytes());
    let parts_without_meta = bytes[12 + descriptors.len() * 12..].to_vec();
    let mut rewritten = Vec::new();
    rewritten.extend(b"DXIL");
    rewritten.extend(&1_u32.to_le_bytes());
    rewritten.extend(&((descriptors.len() + 1) as u32).to_le_bytes());
    let mut running_offset = (12 + (descriptors.len() + 1) * 12) as u32;
    for (kind, _, size) in descriptors {
        rewritten.extend(kind);
        rewritten.extend(&running_offset.to_le_bytes());
        rewritten.extend(&size.to_le_bytes());
        running_offset += size;
    }
    rewritten.extend(*b"META");
    rewritten.extend(&running_offset.to_le_bytes());
    rewritten.extend(&(meta.len() as u32).to_le_bytes());
    rewritten.extend(parts_without_meta);
    rewritten.extend(meta);
    rewritten
}

fn build_test_vertex_dxil() -> Vec<u8> {
    let root_signature = build_test_root_signature(8, &[(1, 0, 0, 1, 0, 0), (2, 0, 0, 1, 1, 0), (3, 0, 0, 1, 2, 0)]);
    build_test_dxil_container(
        "main_vs",
        vec![
            (
                *b"PROG",
                build_test_program_part(
                    32,
                    512,
                    (8, 8, 1),
                    &[(1, 0, 0, 0, 1, 0), (2, 0, 0, 0, 3, 0), (3, 0, 0, 0, 0, 64)],
                ),
            ),
            (*b"SIGN", b"input-signature-output-signature".to_vec()),
            (
                *b"RFLX",
                build_test_reflection_part(
                    &[(1, 0, 0, 0, 0, 0, 1), (2, 0, 0, 1, 0, 0, 3)],
                    &[(0, 0, 64, 0x0102_0304)],
                ),
            ),
            (*b"ROOT", root_signature),
        ],
    )
}

fn build_test_pixel_dxil() -> Vec<u8> {
    let root_signature = build_test_root_signature(8, &[(1, 0, 0, 1, 0, 0), (2, 0, 0, 1, 1, 0), (3, 0, 0, 1, 2, 0)]);
    build_test_dxil_container(
        "main_ps",
        vec![
            (
                *b"PROG",
                build_test_program_part(
                    32,
                    512,
                    (8, 8, 1),
                    &[(1, 0, 0, 0, 1, 0), (2, 0, 0, 0, 3, 0), (3, 0, 0, 0, 0, 64)],
                ),
            ),
            (*b"SIGN", b"input-signature-output-signature".to_vec()),
            (
                *b"RFLX",
                build_test_reflection_part(
                    &[(1, 0, 0, 0, 0, 0, 1), (2, 0, 0, 1, 0, 0, 3)],
                    &[(0, 0, 64, 0x0102_0304)],
                ),
            ),
            (*b"ROOT", root_signature),
        ],
    )
}

fn asm_byte_block(label: &str, bytes: &[u8]) -> String {
    let mut text = String::new();
    writeln!(&mut text, "{label}:").expect("write assembly label");
    for chunk in bytes.chunks(16) {
        text.push_str("    .byte ");
        for (index, byte) in chunk.iter().enumerate() {
            if index != 0 {
                text.push_str(", ");
            }
            write!(&mut text, "0x{byte:02x}").expect("write assembly byte");
        }
        text.push('\n');
    }
    text
}

pub fn build_real_windows_d3d11_shader_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_d3d11_shader_probe.s");
    let vs_dxil = build_test_vertex_dxil();
    let ps_dxil = build_test_pixel_dxil();
    let source = format!(
        r#".intel_syntax noprefix
.globl mainCRTStartup
.extern RegisterClassExW
.extern CreateWindowExW
.extern D3D11CreateDeviceAndSwapChain
.extern ExitProcess

.section .data,"dw"
.align 8
window_handle:
    .quad 0
device_ptr:
    .quad 0
context_ptr:
    .quad 0
swapchain_ptr:
    .quad 0
texture_ptr:
    .quad 0
srv_ptr:
    .quad 0
buffer_ptr:
    .quad 0
input_layout_ptr:
    .quad 0
vs_ptr:
    .quad 0
ps_ptr:
    .quad 0
feature_level:
    .long 0
    .long 0

constant_buffer_bindings:
    .quad 0
shader_resource_bindings:
    .quad 0

class_name:
    .short 'C','a','s','a','1','D','3','D',0
window_title:
    .short 'C','a','s','a','1',' ','S','h','a','d','e','r',0

semantic_position:
    .asciz "POSITION"

.align 8
wnd_class:
    .long 80
    .long 0
    .quad 0
    .long 0
    .long 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
    .quad class_name
    .quad 0

.align 8
feature_levels:
    .long 0x0000a100

.align 8
swapchain_desc:
    .long 2
    .long 2
    .long 0
    .long 0
    .long 87
    .long 0
    .long 0
    .long 1
    .long 0
    .long 32
    .long 2
    .long 0
    .quad 0
    .long 1
    .long 0
    .long 0

.align 8
buffer_desc:
    .long 16
    .long 0
    .long 4
    .long 0
    .long 0
    .long 0

.align 8
input_element_desc:
    .quad semantic_position
    .long 0
    .long 28
    .long 0
    .long 0
    .long 0
    .long 0

{vs_dxil_block}

{ps_dxil_block}

.section .text,"xr"
mainCRTStartup:
    sub rsp, 0x98

    lea rcx, [rip + wnd_class]
    call RegisterClassExW
    test eax, eax
    je exit_one

    xor ecx, ecx
    lea rdx, [rip + class_name]
    lea r8, [rip + window_title]
    mov r9d, 0x10000000
    mov qword ptr [rsp + 0x20], 0
    mov qword ptr [rsp + 0x28], 0
    mov qword ptr [rsp + 0x30], 2
    mov qword ptr [rsp + 0x38], 2
    mov qword ptr [rsp + 0x40], 0
    mov qword ptr [rsp + 0x48], 0
    mov qword ptr [rsp + 0x50], 0
    mov qword ptr [rsp + 0x58], 0
    call CreateWindowExW
    test rax, rax
    je exit_two
    mov qword ptr [rip + window_handle], rax
    mov qword ptr [rip + swapchain_desc + 48], rax

    xor rcx, rcx
    mov edx, 1
    xor r8d, r8d
    xor r9d, r9d
    lea rax, [rip + feature_levels]
    mov qword ptr [rsp + 0x20], rax
    mov qword ptr [rsp + 0x28], 1
    mov qword ptr [rsp + 0x30], 7
    lea rax, [rip + swapchain_desc]
    mov qword ptr [rsp + 0x38], rax
    lea rax, [rip + swapchain_ptr]
    mov qword ptr [rsp + 0x40], rax
    lea rax, [rip + device_ptr]
    mov qword ptr [rsp + 0x48], rax
    lea rax, [rip + feature_level]
    mov qword ptr [rsp + 0x50], rax
    mov qword ptr [rsp + 0x58], 0
    call D3D11CreateDeviceAndSwapChain
    test eax, eax
    jne exit_three

    mov rcx, qword ptr [rip + device_ptr]
    lea rdx, [rip + context_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 320]

    mov rcx, qword ptr [rip + swapchain_ptr]
    xor edx, edx
    xor r8d, r8d
    lea r9, [rip + texture_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 72]
    test eax, eax
    jne exit_four

    mov rcx, qword ptr [rip + device_ptr]
    lea rdx, [rip + buffer_desc]
    xor r8d, r8d
    lea r9, [rip + buffer_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 24]
    test eax, eax
    jne exit_five

    mov rax, qword ptr [rip + buffer_ptr]
    mov qword ptr [rip + constant_buffer_bindings], rax

    mov rcx, qword ptr [rip + device_ptr]
    mov rdx, qword ptr [rip + texture_ptr]
    xor r8d, r8d
    lea r9, [rip + srv_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 56]
    test eax, eax
    jne exit_six

    mov rax, qword ptr [rip + srv_ptr]
    mov qword ptr [rip + shader_resource_bindings], rax

    mov rcx, qword ptr [rip + device_ptr]
    lea rdx, [rip + input_element_desc]
    mov r8d, 1
    lea r9, [rip + vs_dxil_blob]
    mov qword ptr [rsp + 0x20], {vs_dxil_len}
    lea rax, [rip + input_layout_ptr]
    mov qword ptr [rsp + 0x28], rax
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 88]
    test eax, eax
    jne exit_seven

    mov rcx, qword ptr [rip + device_ptr]
    lea rdx, [rip + vs_dxil_blob]
    mov r8d, {vs_dxil_len}
    xor r9d, r9d
    lea rax, [rip + vs_ptr]
    mov qword ptr [rsp + 0x20], rax
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 96]
    test eax, eax
    jne exit_eight

    mov rcx, qword ptr [rip + device_ptr]
    lea rdx, [rip + ps_dxil_blob]
    mov r8d, {ps_dxil_len}
    xor r9d, r9d
    lea rax, [rip + ps_ptr]
    mov qword ptr [rsp + 0x20], rax
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 120]
    test eax, eax
    jne exit_nine

    mov rcx, qword ptr [rip + context_ptr]
    xor edx, edx
    mov r8d, 1
    lea r9, [rip + constant_buffer_bindings]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 56]

    mov rcx, qword ptr [rip + context_ptr]
    xor edx, edx
    mov r8d, 1
    lea r9, [rip + shader_resource_bindings]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 64]

    mov rcx, qword ptr [rip + context_ptr]
    mov rdx, qword ptr [rip + input_layout_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 136]

    mov rcx, qword ptr [rip + context_ptr]
    mov rdx, qword ptr [rip + vs_ptr]
    xor r8d, r8d
    xor r9d, r9d
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 88]

    mov rcx, qword ptr [rip + context_ptr]
    mov rdx, qword ptr [rip + ps_ptr]
    xor r8d, r8d
    xor r9d, r9d
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 72]

    mov rcx, qword ptr [rip + swapchain_ptr]
    mov edx, 1
    xor r8d, r8d
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 64]
    test eax, eax
    jne exit_ten

    mov rcx, qword ptr [rip + ps_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + vs_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + input_layout_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + srv_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + buffer_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + texture_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + context_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + swapchain_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + device_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    xor ecx, ecx
    call ExitProcess

exit_one:
    mov ecx, 1
    call ExitProcess

exit_two:
    mov ecx, 2
    call ExitProcess

exit_three:
    mov ecx, 3
    call ExitProcess

exit_four:
    mov ecx, 4
    call ExitProcess

exit_five:
    mov ecx, 5
    call ExitProcess

exit_six:
    mov ecx, 6
    call ExitProcess

exit_seven:
    mov ecx, 7
    call ExitProcess

exit_eight:
    mov ecx, 8
    call ExitProcess

exit_nine:
    mov ecx, 9
    call ExitProcess

exit_ten:
    mov ecx, 10
    call ExitProcess
"#,
        vs_dxil_block = asm_byte_block("vs_dxil_blob", &vs_dxil),
        ps_dxil_block = asm_byte_block("ps_dxil_blob", &ps_dxil),
        vs_dxil_len = vs_dxil.len(),
        ps_dxil_len = ps_dxil.len(),
    );
    fs::write(&source_path, source).expect("write d3d11 shader probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,windows")
        .arg("-lkernel32")
        .arg("-luser32")
        .arg("-ld3d11")
        .arg("-ldxgi")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_real_windows_d3d11_no_swapchain_probe(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the real Windows PE build test");

    let parent = output.parent().expect("probe output parent");
    fs::create_dir_all(parent).expect("create probe output directory");
    let source_path = parent.join("real_windows_d3d11_no_swapchain_probe.s");
    fs::write(
        &source_path,
        r#".intel_syntax noprefix
.globl mainCRTStartup
.extern D3D11CreateDevice
.extern ExitProcess

.section .data,"dw"
.align 8
device_ptr:
    .quad 0
context_ptr:
    .quad 0
feature_level:
    .long 0
    .long 0

.align 8
feature_levels:
    .long 0x0000a100

.section .text,"xr"
mainCRTStartup:
    sub rsp, 0x58

    xor rcx, rcx
    mov edx, 1
    xor r8d, r8d
    xor r9d, r9d
    lea rax, [rip + feature_levels]
    mov qword ptr [rsp + 0x20], rax
    mov qword ptr [rsp + 0x28], 1
    mov qword ptr [rsp + 0x30], 7
    lea rax, [rip + device_ptr]
    mov qword ptr [rsp + 0x38], rax
    lea rax, [rip + feature_level]
    mov qword ptr [rsp + 0x40], rax
    mov qword ptr [rsp + 0x48], 0
    call D3D11CreateDevice
    test eax, eax
    jne exit_one

    mov rcx, qword ptr [rip + device_ptr]
    lea rdx, [rip + context_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 320]

    cmp qword ptr [rip + context_ptr], 0
    je exit_two

    mov rcx, qword ptr [rip + context_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    mov rcx, qword ptr [rip + device_ptr]
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 16]

    xor ecx, ecx
    call ExitProcess

exit_one:
    mov ecx, 1
    call ExitProcess

exit_two:
    mov ecx, 2
    call ExitProcess
"#,
    )
    .expect("write d3d11 no-swapchain probe source");

    let output_run = Command::new("zig")
        .arg("cc")
        .arg("-target")
        .arg("x86_64-windows-gnu")
        .arg("-nostdlib")
        .arg("-Wl,-e,mainCRTStartup")
        .arg("-Wl,--subsystem,windows")
        .arg("-lkernel32")
        .arg("-ld3d11")
        .arg("-o")
        .arg(output)
        .arg(&source_path)
        .output()
        .expect("run zig cc");
    assert!(
        output_run.status.success(),
        "zig cc failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn build_windows_tetris_game(output: &Path) {
    Command::new("zig")
        .arg("version")
        .output()
        .expect("zig must be installed for the standalone Windows Tetris build");

    let game_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("games/windows_tetris");
    let output_run = Command::new("sh")
        .arg(game_dir.join("build.sh"))
        .arg(output)
        .env("TETRIS_SMOKE", "1")
        .current_dir(&game_dir)
        .output()
        .expect("run standalone Tetris build script");
    assert!(
        output_run.status.success(),
        "standalone Tetris build failed: {}",
        String::from_utf8_lossy(&output_run.stderr)
    );
}

pub fn windows_tetris_replay(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("games/windows_tetris/replays")
        .join(name)
}

pub fn run_oracle<T>(subcommand: &str) -> T
where
    T: DeserializeOwned,
{
    let output = Command::new(env!("CARGO_BIN_EXE_casa1-oracle"))
        .arg(subcommand)
        .output()
        .expect("run casa1-oracle");
    assert!(
        output.status.success(),
        "casa1-oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse casa1-oracle JSON")
}

pub fn lifecycle_log_lines(plan: &LifecyclePlan) -> Vec<String> {
    let mut lines = Vec::new();
    for event in &plan.process_attach {
        lines.push(lifecycle_log_line(event));
    }
    for event in &plan.thread_start {
        lines.push(lifecycle_log_line(event));
    }
    for event in &plan.thread_end {
        lines.push(lifecycle_log_line(event));
    }
    for event in &plan.process_detach {
        lines.push(lifecycle_log_line(event));
    }
    lines
}

fn lifecycle_log_line(event: &casa1::pe::LifecycleEvent) -> String {
    let (stage, value) = match event.stage {
        LifecycleStage::TlsProcessAttach(callback) => ("tls_process_attach".to_string(), Some(callback)),
        LifecycleStage::DllMainProcessAttach => ("dllmain_process_attach".to_string(), None),
        LifecycleStage::TlsProcessDetach(callback) => ("tls_process_detach".to_string(), Some(callback)),
        LifecycleStage::DllMainProcessDetach => ("dllmain_process_detach".to_string(), None),
        LifecycleStage::TlsThreadAttach(callback) => ("tls_thread_attach".to_string(), Some(callback)),
        LifecycleStage::DllMainThreadAttach => ("dllmain_thread_attach".to_string(), None),
        LifecycleStage::TlsThreadDetach(callback) => ("tls_thread_detach".to_string(), Some(callback)),
        LifecycleStage::DllMainThreadDetach => ("dllmain_thread_detach".to_string(), None),
    };
    serde_json::to_string(&LifecycleLogEntry {
        module: event.module.clone(),
        stage,
        value,
    })
    .expect("encode lifecycle log line")
}
