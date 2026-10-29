//! Hand-built minimal PE fixtures for the inventory/corpus tests.
//!
//! No binary blobs are checked in: every fixture is emitted from this module at
//! test time, so the exact bytes under test are reviewable in source.

#![allow(dead_code)]

pub const FILE_ALIGN: usize = 0x200;
pub const SECTION_ALIGN: u32 = 0x1000;
pub const TEXT_RVA: u32 = 0x1000;
pub const TEXT_RAW: usize = 0x200;
pub const RDATA_RVA: u32 = 0x2000;
pub const RDATA_RAW: usize = 0x400;
pub const ENTRY_RVA: u32 = 0x1000;

#[derive(Debug, Clone)]
pub struct ExportSpec {
    pub ordinal: u32,
    pub name: Option<String>,
    pub forwarder: Option<String>,
    pub rva: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum ImportSymbolSpec {
    Name(String),
    Ordinal(u16),
}

#[derive(Debug, Clone)]
pub struct ImportSpec {
    pub dll: String,
    pub delay_load: bool,
    pub symbols: Vec<ImportSymbolSpec>,
}

#[derive(Debug, Clone)]
pub struct PeSpec {
    pub pe32plus: bool,
    pub code: Vec<u8>,
    pub imports: Vec<ImportSpec>,
    pub exports: Vec<ExportSpec>,
    /// Module name written into the export directory (`fixture.dll` default).
    pub export_name: String,
}

impl Default for PeSpec {
    fn default() -> Self {
        Self {
            pe32plus: true,
            code: vec![0x31, 0xc0, 0xc3],
            imports: Vec::new(),
            exports: Vec::new(),
            export_name: "fixture.dll".to_string(),
        }
    }
}

pub struct BuiltPe {
    pub bytes: Vec<u8>,
    /// `(import index, symbol index, iat_rva)` for code that calls an import.
    pub iat_rvas: Vec<(usize, usize, u32)>,
}

pub fn build(spec: &PeSpec) -> BuiltPe {
    let pointer_bytes = if spec.pe32plus { 8usize } else { 4usize };
    let optional_size = if spec.pe32plus { 0xf0usize } else { 0xe0usize };
    let data_directory_offset = if spec.pe32plus { 112usize } else { 96usize };
    let image_base = if spec.pe32plus {
        0x1_4000_0000u64
    } else {
        0x0040_0000u64
    };
    let machine = if spec.pe32plus { 0x8664u16 } else { 0x014cu16 };
    let ordinal_flag: u64 = if spec.pe32plus {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };

    let mut rdata: Vec<u8> = Vec::new();
    let mut iat_rvas = Vec::new();
    let mut import_dir = (0u32, 0u32);
    let mut delay_dir = (0u32, 0u32);

    // ── Export directory ────────────────────────────────────────────────
    let mut export_dir = None;
    if !spec.exports.is_empty() {
        let directory_rva = alloc_zeroed(&mut rdata, 40, 4, RDATA_RVA);
        let module_name_rva = alloc(&mut rdata, spec.export_name.as_bytes(), 1, RDATA_RVA);
        let _ = alloc(&mut rdata, &[0], 1, RDATA_RVA);
        let base = spec
            .exports
            .iter()
            .map(|export| export.ordinal)
            .min()
            .unwrap_or(1);
        let max = spec
            .exports
            .iter()
            .map(|export| export.ordinal)
            .max()
            .unwrap_or(base);
        let function_count = (max - base + 1) as usize;

        let mut named = spec
            .exports
            .iter()
            .filter(|export| export.name.is_some())
            .collect::<Vec<_>>();
        named.sort_by(|left, right| left.name.cmp(&right.name));
        let name_rvas = named
            .iter()
            .map(|export| {
                let name = export.name.as_deref().unwrap_or_default();
                let rva = alloc(&mut rdata, name.as_bytes(), 1, RDATA_RVA);
                alloc(&mut rdata, &[0], 1, RDATA_RVA);
                rva
            })
            .collect::<Vec<_>>();
        let forward_rvas = spec
            .exports
            .iter()
            .map(|export| {
                export.forwarder.as_ref().map(|target| {
                    let rva = alloc(&mut rdata, target.as_bytes(), 1, RDATA_RVA);
                    alloc(&mut rdata, &[0], 1, RDATA_RVA);
                    rva
                })
            })
            .collect::<Vec<_>>();

        let functions_rva = alloc_zeroed(&mut rdata, function_count * 4, 4, RDATA_RVA);
        let names_rva = alloc_zeroed(&mut rdata, named.len() * 4, 4, RDATA_RVA);
        let ordinals_rva = alloc_zeroed(&mut rdata, named.len() * 2, 2, RDATA_RVA);

        for (index, export) in spec.exports.iter().enumerate() {
            let function_index = (export.ordinal - base) as usize;
            let target = if let Some(forwarder) = &forward_rvas[index] {
                *forwarder
            } else {
                export.rva.unwrap_or(ENTRY_RVA)
            };
            patch_u32_rva(
                &mut rdata,
                functions_rva + (function_index * 4) as u32,
                target,
            );
        }
        for (index, (export, name_rva)) in named.iter().zip(name_rvas.iter()).enumerate() {
            patch_u32_rva(&mut rdata, names_rva + (index * 4) as u32, *name_rva);
            let ordinal_index = (export.ordinal - base) as u16;
            patch_u16_rva(&mut rdata, ordinals_rva + (index * 2) as u32, ordinal_index);
        }

        let end = RDATA_RVA + rdata.len() as u32;
        patch_u32_rva(&mut rdata, directory_rva + 12, module_name_rva);
        patch_u32_rva(&mut rdata, directory_rva + 16, base);
        patch_u32_rva(&mut rdata, directory_rva + 20, function_count as u32);
        patch_u32_rva(&mut rdata, directory_rva + 24, named.len() as u32);
        patch_u32_rva(&mut rdata, directory_rva + 28, functions_rva);
        patch_u32_rva(&mut rdata, directory_rva + 32, names_rva);
        patch_u32_rva(&mut rdata, directory_rva + 36, ordinals_rva);
        export_dir = Some((directory_rva, end - directory_rva));
    }

    // ── Eager imports ───────────────────────────────────────────────────
    let eager = spec
        .imports
        .iter()
        .enumerate()
        .filter(|(_, import)| !import.delay_load)
        .collect::<Vec<_>>();
    if !eager.is_empty() {
        let descriptor_rva = alloc_zeroed(&mut rdata, (eager.len() + 1) * 20, 4, RDATA_RVA);
        for (slot, (import_index, import)) in eager.iter().enumerate() {
            let name_rva = alloc(&mut rdata, import.dll.as_bytes(), 1, RDATA_RVA);
            alloc(&mut rdata, &[0], 1, RDATA_RVA);
            let thunks = build_thunks(&mut rdata, import, pointer_bytes, ordinal_flag);
            let int_rva = thunks.0;
            let iat_rva = thunks.1;
            for (symbol_index, symbol_rva) in thunks.2.iter().enumerate() {
                let _ = symbol_rva;
                iat_rvas.push((
                    *import_index,
                    symbol_index,
                    iat_rva + (symbol_index * pointer_bytes) as u32,
                ));
            }
            let descriptor = descriptor_rva + (slot * 20) as u32;
            patch_u32_rva(&mut rdata, descriptor, int_rva);
            patch_u32_rva(&mut rdata, descriptor + 12, name_rva);
            patch_u32_rva(&mut rdata, descriptor + 16, iat_rva);
        }
        import_dir = (descriptor_rva, ((eager.len() + 1) * 20) as u32);
    }

    // ── Delay-load imports ──────────────────────────────────────────────
    let delayed = spec
        .imports
        .iter()
        .enumerate()
        .filter(|(_, import)| import.delay_load)
        .collect::<Vec<_>>();
    if !delayed.is_empty() {
        let descriptor_rva = alloc_zeroed(&mut rdata, (delayed.len() + 1) * 32, 4, RDATA_RVA);
        for (slot, (import_index, import)) in delayed.iter().enumerate() {
            let name_rva = alloc(&mut rdata, import.dll.as_bytes(), 1, RDATA_RVA);
            alloc(&mut rdata, &[0], 1, RDATA_RVA);
            let thunks = build_thunks(&mut rdata, import, pointer_bytes, ordinal_flag);
            for (symbol_index, _) in thunks.2.iter().enumerate() {
                iat_rvas.push((
                    *import_index,
                    symbol_index,
                    thunks.1 + (symbol_index * pointer_bytes) as u32,
                ));
            }
            let descriptor = descriptor_rva + (slot * 32) as u32;
            patch_u32_rva(&mut rdata, descriptor + 4, name_rva);
            patch_u32_rva(&mut rdata, descriptor + 12, thunks.1);
            patch_u32_rva(&mut rdata, descriptor + 16, thunks.0);
        }
        delay_dir = (descriptor_rva, ((delayed.len() + 1) * 32) as u32);
    }

    // ── Headers ─────────────────────────────────────────────────────────
    let rdata_raw_size = align(rdata.len(), FILE_ALIGN);
    let size_of_image = align_u32(RDATA_RVA + rdata.len() as u32, SECTION_ALIGN);
    let size_of_headers = FILE_ALIGN as u32;

    let mut bytes = Vec::new();
    let mut dos = vec![0u8; 0x40];
    dos[0..2].copy_from_slice(b"MZ");
    patch_u32(&mut dos, 0x3c, 0x40);
    bytes.extend_from_slice(&dos);
    bytes.extend_from_slice(b"PE\0\0");
    bytes.extend_from_slice(&machine.to_le_bytes());
    bytes.extend_from_slice(&(2u16).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(optional_size as u16).to_le_bytes());
    bytes.extend_from_slice(&0x22u16.to_le_bytes());

    let mut optional = vec![0u8; optional_size];
    patch_u16(&mut optional, 0, if spec.pe32plus { 0x20b } else { 0x10b });
    patch_u32(&mut optional, 16, ENTRY_RVA);
    if spec.pe32plus {
        patch_u64(&mut optional, 24, image_base);
    } else {
        patch_u32(&mut optional, 28, image_base as u32);
    }
    patch_u32(&mut optional, 32, SECTION_ALIGN);
    patch_u32(&mut optional, 36, FILE_ALIGN as u32);
    patch_u32(&mut optional, 56, size_of_image);
    patch_u32(&mut optional, 60, size_of_headers);
    patch_u16(&mut optional, 68, 3);
    let data_directory_offset = data_directory_offset as u32;
    patch_u32(&mut optional, data_directory_offset - 4, 16);
    if let Some((rva, size)) = export_dir {
        patch_u32(&mut optional, data_directory_offset, rva);
        patch_u32(&mut optional, data_directory_offset + 4, size);
    }
    if import_dir.0 != 0 {
        patch_u32(&mut optional, data_directory_offset + 8, import_dir.0);
        patch_u32(&mut optional, data_directory_offset + 12, import_dir.1);
    }
    if delay_dir.0 != 0 {
        patch_u32(&mut optional, data_directory_offset + 13 * 8, delay_dir.0);
        patch_u32(
            &mut optional,
            data_directory_offset + 13 * 8 + 4,
            delay_dir.1,
        );
    }
    bytes.extend_from_slice(&optional);

    let mut text_section = vec![0u8; 40];
    text_section[0..5].copy_from_slice(b".text");
    patch_u32(&mut text_section, 8, 0x200);
    patch_u32(&mut text_section, 12, TEXT_RVA);
    patch_u32(&mut text_section, 16, FILE_ALIGN as u32);
    patch_u32(&mut text_section, 20, TEXT_RAW as u32);
    patch_u32(&mut text_section, 36, 0x6000_0020);
    bytes.extend_from_slice(&text_section);

    let mut rdata_section = vec![0u8; 40];
    rdata_section[0..6].copy_from_slice(b".rdata");
    patch_u32(&mut rdata_section, 8, rdata.len() as u32);
    patch_u32(&mut rdata_section, 12, RDATA_RVA);
    patch_u32(&mut rdata_section, 16, rdata_raw_size as u32);
    patch_u32(&mut rdata_section, 20, RDATA_RAW as u32);
    patch_u32(&mut rdata_section, 36, 0x4000_0040);
    bytes.extend_from_slice(&rdata_section);
    bytes.resize(size_of_headers as usize, 0);

    let mut text = spec.code.clone();
    text.resize(FILE_ALIGN, 0);
    bytes.extend_from_slice(&text);
    rdata.resize(rdata_raw_size, 0);
    bytes.extend_from_slice(&rdata);

    BuiltPe { bytes, iat_rvas }
}

/// `(INT RVA, IAT RVA, per-symbol thunk addresses)`.
fn build_thunks(
    rdata: &mut Vec<u8>,
    import: &ImportSpec,
    pointer_bytes: usize,
    ordinal_flag: u64,
) -> (u32, u32, Vec<u32>) {
    let mut hint_name_rvas = Vec::new();
    for symbol in &import.symbols {
        if let ImportSymbolSpec::Name(name) = symbol {
            let rva = alloc(rdata, &[0, 0], 2, RDATA_RVA);
            alloc(rdata, name.as_bytes(), 1, RDATA_RVA);
            alloc(rdata, &[0], 1, RDATA_RVA);
            hint_name_rvas.push(Some(rva));
        } else {
            hint_name_rvas.push(None);
        }
    }
    let int_rva = alloc_zeroed(
        rdata,
        (import.symbols.len() + 1) * pointer_bytes,
        pointer_bytes,
        RDATA_RVA,
    );
    let iat_rva = alloc_zeroed(
        rdata,
        (import.symbols.len() + 1) * pointer_bytes,
        pointer_bytes,
        RDATA_RVA,
    );
    let mut values = Vec::new();
    for (index, symbol) in import.symbols.iter().enumerate() {
        let value = match symbol {
            ImportSymbolSpec::Name(_) => u64::from(hint_name_rvas[index].unwrap_or(0)),
            ImportSymbolSpec::Ordinal(ordinal) => ordinal_flag | u64::from(*ordinal),
        };
        values.push(value);
        write_pointer(
            rdata,
            int_rva + (index * pointer_bytes) as u32,
            value,
            pointer_bytes,
        );
        write_pointer(
            rdata,
            iat_rva + (index * pointer_bytes) as u32,
            value,
            pointer_bytes,
        );
    }
    let _ = values;
    (
        int_rva,
        iat_rva,
        hint_name_rvas.into_iter().flatten().collect(),
    )
}

fn alloc(rdata: &mut Vec<u8>, bytes: &[u8], alignment: usize, base_rva: u32) -> u32 {
    align_vec(rdata, alignment);
    let rva = base_rva + rdata.len() as u32;
    rdata.extend_from_slice(bytes);
    rva
}

fn alloc_zeroed(rdata: &mut Vec<u8>, size: usize, alignment: usize, base_rva: u32) -> u32 {
    align_vec(rdata, alignment);
    let rva = base_rva + rdata.len() as u32;
    rdata.resize(rdata.len() + size, 0);
    rva
}

fn align_vec(data: &mut Vec<u8>, alignment: usize) {
    let target = align(data.len(), alignment);
    data.resize(target, 0);
}

fn align(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn align_u32(value: u32, alignment: u32) -> u32 {
    value.div_ceil(alignment) * alignment
}

fn patch_u16_rva(bytes: &mut [u8], rva: u32, value: u16) {
    patch_u16(bytes, rva - RDATA_RVA, value);
}

fn patch_u32_rva(bytes: &mut [u8], rva: u32, value: u32) {
    patch_u32(bytes, rva - RDATA_RVA, value);
}

fn patch_u16(bytes: &mut [u8], offset: u32, value: u16) {
    let offset = offset as usize;
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn patch_u32(bytes: &mut [u8], offset: u32, value: u32) {
    let offset = offset as usize;
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn patch_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_pointer(bytes: &mut [u8], rva: u32, value: u64, pointer_bytes: usize) {
    let offset = rva as usize - RDATA_RVA as usize;
    if pointer_bytes == 8 {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    } else {
        bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
}

/// Overwrite the first bytes of the `.text` raw payload (entry point).
pub fn patch_text(bytes: &mut [u8], code: &[u8]) {
    let start = TEXT_RAW;
    bytes[start..start + code.len()].copy_from_slice(code);
}

/// `call qword ptr [rip+disp]` to `iat_rva`, then `xor eax,eax; ret`.
pub fn call_iat_then_exit(iat_rva: u32) -> Vec<u8> {
    let next = ENTRY_RVA + 6;
    let displacement = iat_rva as i64 - i64::from(next);
    let mut code = vec![0xff, 0x15];
    code.extend_from_slice(&(displacement as i32).to_le_bytes());
    code.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    code
}

/// `sub rsp,0x28; mov ecx,code; call [rip+disp]; xor eax,eax; ret`.
pub fn exit_process_code(iat_rva: u32, code: i32) -> Vec<u8> {
    let mut bytes = vec![0x48, 0x83, 0xec, 0x28, 0xb9];
    bytes.extend_from_slice(&code.to_le_bytes());
    let next = ENTRY_RVA + bytes.len() as u32 + 6;
    let displacement = i64::from(iat_rva) - i64::from(next);
    bytes.extend_from_slice(&[0xff, 0x15]);
    bytes.extend_from_slice(&(displacement as i32).to_le_bytes());
    bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    bytes
}

/// `ud2` — a deterministic guest fault.
pub fn crash_code() -> Vec<u8> {
    vec![0x0f, 0x0b]
}

/// `jmp $` — a deterministic infinite loop (used to exercise timeouts).
pub fn hang_code() -> Vec<u8> {
    vec![0xeb, 0xfe]
}

pub fn trivial_exit_code(code: i32) -> Vec<u8> {
    let mut bytes = vec![0xb8];
    bytes.extend_from_slice(&code.to_le_bytes());
    bytes.push(0xc3);
    bytes
}

/// Ensure `SizeOfImage`/section alignment used by the builder stays valid when
/// tests grow the `.rdata` payload.
pub fn image_size(spec: &PeSpec) -> u32 {
    let built = build(spec);
    let optional_offset = 0x40 + 4 + 20;
    let offset = if spec.pe32plus {
        optional_offset + 56
    } else {
        optional_offset + 56
    };
    u32::from_le_bytes([
        built.bytes[offset],
        built.bytes[offset + 1],
        built.bytes[offset + 2],
        built.bytes[offset + 3],
    ])
}

pub fn align_u32_public(value: u32, alignment: u32) -> u32 {
    align_u32(value, alignment)
}
