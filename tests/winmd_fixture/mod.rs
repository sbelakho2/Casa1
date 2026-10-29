//! Synthetic ECMA-335 `.winmd` fixtures emitted at test time.
//!
//! The builder writes a minimal PE32+ image with a CLR header and a metadata
//! root containing only `#~`, `#Strings`, `#US`, `#GUID` and `#Blob`.  Table
//! rows are laid out exactly as the production reader expects, so tests can
//! corrupt individual fields/offsets without any checked-in binary.

#![allow(dead_code)]

const FILE_ALIGN: usize = 0x200;
const SECTION_RVA: u32 = 0x1000;
const CLR_OFFSET: usize = 0;
const METADATA_SECTION_OFFSET: usize = 0x80;
const ROOT_HEADER_OFFSET: usize = 32;

#[derive(Debug, Clone)]
pub struct ImportSpec {
    pub module_ref: usize,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct MethodSpec {
    pub name: String,
    pub signature: Vec<u8>,
    pub import: Option<ImportSpec>,
}

impl MethodSpec {
    pub fn plain(name: &str) -> Self {
        Self {
            name: name.to_string(),
            signature: vec![0x20, 0x00, 0x01],
            import: None,
        }
    }

    pub fn imported(name: &str, module_ref: usize, export: &str) -> Self {
        Self {
            name: name.to_string(),
            signature: vec![0x20, 0x00, 0x01],
            import: Some(ImportSpec {
                module_ref,
                name: export.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypeSpec {
    pub namespace: String,
    pub name: String,
    pub interface: bool,
    pub methods: Vec<MethodSpec>,
}

impl TypeSpec {
    pub fn api(namespace: &str, methods: Vec<MethodSpec>) -> Self {
        Self {
            namespace: namespace.to_string(),
            name: "Apis".to_string(),
            interface: false,
            methods,
        }
    }

    pub fn interface(namespace: &str, name: &str, methods: Vec<MethodSpec>) -> Self {
        Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            interface: true,
            methods,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WinmdSpec {
    pub assembly: String,
    pub module_refs: Vec<String>,
    pub types: Vec<TypeSpec>,
}

impl Default for WinmdSpec {
    fn default() -> Self {
        Self {
            assembly: "Fixture.Winmd".to_string(),
            module_refs: Vec::new(),
            types: Vec::new(),
        }
    }
}

pub struct BuiltWinmd {
    pub bytes: Vec<u8>,
    pub clr_offset: usize,
    pub metadata_offset: usize,
    pub metadata_size: usize,
    pub root_header_offset: usize,
    pub tables_offset: usize,
}

#[derive(Default)]
struct Strings {
    bytes: Vec<u8>,
    indexes: std::collections::BTreeMap<String, u32>,
}

impl Strings {
    fn new() -> Self {
        Self {
            bytes: vec![0],
            indexes: std::collections::BTreeMap::new(),
        }
    }

    fn add(&mut self, value: &str) -> u32 {
        if let Some(index) = self.indexes.get(value) {
            return *index;
        }
        let index = self.bytes.len() as u32;
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
        self.indexes.insert(value.to_string(), index);
        index
    }
}

#[derive(Default)]
struct Blobs {
    bytes: Vec<u8>,
}

impl Blobs {
    fn new() -> Self {
        Self { bytes: vec![0] }
    }

    fn add(&mut self, data: &[u8]) -> u32 {
        let index = self.bytes.len() as u32;
        if data.len() < 0x80 {
            self.bytes.push(data.len() as u8);
        } else if data.len() < 0x4000 {
            self.bytes.push(0x80 | ((data.len() >> 8) as u8));
            self.bytes.push((data.len() & 0xff) as u8);
        } else {
            self.bytes.push(0xc0 | ((data.len() >> 24) as u8));
            self.bytes.push(((data.len() >> 16) & 0xff) as u8);
            self.bytes.push(((data.len() >> 8) & 0xff) as u8);
            self.bytes.push((data.len() & 0xff) as u8);
        }
        self.bytes.extend_from_slice(data);
        index
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn stream_header_len(name: &str) -> usize {
    align4(8 + name.len() + 1)
}

pub fn build(spec: &WinmdSpec) -> BuiltWinmd {
    let mut strings = Strings::new();
    let mut blobs = Blobs::new();

    let module_name = strings.add(&spec.assembly);
    let assembly_name = strings.add(&spec.assembly);
    let module_ref_names = spec
        .module_refs
        .iter()
        .map(|name| strings.add(name))
        .collect::<Vec<_>>();

    let mut method_rows = Vec::new();
    let mut impl_map_rows = Vec::new();
    let mut type_rows = Vec::new();
    let mut next_method = 1u32;
    for ty in &spec.types {
        let name = strings.add(&ty.name);
        let namespace = strings.add(&ty.namespace);
        let flags = if ty.interface { 0x20u32 } else { 0x1u32 };
        let method_list = next_method;
        for method in &ty.methods {
            let method_name = strings.add(&method.name);
            let signature = blobs.add(&method.signature);
            method_rows.push((0u32, 0u16, 0x16u16, method_name, signature, 1u16));
            if let Some(import) = &method.import {
                let import_name = strings.add(&import.name);
                impl_map_rows.push((
                    0u16,
                    ((next_method as u16) << 1) | 1,
                    import_name,
                    (import.module_ref + 1) as u16,
                ));
            }
            next_method += 1;
        }
        type_rows.push((flags, name, namespace, 0u16, 1u16, method_list as u16));
    }

    let valid_bits: u64 = [0u32, 2, 6, 26, 28, 32]
        .iter()
        .map(|table| 1u64 << table)
        .sum();
    let mut tables = Vec::new();
    push_u32(&mut tables, 0);
    tables.push(2);
    tables.push(0);
    tables.push(0);
    tables.push(1);
    tables.extend_from_slice(&valid_bits.to_le_bytes());
    tables.extend_from_slice(&0u64.to_le_bytes());
    let counts = [
        (0u32, 1u32),
        (2u32, type_rows.len() as u32),
        (6u32, method_rows.len() as u32),
        (26u32, module_ref_names.len() as u32),
        (28u32, impl_map_rows.len() as u32),
        (32u32, 1u32),
    ];
    for (_, count) in &counts {
        push_u32(&mut tables, *count);
    }
    push_u16(&mut tables, 0);
    push_u16(&mut tables, module_name as u16);
    push_u16(&mut tables, 1);
    push_u16(&mut tables, 0);
    push_u16(&mut tables, 0);
    for (flags, name, namespace, extends, field_list, method_list) in &type_rows {
        push_u32(&mut tables, *flags);
        push_u16(&mut tables, *name as u16);
        push_u16(&mut tables, *namespace as u16);
        push_u16(&mut tables, *extends);
        push_u16(&mut tables, *field_list);
        push_u16(&mut tables, *method_list);
    }
    for (rva, impl_flags, flags, name, signature, param_list) in &method_rows {
        push_u32(&mut tables, *rva);
        push_u16(&mut tables, *impl_flags);
        push_u16(&mut tables, *flags);
        push_u16(&mut tables, *name as u16);
        push_u16(&mut tables, *signature as u16);
        push_u16(&mut tables, *param_list);
    }
    for name in &module_ref_names {
        push_u16(&mut tables, *name as u16);
    }
    for (flags, forwarded, import_name, scope) in &impl_map_rows {
        push_u16(&mut tables, *flags);
        push_u16(&mut tables, *forwarded);
        push_u16(&mut tables, *import_name as u16);
        push_u16(&mut tables, *scope);
    }
    push_u32(&mut tables, 0x8004);
    push_u16(&mut tables, 1);
    push_u16(&mut tables, 0);
    push_u16(&mut tables, 0);
    push_u16(&mut tables, 0);
    push_u32(&mut tables, 0);
    push_u16(&mut tables, 0);
    push_u16(&mut tables, assembly_name as u16);
    push_u16(&mut tables, 0);

    let mut guid_heap = vec![0u8; 16];
    guid_heap[0] = 0;
    let us_heap = vec![0u8; 4];

    let names = ["#~", "#Strings", "#US", "#GUID", "#Blob"];
    let data_bodies: [&[u8]; 5] = [&tables, &strings.bytes, &us_heap, &guid_heap, &blobs.bytes];
    let header_len = names
        .iter()
        .map(|name| stream_header_len(name))
        .sum::<usize>();
    let data_start = ROOT_HEADER_OFFSET + header_len;
    let mut offsets = Vec::new();
    let mut cursor = data_start;
    for body in data_bodies {
        offsets.push(cursor);
        cursor = align4(cursor + body.len());
    }

    let mut metadata = Vec::new();
    metadata.extend_from_slice(b"BSJB");
    push_u16(&mut metadata, 1);
    push_u16(&mut metadata, 1);
    push_u32(&mut metadata, 0);
    let version = b"v4.0.30319\0";
    push_u32(&mut metadata, version.len() as u32);
    metadata.extend_from_slice(version);
    while metadata.len() % 4 != 0 {
        metadata.push(0);
    }
    assert_eq!(metadata.len(), ROOT_HEADER_OFFSET - 4);
    push_u16(&mut metadata, 0);
    push_u16(&mut metadata, names.len() as u16);
    for (index, name) in names.iter().enumerate() {
        push_u32(&mut metadata, offsets[index] as u32);
        push_u32(&mut metadata, data_bodies[index].len() as u32);
        metadata.extend_from_slice(name.as_bytes());
        metadata.push(0);
        while metadata.len() % 4 != 0 {
            metadata.push(0);
        }
    }
    for body in data_bodies {
        metadata.extend_from_slice(body);
        while metadata.len() % 4 != 0 {
            metadata.push(0);
        }
    }

    let section_size = FILE_ALIGN.max(align4(METADATA_SECTION_OFFSET + metadata.len()));
    let mut image = vec![0u8; FILE_ALIGN + section_size];
    image[0] = b'M';
    image[1] = b'Z';
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let pe = 0x40usize;
    image[pe..pe + 4].copy_from_slice(b"PE\0\0");
    image[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    image[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
    image[pe + 20..pe + 22].copy_from_slice(&0xf0u16.to_le_bytes());
    image[pe + 22..pe + 24].copy_from_slice(&0x2022u16.to_le_bytes());
    let optional = pe + 24;
    image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    image[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
    image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    let directories = optional + 112;
    image[directories + 14 * 8..directories + 14 * 8 + 4]
        .copy_from_slice(&SECTION_RVA.to_le_bytes());
    image[directories + 14 * 8 + 4..directories + 14 * 8 + 8].copy_from_slice(&72u32.to_le_bytes());

    let section_table = optional + 0xf0;
    image[section_table..section_table + 8].copy_from_slice(b".text\0\0\0");
    image[section_table + 8..section_table + 12]
        .copy_from_slice(&(section_size as u32).to_le_bytes());
    image[section_table + 12..section_table + 16].copy_from_slice(&SECTION_RVA.to_le_bytes());
    image[section_table + 16..section_table + 20]
        .copy_from_slice(&(section_size as u32).to_le_bytes());
    image[section_table + 20..section_table + 24].copy_from_slice(&0x200u32.to_le_bytes());
    image[section_table + 36..section_table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    let section_raw = FILE_ALIGN;
    let clr = section_raw + CLR_OFFSET;
    image[clr..clr + 4].copy_from_slice(&72u32.to_le_bytes());
    image[clr + 4..clr + 6].copy_from_slice(&2u16.to_le_bytes());
    image[clr + 6..clr + 8].copy_from_slice(&5u16.to_le_bytes());
    image[clr + 8..clr + 12]
        .copy_from_slice(&(SECTION_RVA + METADATA_SECTION_OFFSET as u32).to_le_bytes());
    image[clr + 12..clr + 16].copy_from_slice(&(metadata.len() as u32).to_le_bytes());
    image[clr + 16..clr + 20].copy_from_slice(&1u32.to_le_bytes());

    let metadata_offset = section_raw + METADATA_SECTION_OFFSET;
    image[metadata_offset..metadata_offset + metadata.len()].copy_from_slice(&metadata);

    BuiltWinmd {
        bytes: image,
        clr_offset: clr,
        metadata_offset,
        metadata_size: metadata.len(),
        root_header_offset: ROOT_HEADER_OFFSET,
        tables_offset: metadata_offset + data_start,
    }
}
