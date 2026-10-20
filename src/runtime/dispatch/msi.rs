//! Windows Installer dispatch: the msi.dll exports, in a dedicated module
//! per the audit's modularity requirement.  No products are installed in
//! the runtime, so the product surface answers the documented empty-state
//! semantics: `MsiEnumProductsW` reports ERROR_NO_MORE_ITEMS and
//! `MsiGetProductInfoW`/`MsiQueryProductInfoW` report ERROR_UNKNOWN_PRODUCT.
//!
//! The database surface is real: `MsiOpenDatabaseW` parses the OLE compound
//! file (header, DIFAT, FAT, miniFAT and directory), extracts the MSI schema
//! streams (`_StringPool`, `_StringData`, `_Tables`, `_Columns`,
//! `_Validation`) and decodes the transposed table streams into typed
//! records.  Views parse SQL SELECT statements, fetch real rows, and
//! INSERT/UPDATE/DELETE mutate the in-memory database.  `MsiDatabaseCommit`
//! rewrites the whole compound file, so the round trip is storage-real (the
//! writer emits a CFB v3 file with FAT, miniFAT and DIFAT support) rather
//! than a stubbed commit.
//!
//! Layer contract: every export returns its ERROR_* code in EAX (0 =
//! ERROR_SUCCESS).

use std::collections::BTreeMap;

use super::super::*;
use crate::runtime::state::GuestObjectKind;

/// ERROR_SUCCESS.
const ERROR_SUCCESS: u32 = 0;
/// ERROR_ACCESS_DENIED.
const ERROR_ACCESS_DENIED: u32 = 5;
/// ERROR_INVALID_HANDLE.
const ERROR_INVALID_HANDLE: u32 = 6;
/// ERROR_INVALID_DATA.
const ERROR_INVALID_DATA: u32 = 13;
/// ERROR_INVALID_PARAMETER.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_MORE_DATA.
const ERROR_MORE_DATA: u32 = 234;
/// ERROR_NO_MORE_ITEMS.
const ERROR_NO_MORE_ITEMS: u32 = 259;
/// ERROR_UNKNOWN_PRODUCT.
const ERROR_UNKNOWN_PRODUCT: u32 = 1605;
/// ERROR_UNKNOWN_PROPERTY.
const ERROR_UNKNOWN_PROPERTY: u32 = 1608;
/// ERROR_INVALID_FIELD.
const ERROR_INVALID_FIELD: u32 = 1614;
/// ERROR_BAD_QUERY_SYNTAX.
const ERROR_BAD_QUERY_SYNTAX: u32 = 1615;
/// ERROR_INVALID_TABLE.
const ERROR_INVALID_TABLE: u32 = 1626;
/// ERROR_FUNCTION_FAILED.
const ERROR_FUNCTION_FAILED: u32 = 1627;
/// ERROR_INVALID_DATATYPE.
const ERROR_INVALID_DATATYPE: u32 = 1804;
/// ERROR_INSTALL_PACKAGE_OPEN_FAILED.
const ERROR_INSTALL_PACKAGE_OPEN_FAILED: u32 = 1619;

/// The OLE compound-document magic (an MSI database is an OLE file).
const OLE_MAGIC: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

/// The compound-file allocation markers.
const FREESECT: u32 = 0xFFFF_FFFF;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FATSECT: u32 = 0xFFFF_FFFD;
const DIFSECT: u32 = 0xFFFF_FFFC;
const NOSTREAM: u32 = 0xFFFF_FFFF;

/// MSI column type flags (`msipriv.h`).
const MSITYPE_VALID: u16 = 0x0100;
const MSITYPE_STRING: u16 = 0x0800;
const MSITYPE_NULLABLE: u16 = 0x1000;
const MSITYPE_KEY: u16 = 0x2000;

/// A typed MSI field.  View records carry either a fetched field or one of
/// the values written through `MsiRecordSetStringW`/`MsiRecordSetInteger`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MsiValue {
    Null,
    Int(i32),
    Str(String),
    Stream(Vec<u8>),
}

/// An MSI record handle.  Field 0 is the record/row selector used by
/// `MsiViewModify`; the data fields are 1-based.
#[derive(Debug, Clone)]
pub(crate) struct MsiRecord {
    pub(crate) fields: Vec<MsiValue>,
    pub(crate) stream_positions: Vec<usize>,
}

impl MsiRecord {
    fn new(count: usize) -> Self {
        Self {
            fields: vec![MsiValue::Null; count + 1],
            stream_positions: vec![0; count + 1],
        }
    }

    fn field(&self, index: usize) -> Option<&MsiValue> {
        self.fields.get(index)
    }
}

/// One column definition decoded from `_Columns`.
#[derive(Debug, Clone)]
pub(crate) struct MsiColumn {
    pub(crate) name: String,
    pub(crate) type_bits: u16,
}

impl MsiColumn {
    fn width(&self) -> u16 {
        self.type_bits & 0x00FF
    }

    fn is_binary(&self) -> bool {
        (self.type_bits & !MSITYPE_NULLABLE) == (MSITYPE_STRING | MSITYPE_VALID)
    }

    fn is_string(&self) -> bool {
        self.type_bits & MSITYPE_STRING != 0 && !self.is_binary()
    }

    fn is_key(&self) -> bool {
        self.type_bits & MSITYPE_KEY != 0
    }

    fn is_nullable(&self) -> bool {
        self.type_bits & MSITYPE_NULLABLE != 0
    }

    fn storage_width(&self, string_ref: usize) -> usize {
        if self.is_binary() {
            2
        } else if self.is_string() {
            string_ref
        } else if self.width() <= 2 {
            2
        } else {
            4
        }
    }

    fn type_name(&self) -> String {
        if self.is_binary() {
            "v0".to_string()
        } else if self.is_string() {
            format!("s{}", self.width())
        } else {
            format!("i{}", self.width().max(2))
        }
    }
}

/// One MSI table: the decoded schema plus the in-memory rows.
#[derive(Debug, Clone, Default)]
pub(crate) struct MsiTable {
    pub(crate) name: String,
    pub(crate) columns: Vec<MsiColumn>,
    pub(crate) rows: Vec<Vec<MsiValue>>,
}

/// A parsed WHERE equality term.
#[derive(Debug, Clone)]
struct MsiFilter {
    column: usize,
    value: MsiValue,
}

/// A parsed SELECT statement.
#[derive(Debug, Clone)]
struct MsiQuery {
    columns: Option<Vec<String>>,
    table: String,
    filters: Vec<(String, MsiValue)>,
}

/// The host state behind an MSI database handle.  The schema and rows are
/// fully decoded; `extras` carries the raw streams that the runtime does not
/// interpret (`_Validation`, `_ForceCodepage`, summary information, binary
/// payloads) so a commit preserves them.
#[derive(Debug, Clone)]
pub(crate) struct MsiDatabaseState {
    pub(crate) path: String,
    strings: Vec<String>,
    tables: BTreeMap<String, MsiTable>,
    extras: BTreeMap<String, (bool, Vec<u8>)>,
}

/// A view: the parsed query plus the executed row snapshot.
#[derive(Debug, Clone)]
pub(crate) struct MsiViewState {
    db: u64,
    table: String,
    columns: Vec<usize>,
    filters: Vec<MsiFilter>,
    rows: Vec<usize>,
    next: usize,
    executed: bool,
}

/// A directory entry in an OLE compound file.
#[derive(Debug, Clone)]
struct CompoundEntry {
    name: String,
    kind: u8,
    start: u32,
    size: u64,
}

/// A parsed OLE compound file (CFB v3/v4) with its allocation tables and
/// directory.  Streams are read on demand from the raw file bytes.
#[derive(Debug, Clone)]
struct CompoundFile {
    bytes: Vec<u8>,
    sector_size: usize,
    mini_sector_size: usize,
    cutoff: u32,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    entries: Vec<CompoundEntry>,
    mini_stream: Vec<u8>,
}

fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
}

fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|slice| {
        let mut data = [0_u8; 8];
        data.copy_from_slice(slice);
        u64::from_le_bytes(data)
    })
}

impl CompoundFile {
    fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < 512 || bytes[..8] != OLE_MAGIC {
            return Err("not an OLE compound file".to_string());
        }
        let major = le_u16(&bytes, 0x1A).ok_or("truncated header")?;
        if major != 3 && major != 4 {
            return Err(format!("unsupported compound-file version {major}"));
        }
        let sector_shift = le_u16(&bytes, 0x1E).ok_or("truncated header")?;
        let mini_shift = le_u16(&bytes, 0x20).ok_or("truncated header")?;
        if !(9..=12).contains(&sector_shift) || mini_shift != 6 {
            return Err("invalid sector sizes".to_string());
        }
        let sector_size = 1usize << sector_shift;
        let mini_sector_size = 1usize << mini_shift;
        let fat_count = le_u32(&bytes, 0x28).ok_or("truncated header")?;
        let dir_start = le_u32(&bytes, 0x2C).ok_or("truncated header")?;
        let cutoff = le_u32(&bytes, 0x34).ok_or("truncated header")?;
        let mini_fat_start = le_u32(&bytes, 0x38).ok_or("truncated header")?;
        let mini_fat_count = le_u32(&bytes, 0x3C).ok_or("truncated header")?;
        let difat_start = le_u32(&bytes, 0x40).ok_or("truncated header")?;
        let difat_count = le_u32(&bytes, 0x44).ok_or("truncated header")?;

        let mut fat_sectors = Vec::new();
        for index in 0..109 {
            let sector = le_u32(&bytes, 0x48 + index * 4).ok_or("truncated header")?;
            if sector != FREESECT {
                fat_sectors.push(sector);
            }
        }
        let mut current = difat_start;
        let mut visited = 0u32;
        while current != ENDOFCHAIN && current != FREESECT && visited < difat_count.max(1) + 1 {
            let sector = Self::sector_slice(&bytes, current, sector_size)?;
            let entries = sector_size / 4;
            for index in 0..entries.saturating_sub(1) {
                let fat_sector = le_u32(sector, index * 4).ok_or("truncated DIFAT")?;
                if fat_sector != FREESECT {
                    fat_sectors.push(fat_sector);
                }
            }
            current = le_u32(sector, (entries - 1) * 4).ok_or("truncated DIFAT")?;
            visited += 1;
        }
        fat_sectors.truncate(fat_count as usize);

        let mut fat = Vec::new();
        for sector_id in fat_sectors {
            let sector = Self::sector_slice(&bytes, sector_id, sector_size)?;
            for index in 0..sector_size / 4 {
                fat.push(le_u32(sector, index * 4).ok_or("truncated FAT")?);
            }
        }
        if fat.is_empty() {
            return Err("compound file has no FAT".to_string());
        }

        let directory_raw = Self::read_chain(&bytes, dir_start, &fat, sector_size, usize::MAX)?;
        let mut entries = Vec::new();
        for chunk in directory_raw.chunks_exact(128) {
            let name_len = le_u16(chunk, 0x40).unwrap_or(0) as usize;
            let units = name_len.saturating_div(2).saturating_sub(1).min(31);
            let name_units: Vec<u16> = (0..units)
                .map(|index| le_u16(chunk, index * 2).unwrap_or(0))
                .collect();
            let name = String::from_utf16_lossy(&name_units);
            let kind = chunk[0x42];
            let start = le_u32(chunk, 0x74).unwrap_or(ENDOFCHAIN);
            let size = if major == 3 {
                u64::from(le_u32(chunk, 0x78).unwrap_or(0))
            } else {
                le_u64(chunk, 0x78).unwrap_or(0)
            };
            entries.push(CompoundEntry {
                name,
                kind,
                start,
                size,
            });
        }

        let mut mini_fat = Vec::new();
        if mini_fat_start != ENDOFCHAIN && mini_fat_count > 0 {
            let raw = Self::read_chain(&bytes, mini_fat_start, &fat, sector_size, usize::MAX)?;
            for chunk in raw.chunks_exact(4) {
                mini_fat.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }

        let root = entries.iter().find(|entry| entry.kind == 5);
        let mini_stream = match root {
            Some(root) if root.size > 0 && root.start != ENDOFCHAIN => {
                Self::read_chain(&bytes, root.start, &fat, sector_size, root.size as usize)?
            }
            _ => Vec::new(),
        };

        Ok(Self {
            bytes,
            sector_size,
            mini_sector_size,
            cutoff,
            fat,
            mini_fat,
            entries,
            mini_stream,
        })
    }

    fn sector_slice(bytes: &[u8], sector: u32, sector_size: usize) -> Result<&[u8], String> {
        if sector >= 0xFFFF_FFF0 {
            return Err("invalid sector reference".to_string());
        }
        let offset = (sector as usize + 1) * sector_size;
        bytes
            .get(offset..offset + sector_size)
            .ok_or_else(|| format!("sector {sector} is past end of file"))
    }

    fn read_chain(
        bytes: &[u8],
        start: u32,
        table: &[u32],
        sector_size: usize,
        size: usize,
    ) -> Result<Vec<u8>, String> {
        if start == ENDOFCHAIN || start == FREESECT || size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut current = start;
        let mut visited = 0usize;
        while current != ENDOFCHAIN && current != FREESECT && out.len() < size {
            let sector = Self::sector_slice(bytes, current, sector_size)?;
            let remaining = size.saturating_sub(out.len());
            out.extend_from_slice(&sector[..remaining.min(sector_size)]);
            current = *table
                .get(current as usize)
                .ok_or_else(|| format!("chain sector {current} is outside the FAT"))?;
            visited += 1;
            if visited > table.len() + 1 {
                return Err("compound-file chain loop".to_string());
            }
        }
        out.truncate(size);
        Ok(out)
    }

    fn read_entry(&self, entry: &CompoundEntry) -> Result<Vec<u8>, String> {
        if entry.size == 0 {
            return Ok(Vec::new());
        }
        let use_mini = entry.size < u64::from(self.cutoff)
            && (entry.start as usize) * self.mini_sector_size < self.mini_stream.len();
        if use_mini {
            let mut out = Vec::new();
            let mut current = entry.start;
            let mut visited = 0usize;
            while current != ENDOFCHAIN && current != FREESECT && out.len() < entry.size as usize {
                let offset = current as usize * self.mini_sector_size;
                let end = offset + self.mini_sector_size;
                let sector = self
                    .mini_stream
                    .get(offset..end)
                    .ok_or("mini sector past end of mini stream")?;
                let remaining = entry.size as usize - out.len();
                out.extend_from_slice(&sector[..remaining.min(self.mini_sector_size)]);
                current = *self
                    .mini_fat
                    .get(current as usize)
                    .ok_or("mini chain sector is outside the miniFAT")?;
                visited += 1;
                if visited > self.mini_fat.len() + 1 {
                    return Err("mini stream chain loop".to_string());
                }
            }
            out.truncate(entry.size as usize);
            return Ok(out);
        }
        if entry.start == ENDOFCHAIN {
            return Ok(Vec::new());
        }
        Self::read_chain(
            &self.bytes,
            entry.start,
            &self.fat,
            self.sector_size,
            entry.size as usize,
        )
    }

    fn stream(&self, name: &str) -> Option<Vec<u8>> {
        let wanted = name.trim_start_matches('\u{4840}');
        for entry in &self.entries {
            if entry.kind != 2 {
                continue;
            }
            let decoded = decode_stream_name(&entry.name);
            let decoded = decoded.trim_start_matches('\u{4840}');
            if decoded == wanted || entry.name == name || entry.name.eq_ignore_ascii_case(name) {
                return self.read_entry(entry).ok();
            }
        }
        None
    }

    fn stream_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.kind == 2)
            .map(|entry| {
                let decoded = decode_stream_name(&entry.name);
                decoded.trim_start_matches('\u{4840}').to_string()
            })
            .collect()
    }
}

impl MsiDatabaseState {
    fn empty(path: String) -> Self {
        let mut database = Self {
            path,
            strings: vec![String::new()],
            tables: BTreeMap::new(),
            extras: BTreeMap::new(),
        };
        database.install_system_tables();
        database
    }

    fn install_system_tables(&mut self) {
        self.tables.insert(
            "_Tables".to_string(),
            MsiTable {
                name: "_Tables".to_string(),
                columns: vec![MsiColumn {
                    name: "Name".to_string(),
                    type_bits: MSITYPE_VALID | MSITYPE_STRING | MSITYPE_KEY | 64,
                }],
                rows: Vec::new(),
            },
        );
        self.tables.insert(
            "_Columns".to_string(),
            MsiTable {
                name: "_Columns".to_string(),
                columns: vec![
                    MsiColumn {
                        name: "Table".to_string(),
                        type_bits: MSITYPE_VALID | MSITYPE_STRING | MSITYPE_KEY | 64,
                    },
                    MsiColumn {
                        name: "Number".to_string(),
                        type_bits: MSITYPE_VALID | MSITYPE_KEY | 2,
                    },
                    MsiColumn {
                        name: "Name".to_string(),
                        type_bits: MSITYPE_VALID | MSITYPE_STRING | 64,
                    },
                    MsiColumn {
                        name: "Type".to_string(),
                        type_bits: MSITYPE_VALID | 2,
                    },
                ],
                rows: Vec::new(),
            },
        );
    }

    fn table(&self, name: &str) -> Option<&MsiTable> {
        self.tables.get(name).or_else(|| {
            self.tables
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, table)| table)
        })
    }

    fn table_mut(&mut self, name: &str) -> Option<&mut MsiTable> {
        if self.tables.contains_key(name) {
            return self.tables.get_mut(name);
        }
        let key = self
            .tables
            .keys()
            .find(|key| key.eq_ignore_ascii_case(name))
            .cloned()?;
        self.tables.get_mut(&key)
    }

    fn load_from_compound(path: String, compound: &CompoundFile) -> Self {
        let pool = compound.stream("_StringPool").unwrap_or_default();
        let data = compound.stream("_StringData").unwrap_or_default();
        let (strings, string_ref) = load_string_table(&pool, &data);
        let mut database = Self {
            path,
            strings,
            tables: BTreeMap::new(),
            extras: BTreeMap::new(),
        };
        database.install_system_tables();

        let tables_columns = database
            .tables
            .get("_Tables")
            .map(|table| table.columns.clone())
            .unwrap_or_default();
        let tables_rows = compound
            .stream("_Tables")
            .map(|raw| {
                decode_table_rows(
                    &raw,
                    &database.strings,
                    &tables_columns,
                    string_ref,
                    "_Tables",
                    Some(compound),
                )
            })
            .unwrap_or_default();
        if let Some(table) = database.tables.get_mut("_Tables") {
            table.rows = tables_rows;
        }
        let columns_columns = database
            .tables
            .get("_Columns")
            .map(|table| table.columns.clone())
            .unwrap_or_default();
        let columns_rows = compound
            .stream("_Columns")
            .map(|raw| {
                decode_table_rows(
                    &raw,
                    &database.strings,
                    &columns_columns,
                    string_ref,
                    "_Columns",
                    Some(compound),
                )
            })
            .unwrap_or_default();
        if let Some(table) = database.tables.get_mut("_Columns") {
            table.rows = columns_rows;
        }

        let mut table_names: Vec<String> = Vec::new();
        if let Some(tables) = database.tables.get("_Tables") {
            for row in &tables.rows {
                if let Some(MsiValue::Str(name)) = row.first() {
                    if !name.is_empty() && !table_names.iter().any(|known| known == name) {
                        table_names.push(name.clone());
                    }
                }
            }
        }
        if let Some(columns) = database.tables.get("_Columns") {
            for row in &columns.rows {
                if let Some(MsiValue::Str(name)) = row.first() {
                    if !name.is_empty() && !table_names.iter().any(|known| known == name) {
                        table_names.push(name.clone());
                    }
                }
            }
        }

        for name in table_names {
            if name.eq_ignore_ascii_case("_Tables") || name.eq_ignore_ascii_case("_Columns") {
                continue;
            }
            let schema = schema_for_table(&database, &name);
            if schema.is_empty() {
                continue;
            }
            let mut table = MsiTable {
                name: name.clone(),
                columns: schema,
                rows: Vec::new(),
            };
            if let Some(raw) = compound.stream(&name) {
                table.rows = decode_table_rows(
                    &raw,
                    &database.strings,
                    &table.columns,
                    string_ref,
                    &name,
                    Some(compound),
                );
            }
            database.tables.insert(name, table);
        }

        for stream_name in compound.stream_names() {
            let covered = database.tables.contains_key(&stream_name)
                || matches!(
                    stream_name.as_str(),
                    "_StringPool" | "_StringData" | "_Tables" | "_Columns"
                );
            if covered {
                continue;
            }
            if let Some(bytes) = compound.stream(&stream_name) {
                let system = stream_name.starts_with('_');
                database.extras.insert(stream_name, (system, bytes));
            }
        }
        database
    }
}

/// Build the schema for one user table from the decoded `_Columns` rows.
fn schema_for_table(database: &MsiDatabaseState, name: &str) -> Vec<MsiColumn> {
    let Some(columns_table) = database.table("_Columns") else {
        return Vec::new();
    };
    let mut found: BTreeMap<u16, MsiColumn> = BTreeMap::new();
    for row in &columns_table.rows {
        let MsiValue::Str(table_name) = row.first().cloned().unwrap_or(MsiValue::Null) else {
            continue;
        };
        if !table_name.eq_ignore_ascii_case(name) {
            continue;
        }
        let number = match row.get(1) {
            Some(MsiValue::Int(number)) if *number > 0 && *number <= u16::MAX as i32 => {
                *number as u16
            }
            _ => continue,
        };
        let MsiValue::Str(column_name) = row.get(2).cloned().unwrap_or(MsiValue::Null) else {
            continue;
        };
        let type_bits = match row.get(3) {
            Some(MsiValue::Int(value)) => *value as u16,
            _ => 0,
        };
        found.insert(
            number,
            MsiColumn {
                name: column_name,
                type_bits,
            },
        );
    }
    found.into_values().collect()
}

impl PeHostRuntime {
    /// Route every MSI thunk to its dispatch function.
    pub(crate) fn dispatch_msi(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::MsiEnumProductsW => {
                // No products are installed.
                state.set(Register::Rax, u64::from(ERROR_NO_MORE_ITEMS));
                Ok(())
            }
            HostThunk::MsiGetProductInfoW | HostThunk::MsiQueryProductInfoW => {
                state.set(Register::Rax, u64::from(ERROR_UNKNOWN_PRODUCT));
                Ok(())
            }
            HostThunk::MsiGetPropertyW | HostThunk::MsiSetPropertyW => {
                // No install session is active.
                state.set(Register::Rax, u64::from(ERROR_UNKNOWN_PROPERTY));
                Ok(())
            }
            HostThunk::MsiInstallProductW
            | HostThunk::MsiConfigureProductW
            | HostThunk::MsiReinstallProductW => {
                // The package cannot be opened.
                state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
                Ok(())
            }
            HostThunk::MsiOpenDatabaseW | HostThunk::MsiOpenPackageW => {
                self.dispatch_msi_open_database(state, memory)
            }
            HostThunk::MsiDatabaseOpenViewW => self.dispatch_msi_open_view(state, memory),
            HostThunk::MsiViewExecute => {
                let view = guest_call_arg(state, memory, 0)?;
                let result = self.msi_execute_view(view);
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiViewFetch => {
                let view = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let (result, record) = self.msi_fetch(view, memory);
                if record != 0 && out != 0 {
                    write_guest_pointer(memory, out, record, self.guest_arch).ok();
                } else if out != 0 && result != ERROR_SUCCESS {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiViewClose => {
                let view = guest_call_arg(state, memory, 0)?;
                let result = match self.msi_views.get_mut(&view) {
                    Some(view) => {
                        view.rows.clear();
                        view.next = 0;
                        view.executed = false;
                        ERROR_SUCCESS
                    }
                    None => ERROR_INVALID_HANDLE,
                };
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiViewGetColumnInfo => {
                let view = guest_call_arg(state, memory, 0)?;
                let info = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                let (result, record) = self.msi_column_info(view, info, memory);
                if record != 0 && out != 0 {
                    write_guest_pointer(memory, out, record, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiViewModify => {
                let view = guest_call_arg(state, memory, 0)?;
                let mode = guest_call_arg_u32(state, memory, 1)?;
                let record = guest_call_arg(state, memory, 2)?;
                let result = self.msi_view_modify(view, mode, record);
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiCreateRecord => {
                let fields = guest_call_arg_u32(state, memory, 0)?;
                let (result, record) = self.msi_create_record(fields as usize, memory);
                state.set(
                    Register::Rax,
                    if result == ERROR_SUCCESS { record } else { 0 },
                );
                Ok(())
            }
            HostThunk::MsiRecordDataSize => {
                let record = guest_call_arg(state, memory, 0)?;
                let field = guest_call_arg_u32(state, memory, 1)?;
                let size = self
                    .msi_records
                    .get(&record)
                    .and_then(|record| record.field(field as usize))
                    .map(msi_value_size)
                    .unwrap_or(0);
                state.set(Register::Rax, u64::from(size));
                Ok(())
            }
            HostThunk::MsiRecordGetInteger => {
                let record = guest_call_arg(state, memory, 0)?;
                let field = guest_call_arg_u32(state, memory, 1)?;
                let value = self
                    .msi_records
                    .get(&record)
                    .and_then(|record| record.field(field as usize))
                    .map(|value| match value {
                        MsiValue::Int(number) => *number,
                        MsiValue::Str(text) => text.trim().parse::<i32>().unwrap_or(i32::MIN),
                        MsiValue::Null => i32::MIN,
                        MsiValue::Stream(_) => 0,
                    })
                    .unwrap_or(i32::MIN);
                state.set(Register::Rax, u64::from(value as u32));
                Ok(())
            }
            HostThunk::MsiRecordGetStringW => self.dispatch_msi_record_get_string(state, memory),
            HostThunk::MsiRecordSetStringW => {
                let record = guest_call_arg(state, memory, 0)?;
                let field = guest_call_arg_u32(state, memory, 1)?;
                let text = guest_call_arg(state, memory, 2)?;
                let value = read_utf16_string(memory, text).unwrap_or_default();
                let result = match self.msi_records.get_mut(&record) {
                    Some(record) if (field as usize) < record.fields.len() => {
                        record.fields[field as usize] = MsiValue::Str(value);
                        ERROR_SUCCESS
                    }
                    Some(_) => ERROR_INVALID_FIELD,
                    None => ERROR_INVALID_HANDLE,
                };
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiRecordSetInteger => {
                let record = guest_call_arg(state, memory, 0)?;
                let field = guest_call_arg_u32(state, memory, 1)?;
                let value = guest_call_arg_u32(state, memory, 2)? as i32;
                let result = match self.msi_records.get_mut(&record) {
                    Some(record) if (field as usize) < record.fields.len() => {
                        record.fields[field as usize] = MsiValue::Int(value);
                        ERROR_SUCCESS
                    }
                    Some(_) => ERROR_INVALID_FIELD,
                    None => ERROR_INVALID_HANDLE,
                };
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiRecordReadStream => self.dispatch_msi_record_read_stream(state, memory),
            HostThunk::MsiDatabaseCommit => {
                let database = guest_call_arg(state, memory, 0)?;
                let result = self.msi_commit(database);
                state.set(Register::Rax, u64::from(result));
                Ok(())
            }
            HostThunk::MsiCloseHandle => {
                let handle = guest_call_arg(state, memory, 0)?;
                let closed = self.msi_databases.remove(&handle).is_some()
                    | self.msi_views.remove(&handle).is_some()
                    | self.msi_records.remove(&handle).is_some();
                state.set(
                    Register::Rax,
                    u64::from(if closed {
                        ERROR_SUCCESS
                    } else {
                        ERROR_INVALID_HANDLE
                    }),
                );
                Ok(())
            }
            HostThunk::MsiCloseAllHandles => {
                self.msi_databases.clear();
                self.msi_views.clear();
                self.msi_records.clear();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted MSI thunk {thunk:?}"),
            )),
        }
    }

    /// `MsiOpenDatabaseW(persistedPath, persist, phDatabase)` — parse the
    /// OLE compound file and decode the MSI schema into the handle state.
    pub(crate) fn dispatch_msi_open_database(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let path_ptr = guest_call_arg(state, memory, 0)?;
        let _persist = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Ok(path) = read_utf16_string(memory, path_ptr) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
            return Ok(());
        };
        let Ok(bytes) = std::fs::read(&path) else {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        };
        if bytes.len() < 8 || bytes[..8] != OLE_MAGIC {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        }
        let database = match CompoundFile::parse(bytes.clone()) {
            Ok(compound) => MsiDatabaseState::load_from_compound(path.clone(), &compound),
            Err(_) if bytes.len() == 512 && bytes[8..].iter().all(|byte| *byte == 0) => {
                // The legacy placeholder database: a magic-only header is an
                // empty, storage-less database rather than a hard failure.
                MsiDatabaseState::empty(path.clone())
            }
            Err(_) => {
                state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
                return Ok(());
            }
        };
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let handle = self
            .alloc_guest_object(memory, GuestObjectKind::MsiDatabase, vtable)
            .unwrap_or(0);
        if handle == 0 {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        }
        self.msi_databases.insert(handle, database);
        if out != 0 {
            write_guest_pointer(memory, out, handle, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    /// `MsiDatabaseOpenViewW(db, query, view)` — parse the SELECT statement
    /// against the real schema and hand out a view handle.
    pub(crate) fn dispatch_msi_open_view(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let db = guest_call_arg(state, memory, 0)?;
        let query = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(database) = self.msi_databases.get(&db) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
            return Ok(());
        };
        let query_text = read_utf16_string(memory, query).unwrap_or_default();
        let parsed = match parse_select(&query_text) {
            Ok(parsed) => parsed,
            Err(()) => {
                state.set(Register::Rax, u64::from(ERROR_BAD_QUERY_SYNTAX));
                return Ok(());
            }
        };
        let Some(table) = database.table(&parsed.table) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_TABLE));
            return Ok(());
        };
        let table_name = table.name.clone();
        let columns = match &parsed.columns {
            None => (0..table.columns.len()).collect::<Vec<_>>(),
            Some(names) => {
                let mut indices = Vec::new();
                for name in names {
                    match table
                        .columns
                        .iter()
                        .position(|column| column.name.eq_ignore_ascii_case(name))
                    {
                        Some(index) => indices.push(index),
                        None => {
                            state.set(Register::Rax, u64::from(ERROR_BAD_QUERY_SYNTAX));
                            return Ok(());
                        }
                    }
                }
                indices
            }
        };
        let mut filters = Vec::new();
        for (name, literal) in &parsed.filters {
            let Some(index) = table
                .columns
                .iter()
                .position(|column| column.name.eq_ignore_ascii_case(name))
            else {
                state.set(Register::Rax, u64::from(ERROR_BAD_QUERY_SYNTAX));
                return Ok(());
            };
            let column = &table.columns[index];
            if column.is_binary() {
                state.set(Register::Rax, u64::from(ERROR_BAD_QUERY_SYNTAX));
                return Ok(());
            }
            let value = match (column.is_string(), literal) {
                (true, MsiValue::Str(text)) => MsiValue::Str(text.clone()),
                (true, MsiValue::Int(number)) => MsiValue::Str(number.to_string()),
                (false, MsiValue::Int(number)) => MsiValue::Int(*number),
                (false, MsiValue::Str(text)) => match text.trim().parse::<i32>() {
                    Ok(number) => MsiValue::Int(number),
                    Err(_) => {
                        state.set(Register::Rax, u64::from(ERROR_BAD_QUERY_SYNTAX));
                        return Ok(());
                    }
                },
                _ => {
                    state.set(Register::Rax, u64::from(ERROR_BAD_QUERY_SYNTAX));
                    return Ok(());
                }
            };
            filters.push(MsiFilter {
                column: index,
                value,
            });
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let view = self
            .alloc_guest_object(memory, GuestObjectKind::MsiView, vtable)
            .unwrap_or(0);
        if view == 0 {
            state.set(Register::Rax, u64::from(ERROR_INSTALL_PACKAGE_OPEN_FAILED));
            return Ok(());
        }
        self.msi_views.insert(
            view,
            MsiViewState {
                db,
                table: table_name,
                columns,
                filters,
                rows: Vec::new(),
                next: 0,
                executed: false,
            },
        );
        if out != 0 {
            write_guest_pointer(memory, out, view, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    fn msi_execute_view(&mut self, handle: u64) -> u32 {
        let Some(view) = self.msi_views.get(&handle) else {
            return ERROR_INVALID_HANDLE;
        };
        let Some(database) = self.msi_databases.get(&view.db) else {
            return ERROR_INVALID_HANDLE;
        };
        let rows = matching_rows(database, view);
        let Some(view) = self.msi_views.get_mut(&handle) else {
            return ERROR_INVALID_HANDLE;
        };
        view.rows = rows;
        view.next = 0;
        view.executed = true;
        ERROR_SUCCESS
    }

    fn msi_fetch(&mut self, handle: u64, memory: &mut MemoryImage) -> (u32, u64) {
        let Some(view) = self.msi_views.get(&handle) else {
            return (ERROR_INVALID_HANDLE, 0);
        };
        if !view.executed || view.next >= view.rows.len() {
            return (ERROR_NO_MORE_ITEMS, 0);
        }
        let Some(database) = self.msi_databases.get(&view.db) else {
            return (ERROR_INVALID_HANDLE, 0);
        };
        let Some(table) = database.table(&view.table) else {
            return (ERROR_INVALID_TABLE, 0);
        };
        let row_index = view.rows[view.next];
        let Some(row) = table.rows.get(row_index) else {
            return (ERROR_FUNCTION_FAILED, 0);
        };
        let mut record = MsiRecord::new(view.columns.len());
        record.fields[0] = MsiValue::Int(row_index as i32 + 1);
        for (slot, column) in view.columns.iter().enumerate() {
            if let Some(value) = row.get(*column) {
                record.fields[slot + 1] = value.clone();
            }
        }
        let view = self.msi_views.get_mut(&handle).expect("view checked above");
        view.next += 1;
        let record_handle = self.alloc_msi_record(record, memory);
        if record_handle == 0 {
            return (ERROR_FUNCTION_FAILED, 0);
        }
        (ERROR_SUCCESS, record_handle)
    }

    fn msi_column_info(&mut self, handle: u64, info: u32, memory: &mut MemoryImage) -> (u32, u64) {
        if info > 1 {
            return (ERROR_INVALID_PARAMETER, 0);
        }
        let Some(view) = self.msi_views.get(&handle) else {
            return (ERROR_INVALID_HANDLE, 0);
        };
        let Some(database) = self.msi_databases.get(&view.db) else {
            return (ERROR_INVALID_HANDLE, 0);
        };
        let Some(table) = database.table(&view.table) else {
            return (ERROR_INVALID_TABLE, 0);
        };
        let mut record = MsiRecord::new(view.columns.len());
        record.fields[0] = MsiValue::Int(0);
        for (slot, index) in view.columns.iter().enumerate() {
            let Some(column) = table.columns.get(*index) else {
                return (ERROR_FUNCTION_FAILED, 0);
            };
            record.fields[slot + 1] = MsiValue::Str(if info == 0 {
                column.name.clone()
            } else {
                column.type_name()
            });
        }
        let vtable = match self.alloc_guest_vtable(memory, Vec::new()) {
            Ok(vtable) => vtable,
            Err(_) => return (ERROR_FUNCTION_FAILED, 0),
        };
        let record_handle = self
            .alloc_guest_object(memory, GuestObjectKind::MsiRecord, vtable)
            .unwrap_or(0);
        if record_handle == 0 {
            return (ERROR_FUNCTION_FAILED, 0);
        }
        self.msi_records.insert(record_handle, record);
        (ERROR_SUCCESS, record_handle)
    }

    fn msi_create_record(&mut self, fields: usize, memory: &mut MemoryImage) -> (u32, u64) {
        let vtable = match self.alloc_guest_vtable(memory, Vec::new()) {
            Ok(vtable) => vtable,
            Err(_) => return (ERROR_FUNCTION_FAILED, 0),
        };
        let handle = self
            .alloc_guest_object(memory, GuestObjectKind::MsiRecord, vtable)
            .unwrap_or(0);
        if handle == 0 {
            return (ERROR_FUNCTION_FAILED, 0);
        }
        self.msi_records.insert(handle, MsiRecord::new(fields));
        (ERROR_SUCCESS, handle)
    }

    fn alloc_msi_record(&mut self, record: MsiRecord, memory: &mut MemoryImage) -> u64 {
        let vtable = match self.alloc_guest_vtable(memory, Vec::new()) {
            Ok(vtable) => vtable,
            Err(_) => return 0,
        };
        let handle = self
            .alloc_guest_object(memory, GuestObjectKind::MsiRecord, vtable)
            .unwrap_or(0);
        if handle != 0 {
            self.msi_records.insert(handle, record);
        }
        handle
    }

    fn msi_view_modify(&mut self, handle: u64, mode: u32, record_handle: u64) -> u32 {
        let Some(view) = self.msi_views.get(&handle).cloned() else {
            return ERROR_INVALID_HANDLE;
        };
        let Some(record) = self.msi_records.get(&record_handle).cloned() else {
            return ERROR_INVALID_HANDLE;
        };
        let Some(database) = self.msi_databases.get_mut(&view.db) else {
            return ERROR_INVALID_HANDLE;
        };
        let Some(table) = database.table_mut(&view.table) else {
            return ERROR_INVALID_TABLE;
        };
        let result = match mode as i32 {
            1 | 7 => insert_record(table, &record),
            2 | 3 | 4 | 5 => update_record(table, &record),
            6 => delete_record(table, &record),
            _ => ERROR_INVALID_PARAMETER,
        };
        if result == ERROR_SUCCESS {
            self.msi_refresh_views(view.db);
        }
        result
    }

    fn msi_refresh_views(&mut self, db: u64) {
        let updates: Vec<(u64, Vec<usize>)> = self
            .msi_views
            .iter()
            .filter(|(_, view)| view.db == db)
            .filter_map(|(handle, view)| {
                self.msi_databases
                    .get(&db)
                    .map(|database| (*handle, matching_rows(database, view)))
            })
            .collect();
        for (handle, rows) in updates {
            if let Some(view) = self.msi_views.get_mut(&handle) {
                view.rows = rows;
                view.next = 0;
                view.executed = true;
            }
        }
    }

    fn msi_commit(&mut self, handle: u64) -> u32 {
        let Some(database) = self.msi_databases.get(&handle) else {
            return ERROR_INVALID_HANDLE;
        };
        if database.path.is_empty() {
            return ERROR_ACCESS_DENIED;
        }
        match serialize_database(database) {
            Ok(bytes) => match std::fs::write(&database.path, bytes) {
                Ok(()) => ERROR_SUCCESS,
                Err(_) => ERROR_FUNCTION_FAILED,
            },
            Err(code) => code,
        }
    }

    fn dispatch_msi_record_get_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let record_handle = guest_call_arg(state, memory, 0)?;
        let field = guest_call_arg_u32(state, memory, 1)? as usize;
        let buffer = guest_call_arg(state, memory, 2)?;
        let size_ptr = guest_call_arg(state, memory, 3)?;
        if size_ptr == 0 {
            state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
            return Ok(());
        }
        let Some(record) = self.msi_records.get(&record_handle) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
            return Ok(());
        };
        let Some(value) = record.field(field) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_FIELD));
            return Ok(());
        };
        let text = match value {
            MsiValue::Str(text) => text.clone(),
            MsiValue::Int(number) => number.to_string(),
            MsiValue::Null | MsiValue::Stream(_) => String::new(),
        };
        let units: Vec<u16> = text.encode_utf16().collect();
        let required = units.len() + 1;
        let capacity = read_guest_u32(memory, size_ptr).unwrap_or(0) as usize;
        if buffer == 0 || capacity == 0 {
            write_guest_u32(memory, size_ptr, required as u32).ok();
            state.set(Register::Rax, u64::from(ERROR_SUCCESS));
            return Ok(());
        }
        if capacity < required {
            let copied = capacity.saturating_sub(1);
            for (index, unit) in units.iter().take(copied).enumerate() {
                write_guest_u16(memory, buffer + (index as u64 * 2), *unit).ok();
            }
            write_guest_u16(memory, buffer + (copied as u64 * 2), 0).ok();
            write_guest_u32(memory, size_ptr, required as u32).ok();
            state.set(Register::Rax, u64::from(ERROR_MORE_DATA));
            return Ok(());
        }
        for (index, unit) in units.iter().enumerate() {
            write_guest_u16(memory, buffer + (index as u64 * 2), *unit).ok();
        }
        write_guest_u16(memory, buffer + (units.len() as u64 * 2), 0).ok();
        write_guest_u32(memory, size_ptr, units.len() as u32).ok();
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    fn dispatch_msi_record_read_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let record_handle = guest_call_arg(state, memory, 0)?;
        let field = guest_call_arg_u32(state, memory, 1)? as usize;
        let buffer = guest_call_arg(state, memory, 2)?;
        let size_ptr = guest_call_arg(state, memory, 3)?;
        if size_ptr == 0 {
            state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
            return Ok(());
        }
        let Some(record) = self.msi_records.get_mut(&record_handle) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_HANDLE));
            return Ok(());
        };
        let Some(value) = record.field(field) else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_FIELD));
            return Ok(());
        };
        let MsiValue::Stream(data) = value else {
            state.set(Register::Rax, u64::from(ERROR_INVALID_DATATYPE));
            return Ok(());
        };
        let data = data.clone();
        let requested = read_guest_u32(memory, size_ptr).unwrap_or(0) as usize;
        let position = record
            .stream_positions
            .get(field)
            .copied()
            .unwrap_or(0)
            .min(data.len());
        let available = data.len().saturating_sub(position);
        let copied = requested.min(available);
        if buffer != 0 {
            for (index, byte) in data[position..position + copied].iter().enumerate() {
                memory.write_u8(buffer + index as u64, *byte);
            }
        }
        record.stream_positions[field] = position + copied;
        write_guest_u32(memory, size_ptr, copied as u32).ok();
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }
}

fn msi_value_size(value: &MsiValue) -> u32 {
    match value {
        MsiValue::Null => 0,
        MsiValue::Int(_) => 4,
        MsiValue::Str(text) => ((text.encode_utf16().count() + 1) * 2) as u32,
        MsiValue::Stream(data) => data.len() as u32,
    }
}

fn record_int(record: &MsiRecord, field: usize) -> Option<i32> {
    match record.field(field)? {
        MsiValue::Int(value) => Some(*value),
        MsiValue::Str(text) => text.trim().parse::<i32>().ok(),
        MsiValue::Null | MsiValue::Stream(_) => None,
    }
}

fn matching_rows(database: &MsiDatabaseState, view: &MsiViewState) -> Vec<usize> {
    let Some(table) = database.table(&view.table) else {
        return Vec::new();
    };
    table
        .rows
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            view.filters
                .iter()
                .all(|filter| match (&filter.value, row.get(filter.column)) {
                    (MsiValue::Str(expected), Some(MsiValue::Str(actual))) => {
                        expected.eq_ignore_ascii_case(actual)
                    }
                    (MsiValue::Int(expected), Some(MsiValue::Int(actual))) => expected == actual,
                    _ => false,
                })
        })
        .map(|(index, _)| index)
        .collect()
}

fn row_stream_name(table_name: &str, columns: &[MsiColumn], row: &[MsiValue]) -> String {
    let mut name = table_name.to_string();
    for (index, column) in columns.iter().enumerate() {
        if !column.is_key() {
            continue;
        }
        name.push('.');
        match row.get(index) {
            Some(MsiValue::Str(value)) => name.push_str(value),
            Some(MsiValue::Int(value)) => name.push_str(&value.to_string()),
            _ => {}
        }
    }
    name
}

fn convert_record_field(column: &MsiColumn, value: &MsiValue) -> Result<MsiValue, u32> {
    if column.is_binary() {
        return Ok(match value {
            MsiValue::Stream(data) => MsiValue::Stream(data.clone()),
            MsiValue::Int(number) if *number > 0 => MsiValue::Int(*number),
            MsiValue::Null | MsiValue::Int(_) => MsiValue::Null,
            MsiValue::Str(_) => return Err(ERROR_INVALID_DATATYPE),
        });
    }
    if column.is_string() {
        return Ok(match value {
            MsiValue::Str(text) => MsiValue::Str(text.clone()),
            MsiValue::Int(number) => MsiValue::Str(number.to_string()),
            MsiValue::Null => MsiValue::Null,
            MsiValue::Stream(_) => return Err(ERROR_INVALID_DATATYPE),
        });
    }
    match value {
        MsiValue::Int(number) => Ok(MsiValue::Int(*number)),
        MsiValue::Str(text) => text
            .trim()
            .parse::<i32>()
            .map(MsiValue::Int)
            .map_err(|_| ERROR_INVALID_DATA),
        MsiValue::Null => Ok(MsiValue::Null),
        MsiValue::Stream(_) => Err(ERROR_INVALID_DATATYPE),
    }
}

fn build_record_row(
    table: &MsiTable,
    record: &MsiRecord,
    validate_required: bool,
) -> Result<Vec<MsiValue>, u32> {
    let mut row = Vec::with_capacity(table.columns.len());
    for (index, column) in table.columns.iter().enumerate() {
        let value = record
            .fields
            .get(index + 1)
            .cloned()
            .unwrap_or(MsiValue::Null);
        let value = convert_record_field(column, &value)?;
        if validate_required
            && !column.is_nullable()
            && !column.is_binary()
            && matches!(&value, MsiValue::Null)
        {
            return Err(ERROR_INVALID_DATA);
        }
        if validate_required
            && column.is_string()
            && !column.is_nullable()
            && matches!(&value, MsiValue::Str(text) if text.is_empty())
        {
            return Err(ERROR_INVALID_DATA);
        }
        row.push(value);
    }
    Ok(row)
}

fn row_keys(table: &MsiTable, row: &[MsiValue]) -> Vec<MsiValue> {
    table
        .columns
        .iter()
        .enumerate()
        .filter(|(_, column)| column.is_key())
        .map(|(index, _)| row.get(index).cloned().unwrap_or(MsiValue::Null))
        .collect()
}

fn table_has_key(table: &MsiTable, row: &[MsiValue]) -> bool {
    let keys = row_keys(table, row);
    if keys.is_empty() {
        return false;
    }
    table
        .rows
        .iter()
        .any(|existing| row_keys(table, existing) == keys)
}

fn insert_record(table: &mut MsiTable, record: &MsiRecord) -> u32 {
    let row = match build_record_row(table, record, true) {
        Ok(row) => row,
        Err(code) => return code,
    };
    if table_has_key(table, &row) {
        return ERROR_FUNCTION_FAILED;
    }
    table.rows.push(row);
    ERROR_SUCCESS
}

fn update_record(table: &mut MsiTable, record: &MsiRecord) -> u32 {
    let Some(row_number) = record_int(record, 0) else {
        return ERROR_FUNCTION_FAILED;
    };
    if row_number <= 0 || row_number as usize > table.rows.len() {
        return ERROR_FUNCTION_FAILED;
    }
    let row_index = row_number as usize - 1;
    for (index, column) in table.columns.iter().enumerate() {
        let Some(value) = record.fields.get(index + 1) else {
            continue;
        };
        if matches!(value, MsiValue::Null) {
            continue;
        }
        let value = match convert_record_field(column, value) {
            Ok(value) => value,
            Err(code) => return code,
        };
        if let Some(slot) = table.rows[row_index].get_mut(index) {
            *slot = value;
        }
    }
    ERROR_SUCCESS
}

fn delete_record(table: &mut MsiTable, record: &MsiRecord) -> u32 {
    let Some(row_number) = record_int(record, 0) else {
        return ERROR_FUNCTION_FAILED;
    };
    if row_number <= 0 || row_number as usize > table.rows.len() {
        return ERROR_FUNCTION_FAILED;
    }
    table.rows.remove(row_number as usize - 1);
    ERROR_SUCCESS
}

/// A tiny SELECT parser: column list, table name and equality terms joined by
/// AND.  Unsupported SQL (joins, ORDER BY, parameters) is rejected with
/// ERROR_BAD_QUERY_SYNTAX by the caller.
struct SqlCursor {
    chars: Vec<char>,
    position: usize,
}

impl SqlCursor {
    fn new(text: &str) -> Self {
        Self {
            chars: text.chars().collect(),
            position: 0,
        }
    }

    fn skip_space(&mut self) {
        while self
            .chars
            .get(self.position)
            .is_some_and(|ch| ch.is_whitespace())
        {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.position += 1;
        Some(ch)
    }

    fn at_end(&mut self) -> bool {
        self.skip_space();
        self.position >= self.chars.len()
    }

    fn word(&mut self) -> String {
        self.skip_space();
        let start = self.position;
        while self
            .chars
            .get(self.position)
            .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == '_')
        {
            self.position += 1;
        }
        self.chars[start..self.position].iter().collect()
    }

    fn expect_word(&mut self, expected: &str) -> Result<(), ()> {
        if self.word().eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn ident(&mut self) -> Result<String, ()> {
        self.skip_space();
        match self.peek() {
            Some('`') => {
                self.position += 1;
                let mut out = String::new();
                loop {
                    match self.bump().ok_or(())? {
                        '`' => {
                            if self.peek() == Some('`') {
                                self.position += 1;
                                out.push('`');
                            } else {
                                break;
                            }
                        }
                        ch => out.push(ch),
                    }
                }
                Ok(out)
            }
            Some('[') => {
                self.position += 1;
                let mut out = String::new();
                while let Some(ch) = self.bump() {
                    if ch == ']' {
                        break;
                    }
                    out.push(ch);
                }
                Ok(out)
            }
            Some(ch) if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' => {
                let start = self.position;
                while self.chars.get(self.position).is_some_and(|ch| {
                    ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.' || *ch == '$'
                }) {
                    self.position += 1;
                }
                Ok(self.chars[start..self.position].iter().collect())
            }
            _ => Err(()),
        }
    }

    fn literal(&mut self) -> Result<MsiValue, ()> {
        self.skip_space();
        match self.peek() {
            Some('\'') | Some('"') => {
                let quote = self.bump().ok_or(())?;
                let mut out = String::new();
                loop {
                    match self.bump().ok_or(())? {
                        ch if ch == quote => {
                            if self.peek() == Some(quote) {
                                self.position += 1;
                                out.push(quote);
                            } else {
                                break;
                            }
                        }
                        ch => out.push(ch),
                    }
                }
                Ok(MsiValue::Str(out))
            }
            _ => {
                let start = self.position;
                if self.peek() == Some('-') || self.peek() == Some('+') {
                    self.position += 1;
                }
                while self
                    .chars
                    .get(self.position)
                    .is_some_and(|ch| ch.is_ascii_digit())
                {
                    self.position += 1;
                }
                if start == self.position {
                    return Err(());
                }
                let text: String = self.chars[start..self.position].iter().collect();
                text.parse::<i32>().map(MsiValue::Int).map_err(|_| ())
            }
        }
    }
}

fn parse_select(text: &str) -> Result<MsiQuery, ()> {
    let mut cursor = SqlCursor::new(text);
    cursor.expect_word("SELECT")?;
    cursor.skip_space();
    let columns = if cursor.peek() == Some('*') {
        cursor.position += 1;
        None
    } else {
        let mut names = Vec::new();
        loop {
            names.push(cursor.ident()?);
            cursor.skip_space();
            if cursor.peek() == Some(',') {
                cursor.position += 1;
                continue;
            }
            break;
        }
        Some(names)
    };
    cursor.expect_word("FROM")?;
    let table = cursor.ident()?;
    if table.is_empty() {
        return Err(());
    }
    let mut filters = Vec::new();
    if !cursor.at_end() {
        cursor.expect_word("WHERE")?;
        loop {
            let column = cursor.ident()?;
            cursor.skip_space();
            if cursor.bump() != Some('=') {
                return Err(());
            }
            let value = cursor.literal()?;
            filters.push((column, value));
            if cursor.at_end() {
                break;
            }
            cursor.expect_word("AND")?;
        }
    }
    if !cursor.at_end() {
        return Err(());
    }
    Ok(MsiQuery {
        columns,
        table,
        filters,
    })
}

fn load_string_table(pool: &[u8], data: &[u8]) -> (Vec<String>, usize) {
    let mut strings = vec![String::new()];
    if pool.len() < 4 {
        return (strings, 2);
    }
    let codepage = u32::from(le_u16(pool, 0).unwrap_or(0))
        | (u32::from(le_u16(pool, 2).unwrap_or(0) & 0x7FFF) << 16);
    let long_refs = le_u16(pool, 2).unwrap_or(0) & 0x8000 != 0;
    let string_ref = if long_refs { 3 } else { 2 };
    let count = pool.len() / 4;
    let mut offset = 0usize;
    let mut index = 1usize;
    while index < count {
        let length_word = le_u16(pool, index * 4).unwrap_or(0);
        let refs_word = le_u16(pool, index * 4 + 2).unwrap_or(0);
        let length;
        if length_word == 0 && refs_word == 0 {
            strings.push(String::new());
            index += 1;
            continue;
        } else if length_word == 0 {
            let next = index + 1;
            if next >= count {
                break;
            }
            let low = le_u16(pool, next * 4).unwrap_or(0) as usize;
            let high = le_u16(pool, next * 4 + 2).unwrap_or(0) as usize;
            length = (high << 16) | low;
            index += 2;
        } else {
            length = length_word as usize;
            index += 1;
        }
        if offset + length > data.len() {
            break;
        }
        strings.push(decode_codepage(&data[offset..offset + length], codepage));
        offset += length;
    }
    (strings, string_ref)
}

fn decode_codepage(bytes: &[u8], codepage: u32) -> String {
    match codepage {
        1200 => String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        ),
        1201 => String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        ),
        65001 => String::from_utf8_lossy(bytes).into_owned(),
        _ => bytes.iter().map(|byte| cp1252_char(*byte)).collect(),
    }
}

fn cp1252_char(byte: u8) -> char {
    match byte {
        0x80 => '€',
        0x82 => '‚',
        0x83 => 'ƒ',
        0x84 => '„',
        0x85 => '…',
        0x86 => '†',
        0x87 => '‡',
        0x88 => 'ˆ',
        0x89 => '‰',
        0x8A => 'Š',
        0x8B => '‹',
        0x8C => 'Œ',
        0x8E => 'Ž',
        0x91 => '‘',
        0x92 => '’',
        0x93 => '“',
        0x94 => '”',
        0x95 => '•',
        0x96 => '–',
        0x97 => '—',
        0x98 => '˜',
        0x99 => '™',
        0x9A => 'š',
        0x9B => '›',
        0x9C => 'œ',
        0x9E => 'ž',
        0x9F => 'Ÿ',
        _ => byte as char,
    }
}

fn decode_string_id(cell: &[u8]) -> u32 {
    let mut value = 0u32;
    for (index, byte) in cell.iter().enumerate().take(3) {
        value |= u32::from(*byte) << (index * 8);
    }
    value
}

fn decode_cell(cell: &[u8], column: &MsiColumn, strings: &[String], string_ref: usize) -> MsiValue {
    if column.is_binary() {
        return MsiValue::Int(u16::from_le_bytes([cell[0], cell[1]]) as i32);
    }
    if column.is_string() {
        let id = decode_string_id(&cell[..string_ref.min(cell.len())]);
        if id == 0 {
            return MsiValue::Null;
        }
        return MsiValue::Str(strings.get(id as usize).cloned().unwrap_or_default());
    }
    if cell.len() <= 2 {
        return MsiValue::Int(i32::from(u16::from_le_bytes([cell[0], cell[1]])) - 0x8000);
    }
    let raw = u32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]);
    MsiValue::Int((raw ^ 0x8000_0000) as i32)
}

fn decode_table_rows(
    raw: &[u8],
    strings: &[String],
    columns: &[MsiColumn],
    string_ref: usize,
    table_name: &str,
    compound: Option<&CompoundFile>,
) -> Vec<Vec<MsiValue>> {
    if columns.is_empty() {
        return Vec::new();
    }
    let widths: Vec<usize> = columns
        .iter()
        .map(|column| column.storage_width(string_ref))
        .collect();
    let row_size: usize = widths.iter().sum();
    if row_size == 0 || raw.len() % row_size != 0 {
        return Vec::new();
    }
    let row_count = raw.len() / row_size;
    let mut offsets = Vec::with_capacity(widths.len());
    let mut offset = 0usize;
    for width in &widths {
        offsets.push(offset);
        offset += width;
    }
    let mut rows = Vec::with_capacity(row_count);
    for row in 0..row_count {
        let mut values = Vec::with_capacity(columns.len());
        for (index, column) in columns.iter().enumerate() {
            let width = widths[index];
            let start = offsets[index] * row_count + row * width;
            let cell = &raw[start..start + width];
            values.push(decode_cell(cell, column, strings, string_ref));
        }
        if let Some(compound) = compound {
            for (index, column) in columns.iter().enumerate() {
                if !column.is_binary() {
                    continue;
                }
                let id = match values[index] {
                    MsiValue::Int(id) => id,
                    _ => 0,
                };
                if id <= 0 {
                    values[index] = MsiValue::Null;
                    continue;
                }
                let name = row_stream_name(table_name, columns, &values);
                if let Some(data) = compound.stream(&name) {
                    values[index] = MsiValue::Stream(data);
                }
            }
        }
        rows.push(values);
    }
    rows
}

fn mime_index(ch: char) -> Option<u8> {
    match ch {
        '0'..='9' => Some(ch as u8 - b'0'),
        'A'..='Z' => Some(ch as u8 - b'A' + 10),
        'a'..='z' => Some(ch as u8 - b'a' + 36),
        '.' => Some(62),
        '_' => Some(63),
        _ => None,
    }
}

fn mime_char(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=35 => char::from(b'A' + value - 10),
        36..=61 => char::from(b'a' + value - 36),
        62 => '.',
        _ => '_',
    }
}

/// Encode an MSI stream name into the compound-file directory name used by
/// the Microsoft Installer (the pairing scheme from libmsi's
/// `encode_streamname`; `table` adds the U+4840 table-stream prefix).
fn encode_stream_name(table: bool, name: &str) -> String {
    let mut bytes = Vec::new();
    if table {
        bytes.extend_from_slice(&[0xE4, 0xA1, 0x80]);
    }
    let chars: Vec<char> = name.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        match mime_index(ch) {
            Some(value) => {
                let next = chars.get(index + 1).and_then(|next| mime_index(*next));
                match next {
                    Some(next) => {
                        bytes.push(0xE3 + (next >> 5));
                        bytes.push(0xA0 ^ next);
                        bytes.push(0x80 | value);
                        index += 2;
                    }
                    None => {
                        bytes.extend_from_slice(&[0xE4, 0xA0, 0x80 | value]);
                        index += 1;
                    }
                }
            }
            None => {
                let mut buffer = [0u8; 4];
                bytes.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn decode_stream_name(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = String::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index];
        if (ch == 0xE3 && bytes.get(index + 1).is_some_and(|byte| *byte >= 0xA0))
            || (ch == 0xE4 && bytes.get(index + 1).is_some_and(|byte| *byte < 0xA0))
        {
            let first = mime_char(bytes[index + 2] & 0x7F);
            let second = mime_char(bytes[index + 1] ^ 0xA0);
            out.push(first);
            out.push(second);
            index += 3;
            continue;
        }
        if ch == 0xE4 && bytes.get(index + 1) == Some(&0xA0) {
            out.push(mime_char(bytes[index + 2] & 0x7F));
            index += 3;
            continue;
        }
        let width = if ch < 0xC1 {
            1
        } else if ch < 0xE0 {
            2
        } else if ch < 0xF0 {
            3
        } else {
            4
        };
        if let Ok(text) = std::str::from_utf8(&bytes[index..(index + width).min(bytes.len())]) {
            out.push_str(text);
        }
        index += width;
    }
    out
}

fn build_string_pool(strings: &[String]) -> (Vec<u8>, Vec<u8>) {
    let mut data = Vec::new();
    let mut pool = Vec::with_capacity(4 + strings.len() * 4);
    pool.extend_from_slice(&65001u32.to_le_bytes());
    for text in strings {
        let bytes = text.as_bytes();
        if bytes.len() > 0xFFFF {
            pool.extend_from_slice(&0u16.to_le_bytes());
            pool.extend_from_slice(&((bytes.len() >> 16) as u16).to_le_bytes());
        }
        pool.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        pool.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(bytes);
    }
    (pool, data)
}

fn write_string_id(target: &mut [u8], id: u16) {
    for (index, byte) in target.iter_mut().enumerate().take(3) {
        *byte = (id >> (index * 8)) as u8;
    }
}

fn encode_int2(value: i32) -> u16 {
    (value + 0x8000) as u16
}

fn encode_int4(value: i32) -> u32 {
    (value as u32) ^ 0x8000_0000
}

fn intern_string(
    strings: &mut Vec<String>,
    ids: &mut BTreeMap<String, u16>,
    value: &str,
) -> Result<u16, u32> {
    if value.is_empty() {
        return Ok(0);
    }
    if let Some(id) = ids.get(value) {
        return Ok(*id);
    }
    let id = u16::try_from(strings.len() + 1).map_err(|_| ERROR_FUNCTION_FAILED)?;
    strings.push(value.to_string());
    ids.insert(value.to_string(), id);
    Ok(id)
}

fn encode_table_stream(
    table: &MsiTable,
    ids: &BTreeMap<String, u16>,
    string_ref: usize,
) -> Result<Vec<u8>, u32> {
    let row_count = table.rows.len();
    let widths: Vec<usize> = table
        .columns
        .iter()
        .map(|column| column.storage_width(string_ref))
        .collect();
    let row_size: usize = widths.iter().sum();
    let mut out = vec![0u8; row_count * row_size];
    let mut offset = 0usize;
    for (column_index, column) in table.columns.iter().enumerate() {
        let width = widths[column_index];
        for row_index in 0..row_count {
            let start = offset * row_count + row_index * width;
            let cell = &mut out[start..start + width];
            match table.rows[row_index].get(column_index) {
                Some(MsiValue::Str(text)) => {
                    let id = ids.get(text).copied().unwrap_or(0);
                    write_string_id(cell, id);
                }
                Some(MsiValue::Int(value)) => {
                    if column.is_string() {
                        let text = value.to_string();
                        let id = ids.get(&text).copied().unwrap_or(0);
                        write_string_id(cell, id);
                    } else if column.is_binary() {
                        cell[0] = (*value).clamp(0, u16::MAX as i32) as u8;
                        cell[1] = ((*value).clamp(0, u16::MAX as i32) >> 8) as u8;
                    } else if width <= 2 {
                        cell.copy_from_slice(&encode_int2(*value).to_le_bytes());
                    } else {
                        cell.copy_from_slice(&encode_int4(*value).to_le_bytes());
                    }
                }
                Some(MsiValue::Stream(_)) if column.is_binary() && width >= 2 => {
                    cell[0] = 1;
                    cell[1] = 0;
                }
                _ => {}
            }
        }
        offset += width;
    }
    Ok(out)
}

/// Write a CFB v3 compound file.  Streams shorter than 4096 bytes go into the
/// mini stream (miniFAT); larger ones get regular FAT chains; the FAT itself
/// spills into DIFAT sectors past 109 FAT sectors.
fn write_compound_file(streams: &[(String, Vec<u8>)]) -> Vec<u8> {
    const SECTOR: usize = 512;
    const MINI: usize = 64;
    const CUTOFF: u64 = 4096;

    fn allocate_big(data: &[u8], fat: &mut Vec<u32>, bytes: &mut Vec<u8>) -> u32 {
        if data.is_empty() {
            return ENDOFCHAIN;
        }
        let count = data.len().div_ceil(SECTOR);
        let start = fat.len() as u32;
        for index in 0..count {
            fat.push(if index + 1 == count {
                ENDOFCHAIN
            } else {
                start + index as u32 + 1
            });
        }
        bytes.extend_from_slice(data);
        bytes.resize(fat.len() * SECTOR, 0);
        start
    }

    enum Layout {
        Mini(u32),
        Big(u32),
    }

    let mut mini_data = Vec::new();
    let mut mini_fat: Vec<u32> = Vec::new();
    let mut bytes = Vec::new();
    let mut fat: Vec<u32> = Vec::new();
    let mut layouts = Vec::with_capacity(streams.len());
    for (_, data) in streams {
        if data.is_empty() {
            layouts.push(Layout::Mini(ENDOFCHAIN));
        } else if data.len() as u64 >= CUTOFF {
            layouts.push(Layout::Big(allocate_big(data, &mut fat, &mut bytes)));
        } else {
            let count = data.len().div_ceil(MINI);
            let start = mini_fat.len() as u32;
            for index in 0..count {
                mini_fat.push(if index + 1 == count {
                    ENDOFCHAIN
                } else {
                    start + index as u32 + 1
                });
            }
            mini_data.resize(start as usize * MINI, 0);
            mini_data.extend_from_slice(data);
            mini_data.resize((start as usize + count) * MINI, 0);
            layouts.push(Layout::Mini(start));
        }
    }

    let (mini_start, mini_size) = if mini_data.is_empty() {
        (ENDOFCHAIN, 0u64)
    } else {
        (
            allocate_big(&mini_data, &mut fat, &mut bytes),
            mini_data.len() as u64,
        )
    };

    let entry_count = 1 + streams.len();
    let dir_sector_count = (entry_count * 128).div_ceil(SECTOR).max(1);
    let dir_start = fat.len() as u32;
    for index in 0..dir_sector_count {
        fat.push(if index + 1 == dir_sector_count {
            ENDOFCHAIN
        } else {
            dir_start + index as u32 + 1
        });
    }
    bytes.resize(fat.len() * SECTOR, 0);

    let (mini_fat_start, mini_fat_count) = if mini_fat.is_empty() {
        (ENDOFCHAIN, 0u32)
    } else {
        let mut raw = Vec::with_capacity(mini_fat.len() * 4);
        for entry in &mini_fat {
            raw.extend_from_slice(&entry.to_le_bytes());
        }
        let count = raw.len().div_ceil(SECTOR) as u32;
        (allocate_big(&raw, &mut fat, &mut bytes), count)
    };

    let base_sectors = fat.len();
    let mut fat_sector_count = 0usize;
    let mut difat_sector_count = 0usize;
    loop {
        let total = base_sectors + fat_sector_count + difat_sector_count;
        let next_fat = total.div_ceil(128).max(1);
        let next_difat = if next_fat > 109 {
            (next_fat - 109).div_ceil(127)
        } else {
            0
        };
        if next_fat == fat_sector_count && next_difat == difat_sector_count {
            break;
        }
        fat_sector_count = next_fat;
        difat_sector_count = next_difat;
    }
    for _ in 0..fat_sector_count {
        fat.push(FATSECT);
    }
    for _ in 0..difat_sector_count {
        fat.push(DIFSECT);
    }
    let total_sectors = base_sectors + fat_sector_count + difat_sector_count;
    bytes.resize(total_sectors * SECTOR, 0);

    let fat_start = base_sectors;
    for sector in 0..fat_sector_count {
        let start = (fat_start + sector) * SECTOR;
        for index in 0..128 {
            let value = fat.get(sector * 128 + index).copied().unwrap_or(FREESECT);
            bytes[start + index * 4..start + index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    let mut fat_ids: Vec<u32> = (0..fat_sector_count as u32)
        .map(|index| fat_start as u32 + index)
        .collect();
    let difat_start = if difat_sector_count == 0 {
        ENDOFCHAIN
    } else {
        (base_sectors + fat_sector_count) as u32
    };
    if difat_sector_count > 0 {
        fat_ids.truncate(109);
        let mut remaining: Vec<u32> =
            ((fat_start + 109) as u32..(fat_start + fat_sector_count) as u32).collect();
        for sector in 0..difat_sector_count {
            let start = (base_sectors + fat_sector_count + sector) * SECTOR;
            for index in 0..127 {
                let value = remaining.get(index).copied().unwrap_or(FREESECT);
                bytes[start + index * 4..start + index * 4 + 4]
                    .copy_from_slice(&value.to_le_bytes());
            }
            let next = if sector + 1 < difat_sector_count {
                difat_start + sector as u32 + 1
            } else {
                ENDOFCHAIN
            };
            bytes[start + 127 * 4..start + 127 * 4 + 4].copy_from_slice(&next.to_le_bytes());
            remaining.drain(..remaining.len().min(127));
        }
    }

    let mut directory = Vec::with_capacity(dir_sector_count * SECTOR);
    let root_child = if streams.is_empty() { NOSTREAM } else { 1 };
    push_directory_entry(
        &mut directory,
        "Root Entry",
        5,
        NOSTREAM,
        root_child,
        mini_start,
        mini_size,
    );
    for (index, ((name, data), layout)) in streams.iter().zip(layouts.iter()).enumerate() {
        let right = if index + 1 < streams.len() {
            index as u32 + 2
        } else {
            NOSTREAM
        };
        let (start, size) = match layout {
            Layout::Mini(start) => (*start, data.len() as u64),
            Layout::Big(start) => (*start, data.len() as u64),
        };
        push_directory_entry(&mut directory, name, 2, right, NOSTREAM, start, size);
    }
    while directory.len() < dir_sector_count * SECTOR {
        push_empty_directory_entry(&mut directory);
    }
    let dir_offset = dir_start as usize * SECTOR;
    bytes[dir_offset..dir_offset + directory.len()].copy_from_slice(&directory);

    let mut header = vec![0u8; SECTOR];
    header[..8].copy_from_slice(&OLE_MAGIC);
    header[0x08..0x18].copy_from_slice(&[
        0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    header[0x18..0x1A].copy_from_slice(&0x003Eu16.to_le_bytes());
    header[0x1A..0x1C].copy_from_slice(&3u16.to_le_bytes());
    header[0x1C..0x1E].copy_from_slice(&0xFFFEu16.to_le_bytes());
    header[0x1E..0x20].copy_from_slice(&9u16.to_le_bytes());
    header[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
    header[0x28..0x2C].copy_from_slice(&(fat_sector_count as u32).to_le_bytes());
    header[0x2C..0x30].copy_from_slice(&dir_start.to_le_bytes());
    header[0x34..0x38].copy_from_slice(&(CUTOFF as u32).to_le_bytes());
    header[0x38..0x3C].copy_from_slice(&mini_fat_start.to_le_bytes());
    header[0x3C..0x40].copy_from_slice(&mini_fat_count.to_le_bytes());
    header[0x40..0x44].copy_from_slice(&difat_start.to_le_bytes());
    header[0x44..0x48].copy_from_slice(&(difat_sector_count as u32).to_le_bytes());
    for index in 0..109 {
        let value = fat_ids.get(index).copied().unwrap_or(FREESECT);
        header[0x48 + index * 4..0x48 + index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut out = header;
    out.extend_from_slice(&bytes);
    out
}

fn push_directory_entry(
    out: &mut Vec<u8>,
    name: &str,
    kind: u8,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
) {
    let units: Vec<u16> = name.encode_utf16().take(31).collect();
    let mut entry = vec![0u8; 128];
    for (index, unit) in units.iter().enumerate() {
        entry[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    entry[0x40..0x42].copy_from_slice(&(((units.len() + 1) * 2) as u16).to_le_bytes());
    entry[0x42] = kind;
    entry[0x43] = 1;
    entry[0x44..0x48].copy_from_slice(&NOSTREAM.to_le_bytes());
    entry[0x48..0x4C].copy_from_slice(&right.to_le_bytes());
    entry[0x4C..0x50].copy_from_slice(&child.to_le_bytes());
    entry[0x74..0x78].copy_from_slice(&start.to_le_bytes());
    entry[0x78..0x7C].copy_from_slice(&(size as u32).to_le_bytes());
    entry[0x7C..0x80].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    out.extend_from_slice(&entry);
}

fn push_empty_directory_entry(out: &mut Vec<u8>) {
    let mut entry = vec![0u8; 128];
    entry[0x44..0x48].copy_from_slice(&FREESECT.to_le_bytes());
    entry[0x48..0x4C].copy_from_slice(&FREESECT.to_le_bytes());
    entry[0x4C..0x50].copy_from_slice(&FREESECT.to_le_bytes());
    out.extend_from_slice(&entry);
}

fn serialize_database(database: &MsiDatabaseState) -> Result<Vec<u8>, u32> {
    let mut strings: Vec<String> = Vec::new();
    let mut ids: BTreeMap<String, u16> = BTreeMap::new();
    let user_tables: Vec<&MsiTable> = database
        .tables
        .values()
        .filter(|table| {
            !table.name.eq_ignore_ascii_case("_Tables")
                && !table.name.eq_ignore_ascii_case("_Columns")
        })
        .collect();
    for table in &user_tables {
        intern_string(&mut strings, &mut ids, &table.name)?;
        for column in &table.columns {
            intern_string(&mut strings, &mut ids, &column.name)?;
        }
        for row in &table.rows {
            for value in row {
                if let MsiValue::Str(text) = value {
                    intern_string(&mut strings, &mut ids, text)?;
                }
            }
        }
    }
    let string_ref = 2usize;

    let mut tables_stream = vec![0u8; user_tables.len() * string_ref];
    for (index, table) in user_tables.iter().enumerate() {
        let id = ids.get(&table.name).copied().unwrap_or(0);
        let start = index * string_ref;
        write_string_id(&mut tables_stream[start..start + string_ref], id);
    }

    let column_rows: Vec<(&MsiTable, usize, &MsiColumn)> = user_tables
        .iter()
        .flat_map(|table| {
            table
                .columns
                .iter()
                .enumerate()
                .map(move |(index, column)| (*table, index, column))
        })
        .collect();
    let mut columns_stream = vec![0u8; column_rows.len() * (2 * string_ref + 4)];
    for (row_index, (table, column_index, column)) in column_rows.iter().enumerate() {
        let table_id = ids.get(&table.name).copied().unwrap_or(0);
        let name_id = ids.get(&column.name).copied().unwrap_or(0);
        let number = *column_index as u16 + 1;
        let type_raw = column.type_bits.wrapping_add(0x8000);
        let row_count = column_rows.len();
        let base = row_index * string_ref;
        write_string_id(&mut columns_stream[base..base + string_ref], table_id);
        let number_start = row_count * string_ref + row_index * 2;
        columns_stream[number_start..number_start + 2]
            .copy_from_slice(&(number.wrapping_add(0x8000)).to_le_bytes());
        let name_block = row_count * string_ref + row_count * 2;
        let name_start = name_block + base;
        write_string_id(
            &mut columns_stream[name_start..name_start + string_ref],
            name_id,
        );
        let type_block = name_block + row_count * string_ref;
        let type_start = type_block + row_index * 2;
        columns_stream[type_start..type_start + 2].copy_from_slice(&type_raw.to_le_bytes());
    }

    let mut table_streams: Vec<(String, Vec<u8>)> = Vec::new();
    for table in &user_tables {
        table_streams.push((
            table.name.clone(),
            encode_table_stream(table, &ids, string_ref)?,
        ));
    }

    let (pool, data) = build_string_pool(&strings);
    let mut extras = database.extras.clone();
    for table in &user_tables {
        let prefix = format!("{}.", table.name);
        extras.retain(|name, _| !name.starts_with(&prefix));
    }
    let mut entries: Vec<(bool, String, Vec<u8>)> = Vec::new();
    entries.push((true, "_StringPool".to_string(), pool));
    entries.push((true, "_StringData".to_string(), data));
    entries.push((true, "_Tables".to_string(), tables_stream));
    entries.push((true, "_Columns".to_string(), columns_stream));
    for (name, bytes) in table_streams {
        entries.push((true, name, bytes));
    }
    for (name, (system, bytes)) in &extras {
        entries.push((*system, name.clone(), bytes.clone()));
    }
    for table in &user_tables {
        for row in &table.rows {
            for (index, column) in table.columns.iter().enumerate() {
                if !column.is_binary() {
                    continue;
                }
                if let Some(MsiValue::Stream(bytes)) = row.get(index) {
                    let name = row_stream_name(&table.name, &table.columns, row);
                    entries.push((false, name, bytes.clone()));
                }
            }
        }
    }
    Ok(write_msi_compound(&entries))
}

fn write_msi_compound(streams: &[(bool, String, Vec<u8>)]) -> Vec<u8> {
    let encoded: Vec<(String, Vec<u8>)> = streams
        .iter()
        .map(|(table, name, data)| (encode_stream_name(*table, name), data.clone()))
        .collect();
    write_compound_file(&encoded)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};
    use super::*;

    const PATH_PTR: u64 = 0x42_000;
    const QUERY_PTR: u64 = 0x43_000;
    const OUT_PTR: u64 = 0x44_000;
    const STRING_PTR: u64 = 0x45_000;
    const STRING_SIZE: u64 = 0x46_000;
    const STREAM_PTR: u64 = 0x47_000;
    const STREAM_SIZE: u64 = 0x48_000;

    fn write_wide(memory: &mut MemoryImage, address: u64, text: &str) {
        for (index, unit) in text.encode_utf16().chain([0]).enumerate() {
            write_guest_u16(memory, address + index as u64 * 2, unit).ok();
        }
    }

    fn read_wide(memory: &MemoryImage, address: u64) -> String {
        let mut units = Vec::new();
        for index in 0..256 {
            let unit = read_guest_u16(memory, address + index * 2).unwrap_or(0);
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16_lossy(&units)
    }

    fn guest_pointer(memory: &MemoryImage, address: u64) -> u64 {
        read_guest_pointer(memory, address, GuestArch::X86).unwrap()
    }

    fn fixture_compound() -> Vec<u8> {
        let strings: Vec<String> = ["TestTable", "Name", "Value", "Data", "Alpha", "Beta"]
            .iter()
            .map(|text| text.to_string())
            .collect();
        let (pool, data) = build_string_pool(&strings);

        let mut tables = Vec::new();
        tables.extend_from_slice(&1u16.to_le_bytes());

        let mut columns = vec![0u8; 3 * (2 * 2 + 4)];
        for row in 0..3 {
            let table_start = row * 2;
            columns[table_start..table_start + 2].copy_from_slice(&1u16.to_le_bytes());
            let number_start = 6 + row * 2;
            columns[number_start..number_start + 2]
                .copy_from_slice(&(0x8001u16 + row as u16).to_le_bytes());
            let name_start = 12 + row * 2;
            columns[name_start..name_start + 2].copy_from_slice(&(2u16 + row as u16).to_le_bytes());
            let type_start = 18 + row * 2;
            let type_bits = [0x2940u16, 0x0102, 0x0900][row];
            columns[type_start..type_start + 2]
                .copy_from_slice(&type_bits.wrapping_add(0x8000).to_le_bytes());
        }

        let mut table = vec![0u8; 2 * 3 * 2];
        table[0..2].copy_from_slice(&5u16.to_le_bytes());
        table[2..4].copy_from_slice(&6u16.to_le_bytes());
        table[4..6].copy_from_slice(&0x802Au16.to_le_bytes());
        table[6..8].copy_from_slice(&0x7FF9u16.to_le_bytes());
        table[8..10].copy_from_slice(&1u16.to_le_bytes());
        table[10..12].copy_from_slice(&0u16.to_le_bytes());

        write_msi_compound(&[
            (true, "_StringPool".to_string(), pool),
            (true, "_StringData".to_string(), data),
            (true, "_Tables".to_string(), tables),
            (true, "_Columns".to_string(), columns),
            (true, "TestTable".to_string(), table),
            (false, "TestTable.Alpha".to_string(), vec![1, 2, 3, 4]),
            (true, "_Validation".to_string(), vec![9; 20]),
            (false, "LargeExtra".to_string(), vec![0x5A; 5000]),
        ])
    }

    fn open_fixture(fixture: &mut Fixture, name: &str, bytes: &[u8]) -> (u64, std::path::PathBuf) {
        let path = fixture._temp.path().join(name);
        std::fs::write(&path, bytes).expect("write fixture");
        write_wide(&mut fixture.memory, PATH_PTR, &path.to_string_lossy());
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::MsiOpenDatabaseW,
                &[PATH_PTR as u32, 1, OUT_PTR as u32]
            ),
            0
        );
        (guest_pointer(&fixture.memory, OUT_PTR), path)
    }

    fn open_view(fixture: &mut Fixture, db: u64, sql: &str) -> u64 {
        write_wide(&mut fixture.memory, QUERY_PTR, sql);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::MsiDatabaseOpenViewW,
                &[db as u32, QUERY_PTR as u32, OUT_PTR as u32]
            ),
            0
        );
        guest_pointer(&fixture.memory, OUT_PTR)
    }

    fn execute(fixture: &mut Fixture, view: u64) -> u64 {
        dispatch_x86(fixture, HostThunk::MsiViewExecute, &[view as u32, 0])
    }

    fn fetch(fixture: &mut Fixture, view: u64) -> (u64, u64) {
        let result = dispatch_x86(
            fixture,
            HostThunk::MsiViewFetch,
            &[view as u32, OUT_PTR as u32],
        );
        (result, guest_pointer(&fixture.memory, OUT_PTR))
    }

    fn record_string(fixture: &mut Fixture, record: u64, field: u32) -> (u64, String) {
        write_guest_u32(&mut fixture.memory, STRING_SIZE, 64).ok();
        let result = dispatch_x86(
            fixture,
            HostThunk::MsiRecordGetStringW,
            &[record as u32, field, STRING_PTR as u32, STRING_SIZE as u32],
        );
        (result, read_wide(&fixture.memory, STRING_PTR))
    }

    fn record_integer(fixture: &mut Fixture, record: u64, field: u32) -> i32 {
        dispatch_x86(
            fixture,
            HostThunk::MsiRecordGetInteger,
            &[record as u32, field],
        ) as u32 as i32
    }

    fn read_stream(fixture: &mut Fixture, record: u64, field: u32, size: u32) -> (u64, Vec<u8>) {
        write_guest_u32(&mut fixture.memory, STREAM_SIZE, size).ok();
        let result = dispatch_x86(
            fixture,
            HostThunk::MsiRecordReadStream,
            &[record as u32, field, STREAM_PTR as u32, STREAM_SIZE as u32],
        );
        let written = read_guest_u32(&fixture.memory, STREAM_SIZE).unwrap_or(0) as usize;
        let mut bytes = Vec::new();
        for index in 0..written {
            bytes.push(
                fixture
                    .memory
                    .read_u8(STREAM_PTR + index as u64)
                    .unwrap_or(0),
            );
        }
        (result, bytes)
    }

    #[test]
    fn msi_reads_real_compound_database() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-read");
            let (db, _path) = open_fixture(&mut fixture, "read.msi", &fixture_compound());
            assert_ne!(db, 0);

            let view = open_view(
                &mut fixture,
                db,
                "SELECT `Name`, `Value`, `Data` FROM `TestTable`",
            );
            assert_ne!(view, 0);
            assert_eq!(execute(&mut fixture, view), 0);

            let (result, record) = fetch(&mut fixture, view);
            assert_eq!(result, 0);
            assert_ne!(record, 0);
            assert_eq!(record_integer(&mut fixture, record, 0), 1);
            assert_eq!(
                record_string(&mut fixture, record, 1),
                (0, "Alpha".to_string())
            );
            assert_eq!(record_integer(&mut fixture, record, 2), 42);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordDataSize,
                    &[record as u32, 3]
                ),
                4
            );
            assert_eq!(
                read_stream(&mut fixture, record, 3, 8),
                (0, vec![1, 2, 3, 4])
            );

            let (result, record) = fetch(&mut fixture, view);
            assert_eq!(result, 0);
            assert_eq!(
                record_string(&mut fixture, record, 1),
                (0, "Beta".to_string())
            );
            assert_eq!(record_integer(&mut fixture, record, 2), -7);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordDataSize,
                    &[record as u32, 3]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordReadStream,
                    &[record as u32, 3, STREAM_PTR as u32, STREAM_SIZE as u32]
                ),
                1804
            );

            assert_eq!(fetch(&mut fixture, view).0, 259);

            let info = open_view(&mut fixture, db, "SELECT * FROM TestTable");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewGetColumnInfo,
                    &[info as u32, 0, OUT_PTR as u32]
                ),
                0
            );
            let names = guest_pointer(&fixture.memory, OUT_PTR);
            assert_eq!(
                record_string(&mut fixture, names, 1),
                (0, "Name".to_string())
            );
            assert_eq!(
                record_string(&mut fixture, names, 2),
                (0, "Value".to_string())
            );
            assert_eq!(
                record_string(&mut fixture, names, 3),
                (0, "Data".to_string())
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewGetColumnInfo,
                    &[info as u32, 1, OUT_PTR as u32]
                ),
                0
            );
            let types = guest_pointer(&fixture.memory, OUT_PTR);
            assert_eq!(
                record_string(&mut fixture, types, 1),
                (0, "s64".to_string())
            );
            assert_eq!(record_string(&mut fixture, types, 2), (0, "i2".to_string()));
            assert_eq!(record_string(&mut fixture, types, 3), (0, "v0".to_string()));

            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiCloseHandle, &[db as u32]),
                0
            );
        });
    }

    #[test]
    fn msi_modify_and_commit_round_trip() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-commit");
            let (db, path) = open_fixture(&mut fixture, "commit.msi", &fixture_compound());
            let view = open_view(&mut fixture, db, "SELECT * FROM `TestTable`");
            assert_eq!(execute(&mut fixture, view), 0);

            let inserted =
                dispatch_x86(&mut fixture, HostThunk::MsiCreateRecord, &[3]) as u32 as u64;
            write_wide(&mut fixture.memory, STRING_PTR, "Gamma");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordSetStringW,
                    &[inserted as u32, 1, STRING_PTR as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordSetInteger,
                    &[inserted as u32, 2, 5]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewModify,
                    &[view as u32, 1, inserted as u32]
                ),
                0
            );

            let update = dispatch_x86(&mut fixture, HostThunk::MsiCreateRecord, &[2]) as u32 as u64;
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordSetInteger,
                    &[update as u32, 0, 2]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordSetInteger,
                    &[update as u32, 2, 99]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewModify,
                    &[view as u32, 2, update as u32]
                ),
                0
            );

            let delete = dispatch_x86(&mut fixture, HostThunk::MsiCreateRecord, &[1]) as u32 as u64;
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordSetInteger,
                    &[delete as u32, 0, 1]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewModify,
                    &[view as u32, 6, delete as u32]
                ),
                0
            );

            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiDatabaseCommit, &[db as u32]),
                0
            );
            let committed = std::fs::read(&path).expect("committed database");
            assert_eq!(&committed[..8], &OLE_MAGIC);

            let (reopened, _) = open_fixture(&mut fixture, "reopen.msi", &committed);
            assert_ne!(reopened, 0);
            let state = fixture.runtime.msi_databases.get(&reopened).unwrap();
            assert!(state.extras.contains_key("_Validation"));
            assert_eq!(state.extras.get("LargeExtra").unwrap().1.len(), 5000);
            let view = open_view(&mut fixture, reopened, "SELECT * FROM TestTable");
            assert_eq!(execute(&mut fixture, view), 0);

            let (result, record) = fetch(&mut fixture, view);
            assert_eq!(result, 0);
            assert_eq!(
                record_string(&mut fixture, record, 1),
                (0, "Beta".to_string())
            );
            assert_eq!(record_integer(&mut fixture, record, 2), 99);

            let (result, record) = fetch(&mut fixture, view);
            assert_eq!(result, 0);
            assert_eq!(
                record_string(&mut fixture, record, 1),
                (0, "Gamma".to_string())
            );
            assert_eq!(record_integer(&mut fixture, record, 2), 5);
            assert_eq!(fetch(&mut fixture, view).0, 259);
        });
    }

    #[test]
    fn compound_reader_handles_fat_and_difat() {
        let mut big = vec![0u8; 8_000_000];
        big[0] = 0x11;
        big[7_999_999] = 0x22;
        let bytes = write_compound_file(&[
            ("Big".to_string(), big.clone()),
            ("Small".to_string(), b"mini".to_vec()),
        ]);
        let compound = CompoundFile::parse(bytes).expect("parse compound file");
        assert_eq!(compound.stream("Big"), Some(big));
        assert_eq!(compound.stream("Small"), Some(b"mini".to_vec()));
    }

    #[test]
    fn msi_adversarial_error_paths() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-adversarial");
            let (db, _path) = open_fixture(&mut fixture, "adversarial.msi", &fixture_compound());

            for sql in [
                "SELEC * FROM TestTable",
                "SELECT * FROM",
                "SELECT Missing FROM TestTable",
                "SELECT * FROM TestTable WHERE Data = 1",
            ] {
                write_wide(&mut fixture.memory, QUERY_PTR, sql);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::MsiDatabaseOpenViewW,
                        &[db as u32, QUERY_PTR as u32, OUT_PTR as u32]
                    ),
                    1615,
                    "{sql}"
                );
            }
            write_wide(&mut fixture.memory, QUERY_PTR, "SELECT * FROM MissingTable");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiDatabaseOpenViewW,
                    &[db as u32, QUERY_PTR as u32, OUT_PTR as u32]
                ),
                1626
            );

            let view = open_view(&mut fixture, db, "SELECT * FROM TestTable");
            assert_eq!(fetch(&mut fixture, view).0, 259);
            assert_eq!(execute(&mut fixture, view), 0);
            assert_eq!(fetch(&mut fixture, view).0, 0);

            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordGetStringW,
                    &[0xDEAD, 1, STRING_PTR as u32, STRING_SIZE as u32]
                ),
                6
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiRecordGetInteger, &[0xDEAD, 1]),
                u64::from(i32::MIN as u32)
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiRecordDataSize, &[0xDEAD, 1]),
                0
            );
            assert_eq!(record_string(&mut fixture, 0xDEAD, 99).0, 6);

            let record = dispatch_x86(&mut fixture, HostThunk::MsiCreateRecord, &[2]) as u32 as u64;
            assert_eq!(record_string(&mut fixture, record, 99).0, 1614);
            write_wide(&mut fixture.memory, STRING_PTR, "x");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordSetStringW,
                    &[record as u32, 99, STRING_PTR as u32]
                ),
                1614
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewModify,
                    &[0xDEAD, 1, record as u32]
                ),
                6
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewModify,
                    &[view as u32, 1, 0xDEAD]
                ),
                6
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewModify,
                    &[view as u32, 99, record as u32]
                ),
                87
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiRecordSetInteger,
                    &[record as u32, 0, 99]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewModify,
                    &[view as u32, 2, record as u32]
                ),
                1627
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewGetColumnInfo,
                    &[view as u32, 2, OUT_PTR as u32]
                ),
                87
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiCloseHandle, &[0xDEAD]),
                6
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiViewClose, &[view as u32]),
                0
            );
            assert_eq!(fetch(&mut fixture, view).0, 259);
            assert_eq!(execute(&mut fixture, view), 0);
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiCloseHandle, &[view as u32]),
                0
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::MsiViewFetch, &[view as u32, 0]),
                6
            );
        });
    }
}
