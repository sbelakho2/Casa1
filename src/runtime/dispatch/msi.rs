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
/// ERROR_UNKNOWN_TABLE (a table qualifier/alias that is not in the FROM list).
const ERROR_UNKNOWN_TABLE: u32 = 1612;
/// ERROR_BAD_COLUMN (a column that does not exist or is ambiguous).
const ERROR_BAD_COLUMN: u32 = 1616;
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

/// One `SELECT` item.  A `None` column is `*`/`table.*`.
#[derive(Debug, Clone)]
struct SqlSelectItem {
    table: Option<String>,
    column: Option<String>,
    alias: Option<String>,
}

/// A table reference in `FROM`, with an optional `AS`/bare alias.
#[derive(Debug, Clone)]
struct SqlTableRef {
    table: String,
    alias: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlJoinKind {
    Inner,
    LeftOuter,
}

#[derive(Debug, Clone)]
struct SqlJoin {
    kind: SqlJoinKind,
    table: SqlTableRef,
    on: SqlExpr,
}

#[derive(Debug, Clone)]
struct SqlFrom {
    base: SqlTableRef,
    joins: Vec<SqlJoin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlCompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// The supported expression set is deliberately small: a column reference
/// (optionally `Table.Column` or `Alias.Column`), an integer/string literal,
/// a positional `?` parameter, `IS [NOT] NULL`, the comparison operators
/// `=`, `!=`, `<>`, `<`, `<=`, `>`, `>=`, and `AND`/`OR` with parentheses.
/// There are no arithmetic, function, subquery or `NOT` expressions.
#[derive(Debug, Clone)]
enum SqlExpr {
    Column {
        table: Option<String>,
        name: String,
    },
    Literal(MsiValue),
    Parameter(usize),
    IsNull {
        value: Box<SqlExpr>,
        negated: bool,
    },
    Compare {
        left: Box<SqlExpr>,
        op: SqlCompareOp,
        right: Box<SqlExpr>,
    },
    And(Box<SqlExpr>, Box<SqlExpr>),
    Or(Box<SqlExpr>, Box<SqlExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlDirection {
    Ascending,
    Descending,
}

#[derive(Debug, Clone)]
struct SqlOrderKey {
    table: Option<String>,
    name: String,
    direction: SqlDirection,
}

/// A parsed SELECT statement before schema resolution.  MSI SQL surface:
/// `SELECT [DISTINCT] *|exprlist FROM table [alias]
///  [INNER|LEFT [OUTER] JOIN table [alias] ON expr]...
///  [WHERE expr] [ORDER BY column [ASC|DESC], ...]`.
#[derive(Debug, Clone)]
struct MsiQuery {
    distinct: bool,
    columns: Vec<SqlSelectItem>,
    from: SqlFrom,
    filter: Option<SqlExpr>,
    order: Vec<SqlOrderKey>,
    parameter_count: usize,
}

/// A table after FROM resolution (index 0 is the base table).
#[derive(Debug, Clone)]
struct ResolvedTable {
    name: String,
    alias: Option<String>,
}

/// One projected output column and its label/type for `MsiViewGetColumnInfo`.
#[derive(Debug, Clone)]
struct ResolvedColumn {
    table: usize,
    column: usize,
    label: String,
    type_name: String,
}

#[derive(Debug, Clone)]
struct ResolvedJoin {
    table: usize,
    kind: SqlJoinKind,
    on: ResolvedExpr,
}

#[derive(Debug, Clone)]
enum OrderSource {
    Column { table: usize, column: usize },
    Output(usize),
}

#[derive(Debug, Clone)]
struct ResolvedOrder {
    key: OrderSource,
    direction: SqlDirection,
}

/// The comparison context in which a `?` parameter appears.
#[derive(Debug, Clone, Copy)]
enum ParameterExpectation {
    Any,
    Int,
    String { width: u16 },
}

/// A parsed expression with every column bound to a (table, column) index.
#[derive(Debug, Clone)]
enum ResolvedExpr {
    Column {
        table: usize,
        column: usize,
    },
    Literal(MsiValue),
    Parameter(usize),
    IsNull {
        value: Box<ResolvedExpr>,
        negated: bool,
    },
    Compare {
        left: Box<ResolvedExpr>,
        op: SqlCompareOp,
        right: Box<ResolvedExpr>,
    },
    And(Box<ResolvedExpr>, Box<ResolvedExpr>),
    Or(Box<ResolvedExpr>, Box<ResolvedExpr>),
}

#[derive(Debug, Clone)]
struct ResolvedQuery {
    distinct: bool,
    tables: Vec<ResolvedTable>,
    columns: Vec<ResolvedColumn>,
    joins: Vec<ResolvedJoin>,
    filter: Option<ResolvedExpr>,
    order: Vec<ResolvedOrder>,
    parameter_expectations: Vec<ParameterExpectation>,
}

/// A projected view row plus the source row index in each FROM table
/// (`None` for the null-extended side of an outer join).
#[derive(Debug, Clone)]
struct ViewRow {
    values: Vec<MsiValue>,
    source: Vec<Option<usize>>,
}

/// A view: the resolved query plus the executed row snapshot and cursor.
/// The bound parameter values are retained so a database mutation can
/// re-execute parameterized views without inventing new parameter values.
#[derive(Debug, Clone)]
pub(crate) struct MsiViewState {
    db: u64,
    query: ResolvedQuery,
    rows: Vec<ViewRow>,
    next: usize,
    executed: bool,
    bound: Vec<MsiValue>,
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

/// A directory entry in an OLE compound file.
#[derive(Debug, Clone)]
pub(crate) struct CompoundEntry {
    pub(crate) name: String,
    pub(crate) kind: u8,
    pub(crate) start: u32,
    pub(crate) size: u64,
}

/// A parsed OLE compound file (CFB v3/v4) with its allocation tables and
/// directory.  Streams are read on demand from the raw file bytes.
#[derive(Debug, Clone)]
pub(crate) struct CompoundFile {
    bytes: Vec<u8>,
    pub(crate) sector_size: usize,
    pub(crate) mini_sector_size: usize,
    pub(crate) cutoff: u32,
    pub(crate) fat: Vec<u32>,
    pub(crate) mini_fat: Vec<u32>,
    pub(crate) entries: Vec<CompoundEntry>,
    pub(crate) mini_stream: Vec<u8>,
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
    pub(crate) fn parse(bytes: Vec<u8>) -> Result<Self, String> {
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

    pub(crate) fn stream(&self, name: &str) -> Option<Vec<u8>> {
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

    pub(crate) fn stream_names(&self) -> Vec<String> {
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
                let record = guest_call_arg(state, memory, 1)?;
                let result = self.msi_execute_view(view, record);
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
        let resolved = match resolve_query(database, parsed) {
            Ok(resolved) => resolved,
            Err(code) => {
                state.set(Register::Rax, u64::from(code));
                return Ok(());
            }
        };
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
                query: resolved,
                rows: Vec::new(),
                next: 0,
                executed: false,
                bound: Vec::new(),
            },
        );
        if out != 0 {
            write_guest_pointer(memory, out, view, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(ERROR_SUCCESS));
        Ok(())
    }

    fn msi_execute_view(&mut self, handle: u64, record_handle: u64) -> u32 {
        let Some(view) = self.msi_views.get(&handle) else {
            return ERROR_INVALID_HANDLE;
        };
        let query = view.query.clone();
        let db = view.db;
        let record = if record_handle == 0 || query.parameter_expectations.is_empty() {
            None
        } else {
            match self.msi_records.get(&record_handle) {
                Some(record) => Some(record),
                None => return ERROR_INVALID_HANDLE,
            }
        };
        let parameters = match bind_parameters(&query, record) {
            Ok(parameters) => parameters,
            Err(code) => return code,
        };
        let Some(database) = self.msi_databases.get(&db) else {
            return ERROR_INVALID_HANDLE;
        };
        let rows = match execute_query(database, &query, &parameters) {
            Ok(rows) => rows,
            Err(code) => return code,
        };
        let Some(view) = self.msi_views.get_mut(&handle) else {
            return ERROR_INVALID_HANDLE;
        };
        view.rows = rows;
        view.next = 0;
        view.executed = true;
        view.bound = parameters;
        ERROR_SUCCESS
    }

    fn msi_fetch(&mut self, handle: u64, memory: &mut MemoryImage) -> (u32, u64) {
        let Some(view) = self.msi_views.get(&handle) else {
            return (ERROR_INVALID_HANDLE, 0);
        };
        if !view.executed || view.next >= view.rows.len() {
            return (ERROR_NO_MORE_ITEMS, 0);
        }
        let query = view.query.clone();
        let row = view.rows[view.next].clone();
        let mut record = MsiRecord::new(query.columns.len());
        record.fields[0] = MsiValue::Int(if query.tables.len() == 1 {
            row.source
                .first()
                .copied()
                .flatten()
                .map(|index| index as i32 + 1)
                .unwrap_or(0)
        } else {
            0
        });
        for (slot, value) in row.values.iter().enumerate() {
            record.fields[slot + 1] = value.clone();
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
        let query = view.query.clone();
        let mut record = MsiRecord::new(query.columns.len());
        record.fields[0] = MsiValue::Int(0);
        for (slot, column) in query.columns.iter().enumerate() {
            record.fields[slot + 1] = MsiValue::Str(if info == 0 {
                column.label.clone()
            } else {
                column.type_name.clone()
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
        let base_table = if view.query.tables.len() == 1 {
            Some(view.query.tables[0].name.clone())
        } else {
            None
        };
        let result = match mode {
            1 => match &base_table {
                Some(name) => match self.msi_databases.get_mut(&view.db) {
                    Some(database) => match database.table_mut(name) {
                        Some(table) => insert_record(table, &record),
                        None => ERROR_INVALID_TABLE,
                    },
                    None => ERROR_INVALID_HANDLE,
                },
                None => ERROR_FUNCTION_FAILED,
            },
            2 | 3 | 4 | 5 => match &base_table {
                Some(name) => match self.msi_databases.get_mut(&view.db) {
                    Some(database) => match database.table_mut(name) {
                        Some(table) => update_record(table, &record),
                        None => ERROR_INVALID_TABLE,
                    },
                    None => ERROR_INVALID_HANDLE,
                },
                None => ERROR_FUNCTION_FAILED,
            },
            6 => match &base_table {
                Some(name) => match self.msi_databases.get_mut(&view.db) {
                    Some(database) => match database.table_mut(name) {
                        Some(table) => delete_record(table, &record),
                        None => ERROR_INVALID_TABLE,
                    },
                    None => ERROR_INVALID_HANDLE,
                },
                None => ERROR_FUNCTION_FAILED,
            },
            7 => {
                return self.msi_seek_view(handle, &view, base_table.as_deref(), &record);
            }
            8 => {
                return self.msi_refresh_view(
                    handle,
                    &view,
                    base_table.as_deref(),
                    record_handle,
                    &record,
                );
            }
            10 | 11 => {
                return self.msi_validate_view(&view, base_table.as_deref(), &record);
            }
            _ => ERROR_INVALID_PARAMETER,
        };
        if result == ERROR_SUCCESS {
            self.msi_refresh_views(view.db);
        }
        result
    }

    /// `MSIDBVIEWMODIFY_SEEK`: position the view on the row whose primary key
    /// values match the record.  Key values are taken from record fields 1..n
    /// in key order, falling back to the field at the key column's position
    /// (the layout of a record fetched from the view).
    fn msi_seek_view(
        &mut self,
        handle: u64,
        view: &MsiViewState,
        base_table: Option<&str>,
        record: &MsiRecord,
    ) -> u32 {
        let Some(name) = base_table else {
            return ERROR_FUNCTION_FAILED;
        };
        let Some(database) = self.msi_databases.get(&view.db) else {
            return ERROR_INVALID_HANDLE;
        };
        let Some(table) = database.table(name) else {
            return ERROR_INVALID_TABLE;
        };
        let key_columns: Vec<usize> = table
            .columns
            .iter()
            .enumerate()
            .filter(|(_, column)| column.is_key())
            .map(|(index, _)| index)
            .collect();
        if key_columns.is_empty() {
            return ERROR_FUNCTION_FAILED;
        }
        let mut wanted = Vec::with_capacity(key_columns.len());
        for (ordinal, column) in key_columns.iter().enumerate() {
            let sequential = record.fields.get(ordinal + 1);
            let positional = record.fields.get(column + 1);
            let value = match sequential {
                Some(value) if !matches!(value, MsiValue::Null) => value.clone(),
                _ => positional.cloned().unwrap_or(MsiValue::Null),
            };
            wanted.push(value);
        }
        let Some(row_index) = table.rows.iter().position(|row| {
            key_columns.iter().zip(&wanted).all(|(column, expected)| {
                msi_value_equal(row.get(*column).unwrap_or(&MsiValue::Null), expected)
            })
        }) else {
            return ERROR_NO_MORE_ITEMS;
        };
        let Some(position) = view
            .rows
            .iter()
            .position(|row| row.source.len() == 1 && row.source[0] == Some(row_index))
        else {
            return ERROR_NO_MORE_ITEMS;
        };
        if let Some(view) = self.msi_views.get_mut(&handle) {
            view.next = position;
        }
        ERROR_SUCCESS
    }

    /// `MSIDBVIEWMODIFY_REFRESH`: re-read the row selected by the record's
    /// field 0, update the record and the view snapshot with current data.
    fn msi_refresh_view(
        &mut self,
        handle: u64,
        view: &MsiViewState,
        base_table: Option<&str>,
        record_handle: u64,
        record: &MsiRecord,
    ) -> u32 {
        let Some(name) = base_table else {
            return ERROR_FUNCTION_FAILED;
        };
        let Some(row_number) = record_int(record, 0) else {
            return ERROR_FUNCTION_FAILED;
        };
        if row_number <= 0 {
            return ERROR_FUNCTION_FAILED;
        }
        let row_index = row_number as usize - 1;
        let Some(database) = self.msi_databases.get(&view.db) else {
            return ERROR_INVALID_HANDLE;
        };
        let Some(table) = database.table(name) else {
            return ERROR_INVALID_TABLE;
        };
        if row_index >= table.rows.len() {
            return ERROR_FUNCTION_FAILED;
        }
        let source = vec![Some(row_index)];
        if let Some(filter) = &view.query.filter {
            if !eval_expr(database, &view.query, &source, &view.bound, filter) {
                return ERROR_NO_MORE_ITEMS;
            }
        }
        let values = project_row(database, &view.query, &source);
        let Some(position) = view
            .rows
            .iter()
            .position(|row| row.source.len() == 1 && row.source[0] == Some(row_index))
        else {
            return ERROR_NO_MORE_ITEMS;
        };
        if let Some(view) = self.msi_views.get_mut(&handle) {
            view.rows[position].values = values.clone();
        }
        if let Some(target) = self.msi_records.get_mut(&record_handle) {
            for (slot, value) in values.iter().enumerate() {
                if let Some(field) = target.fields.get_mut(slot + 1) {
                    *field = value.clone();
                }
            }
        }
        ERROR_SUCCESS
    }

    /// `MSIDBVIEWMODIFY_VALIDATE`/`VALIDATENEW`: validate the record against
    /// `_Validation` when that table is present, plus structural checks
    /// (required fields, declared string width, foreign keys).
    fn msi_validate_view(
        &mut self,
        view: &MsiViewState,
        base_table: Option<&str>,
        record: &MsiRecord,
    ) -> u32 {
        let Some(name) = base_table else {
            return ERROR_FUNCTION_FAILED;
        };
        let Some(database) = self.msi_databases.get(&view.db) else {
            return ERROR_INVALID_HANDLE;
        };
        let Some(table) = database.table(name) else {
            return ERROR_INVALID_TABLE;
        };
        validate_table_record(database, table, record)
    }

    fn msi_refresh_views(&mut self, db: u64) {
        let updates: Vec<(u64, Vec<ViewRow>)> = self
            .msi_views
            .iter()
            .filter(|(_, view)| view.db == db && view.executed)
            .filter_map(|(handle, view)| {
                self.msi_databases
                    .get(&db)
                    .and_then(|database| execute_query(database, &view.query, &view.bound).ok())
                    .map(|rows| (*handle, rows))
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

/// MSI string comparisons are case-insensitive (database collation), so every
/// SQL comparison, DISTINCT check and ORDER BY key folds ASCII case.
fn sql_lower(ch: char) -> char {
    if ch.is_ascii() {
        ch.to_ascii_lowercase()
    } else {
        ch
    }
}

fn sql_string_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.chars()
        .map(sql_lower)
        .cmp(right.chars().map(sql_lower))
}

fn msi_value_equal(left: &MsiValue, right: &MsiValue) -> bool {
    match (left, right) {
        (MsiValue::Null, MsiValue::Null) => true,
        (MsiValue::Int(left), MsiValue::Int(right)) => left == right,
        (MsiValue::Str(left), MsiValue::Str(right)) => left.eq_ignore_ascii_case(right),
        (MsiValue::Stream(left), MsiValue::Stream(right)) => left == right,
        _ => false,
    }
}

fn compare_msi_values(left: &MsiValue, op: SqlCompareOp, right: &MsiValue) -> bool {
    let ordering = match (left, right) {
        (MsiValue::Int(left), MsiValue::Int(right)) => left.cmp(right),
        (MsiValue::Str(left), MsiValue::Str(right)) => sql_string_cmp(left, right),
        // SQL three-valued logic: any comparison with NULL is unknown/false.
        _ => return false,
    };
    match op {
        SqlCompareOp::Eq => ordering.is_eq(),
        SqlCompareOp::Ne => ordering.is_ne(),
        SqlCompareOp::Lt => ordering.is_lt(),
        SqlCompareOp::Le => ordering.is_le(),
        SqlCompareOp::Gt => ordering.is_gt(),
        SqlCompareOp::Ge => ordering.is_ge(),
    }
}

fn source_value(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    source: &[Option<usize>],
    table: usize,
    column: usize,
) -> MsiValue {
    let Some(Some(row_index)) = source.get(table) else {
        return MsiValue::Null;
    };
    let Some(meta) = tables.get(table) else {
        return MsiValue::Null;
    };
    let Some(table) = database.table(&meta.name) else {
        return MsiValue::Null;
    };
    table
        .rows
        .get(*row_index)
        .and_then(|row| row.get(column))
        .cloned()
        .unwrap_or(MsiValue::Null)
}

fn eval_value(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
    parameters: &[MsiValue],
    expression: &ResolvedExpr,
) -> MsiValue {
    match expression {
        ResolvedExpr::Column { table, column } => {
            source_value(database, &query.tables, source, *table, *column)
        }
        ResolvedExpr::Literal(value) => value.clone(),
        ResolvedExpr::Parameter(index) => parameters.get(*index).cloned().unwrap_or(MsiValue::Null),
        _ => MsiValue::Null,
    }
}

fn eval_expr(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
    parameters: &[MsiValue],
    expression: &ResolvedExpr,
) -> bool {
    match expression {
        ResolvedExpr::And(left, right) => {
            eval_expr(database, query, source, parameters, left)
                && eval_expr(database, query, source, parameters, right)
        }
        ResolvedExpr::Or(left, right) => {
            eval_expr(database, query, source, parameters, left)
                || eval_expr(database, query, source, parameters, right)
        }
        ResolvedExpr::Compare { left, op, right } => compare_msi_values(
            &eval_value(database, query, source, parameters, left),
            *op,
            &eval_value(database, query, source, parameters, right),
        ),
        ResolvedExpr::IsNull { value, negated } => {
            let is_null = matches!(
                eval_value(database, query, source, parameters, value),
                MsiValue::Null
            );
            if *negated { !is_null } else { is_null }
        }
        _ => false,
    }
}

fn project_row(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
) -> Vec<MsiValue> {
    query
        .columns
        .iter()
        .map(|column| source_value(database, &query.tables, source, column.table, column.column))
        .collect()
}

fn deduplicate_rows(rows: &mut Vec<ViewRow>) {
    let mut unique: Vec<ViewRow> = Vec::new();
    for row in rows.drain(..) {
        let duplicate = unique.iter().any(|existing| {
            existing.values.len() == row.values.len()
                && existing
                    .values
                    .iter()
                    .zip(&row.values)
                    .all(|(left, right)| msi_value_equal(left, right))
        });
        if !duplicate {
            unique.push(row);
        }
    }
    *rows = unique;
}

fn order_value(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
    values: &[MsiValue],
    key: &OrderSource,
) -> MsiValue {
    match key {
        OrderSource::Output(index) => values.get(*index).cloned().unwrap_or(MsiValue::Null),
        OrderSource::Column { table, column } => {
            source_value(database, &query.tables, source, *table, *column)
        }
    }
}

fn compare_order_values(left: &MsiValue, right: &MsiValue) -> std::cmp::Ordering {
    match (left, right) {
        (MsiValue::Null, MsiValue::Null) => std::cmp::Ordering::Equal,
        // MSI sorts NULL before non-NULL ascending; reversing for DESC puts
        // them after every value, matching SQL Server/MSI.
        (MsiValue::Null, _) => std::cmp::Ordering::Less,
        (_, MsiValue::Null) => std::cmp::Ordering::Greater,
        (MsiValue::Int(left), MsiValue::Int(right)) => left.cmp(right),
        (MsiValue::Str(left), MsiValue::Str(right)) => sql_string_cmp(left, right),
        (MsiValue::Stream(left), MsiValue::Stream(right)) => left.cmp(right),
        (MsiValue::Int(_), _) => std::cmp::Ordering::Less,
        _ => std::cmp::Ordering::Greater,
    }
}

fn sort_rows(database: &MsiDatabaseState, query: &ResolvedQuery, rows: &mut [ViewRow]) {
    rows.sort_by(|left, right| {
        for order in &query.order {
            let left_value = order_value(database, query, &left.source, &left.values, &order.key);
            let right_value =
                order_value(database, query, &right.source, &right.values, &order.key);
            let mut ordering = compare_order_values(&left_value, &right_value);
            if order.direction == SqlDirection::Descending {
                ordering = ordering.reverse();
            }
            if !ordering.is_eq() {
                return ordering;
            }
        }
        std::cmp::Ordering::Equal
    });
}

fn execute_query(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    parameters: &[MsiValue],
) -> Result<Vec<ViewRow>, u32> {
    let Some(base) = query.tables.first() else {
        return Err(ERROR_BAD_QUERY_SYNTAX);
    };
    let base_table = database.table(&base.name).ok_or(ERROR_INVALID_TABLE)?;
    let mut partial: Vec<Vec<Option<usize>>> = (0..base_table.rows.len())
        .map(|index| vec![Some(index)])
        .collect();
    for join in &query.joins {
        let Some(meta) = query.tables.get(join.table) else {
            return Err(ERROR_BAD_QUERY_SYNTAX);
        };
        let table = database.table(&meta.name).ok_or(ERROR_INVALID_TABLE)?;
        let mut combined = Vec::new();
        for source in partial {
            let mut matched = false;
            for row_index in 0..table.rows.len() {
                let mut candidate = source.clone();
                candidate.push(Some(row_index));
                if eval_expr(database, query, &candidate, parameters, &join.on) {
                    matched = true;
                    combined.push(candidate);
                }
            }
            if !matched && join.kind == SqlJoinKind::LeftOuter {
                let mut candidate = source;
                candidate.push(None);
                combined.push(candidate);
            }
        }
        partial = combined;
    }
    let mut rows = Vec::new();
    for source in partial {
        if let Some(filter) = &query.filter {
            if !eval_expr(database, query, &source, parameters, filter) {
                continue;
            }
        }
        let values = project_row(database, query, &source);
        rows.push(ViewRow { values, source });
    }
    if query.distinct {
        deduplicate_rows(&mut rows);
    }
    if !query.order.is_empty() {
        sort_rows(database, query, &mut rows);
    }
    Ok(rows)
}

/// Bind `?` values in order, validating the record field count and coercing
/// each value to the column type the parameter is compared against.  A
/// non-numeric string for an integer column, a stream, or a string longer
/// than the column width is ERROR_INVALID_DATATYPE; a wrong field count is
/// ERROR_INVALID_PARAMETER.
fn bind_parameters(
    query: &ResolvedQuery,
    record: Option<&MsiRecord>,
) -> Result<Vec<MsiValue>, u32> {
    let count = query.parameter_expectations.len();
    if count == 0 {
        return Ok(Vec::new());
    }
    let Some(record) = record else {
        return Err(ERROR_INVALID_PARAMETER);
    };
    let fields = record.fields.len().saturating_sub(1);
    if fields != count {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut values = Vec::with_capacity(count);
    for (index, expectation) in query.parameter_expectations.iter().enumerate() {
        let value = record
            .fields
            .get(index + 1)
            .cloned()
            .unwrap_or(MsiValue::Null);
        match expectation {
            ParameterExpectation::Any => match value {
                MsiValue::Stream(_) => return Err(ERROR_INVALID_DATATYPE),
                value => values.push(value),
            },
            ParameterExpectation::Int => match value {
                MsiValue::Null => values.push(MsiValue::Null),
                MsiValue::Int(number) => values.push(MsiValue::Int(number)),
                MsiValue::Str(text) => match text.trim().parse::<i32>() {
                    Ok(number) => values.push(MsiValue::Int(number)),
                    Err(_) => return Err(ERROR_INVALID_DATATYPE),
                },
                MsiValue::Stream(_) => return Err(ERROR_INVALID_DATATYPE),
            },
            ParameterExpectation::String { width } => match value {
                MsiValue::Null => values.push(MsiValue::Null),
                MsiValue::Str(text) => {
                    if *width > 0 && text.encode_utf16().count() > *width as usize {
                        return Err(ERROR_INVALID_DATATYPE);
                    }
                    values.push(MsiValue::Str(text));
                }
                MsiValue::Int(number) => {
                    let text = number.to_string();
                    if *width > 0 && text.encode_utf16().count() > *width as usize {
                        return Err(ERROR_INVALID_DATATYPE);
                    }
                    values.push(MsiValue::Str(text));
                }
                MsiValue::Stream(_) => return Err(ERROR_INVALID_DATATYPE),
            },
        }
    }
    Ok(values)
}

#[derive(Debug, Clone)]
struct ValidationRule {
    nullable: Option<bool>,
    min: Option<i32>,
    max: Option<i32>,
    key_table: Option<String>,
    key_column: Option<String>,
}

fn value_as_i32(value: &MsiValue) -> Option<i32> {
    match value {
        // MSI encodes a NULL integer cell as the sign-bit sentinel; empty
        // MinValue/MaxValue cells decode to i32::MIN and are not constraints.
        MsiValue::Int(number) if *number != i32::MIN => Some(*number),
        MsiValue::Str(text) => text
            .trim()
            .parse::<i32>()
            .ok()
            .filter(|number| *number != i32::MIN),
        MsiValue::Null | MsiValue::Int(_) | MsiValue::Stream(_) => None,
    }
}

fn value_as_text(value: &MsiValue) -> Option<String> {
    match value {
        MsiValue::Str(text) if !text.is_empty() => Some(text.clone()),
        MsiValue::Int(number) => Some(number.to_string()),
        MsiValue::Null | MsiValue::Stream(_) | MsiValue::Str(_) => None,
    }
}

fn validation_rule(
    database: &MsiDatabaseState,
    table_name: &str,
    column_name: &str,
) -> Option<ValidationRule> {
    let validation = database.table("_Validation")?;
    let find = |name: &str| {
        validation
            .columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
    };
    let table_column = find("Table")?;
    let name_column = find("Column")?;
    let nullable_column = find("Nullable");
    let min_column = find("MinValue");
    let max_column = find("MaxValue");
    let key_table_column = find("KeyTable");
    let key_column_column = find("KeyColumn");
    for row in &validation.rows {
        let Some(MsiValue::Str(table_value)) = row.get(table_column) else {
            continue;
        };
        if !table_value.eq_ignore_ascii_case(table_name) {
            continue;
        }
        let Some(MsiValue::Str(name_value)) = row.get(name_column) else {
            continue;
        };
        if !name_value.eq_ignore_ascii_case(column_name) {
            continue;
        }
        let nullable =
            nullable_column
                .and_then(|index| row.get(index))
                .and_then(|value| match value {
                    MsiValue::Int(number) => Some(*number != 0),
                    MsiValue::Str(text) if text.eq_ignore_ascii_case("Y") => Some(true),
                    MsiValue::Str(text) if text.eq_ignore_ascii_case("N") => Some(false),
                    _ => None,
                });
        return Some(ValidationRule {
            nullable,
            min: min_column
                .and_then(|index| row.get(index))
                .and_then(value_as_i32),
            max: max_column
                .and_then(|index| row.get(index))
                .and_then(value_as_i32),
            key_table: key_table_column
                .and_then(|index| row.get(index))
                .and_then(value_as_text),
            key_column: key_column_column
                .and_then(|index| row.get(index))
                .and_then(value_as_text),
        });
    }
    None
}

/// Structural validation plus the row-level rules in `_Validation`:
/// nullability, integer MinValue/MaxValue, declared string width and
/// KeyTable/KeyColumn foreign-key existence.
fn validate_table_record(database: &MsiDatabaseState, table: &MsiTable, record: &MsiRecord) -> u32 {
    let row = match build_record_row(table, record, true) {
        Ok(row) => row,
        Err(code) => return code,
    };
    for (index, column) in table.columns.iter().enumerate() {
        let value = row.get(index).cloned().unwrap_or(MsiValue::Null);
        if column.is_string() && !column.is_binary() {
            if let MsiValue::Str(text) = &value {
                if column.width() > 0 && text.encode_utf16().count() > column.width() as usize {
                    return ERROR_INVALID_DATA;
                }
            }
        }
        let Some(rule) = validation_rule(database, &table.name, &column.name) else {
            continue;
        };
        if rule.nullable == Some(false) && matches!(value, MsiValue::Null) {
            return ERROR_INVALID_DATA;
        }
        if let MsiValue::Int(number) = &value {
            if rule.min.is_some_and(|min| *number < min) {
                return ERROR_INVALID_DATA;
            }
            if rule.max.is_some_and(|max| *number > max) {
                return ERROR_INVALID_DATA;
            }
        }
        if let (Some(key_table), Some(key_column)) = (&rule.key_table, &rule.key_column) {
            if !matches!(value, MsiValue::Null) {
                let Some(referenced) = database.table(key_table) else {
                    return ERROR_INVALID_DATA;
                };
                let Some(referenced_column) = referenced
                    .columns
                    .iter()
                    .position(|candidate| candidate.name.eq_ignore_ascii_case(key_column))
                else {
                    return ERROR_INVALID_DATA;
                };
                let found = referenced.rows.iter().any(|row| {
                    row.get(referenced_column)
                        .is_some_and(|candidate| msi_value_equal(candidate, &value))
                });
                if !found {
                    return ERROR_INVALID_DATA;
                }
            }
        }
    }
    ERROR_SUCCESS
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

    fn peek_word(&self) -> String {
        let mut position = self.position;
        while self
            .chars
            .get(position)
            .is_some_and(|ch| ch.is_whitespace())
        {
            position += 1;
        }
        let start = position;
        while self
            .chars
            .get(position)
            .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == '_')
        {
            position += 1;
        }
        self.chars[start..position].iter().collect()
    }

    fn consume_word(&mut self, expected: &str) -> bool {
        if self.peek_word().eq_ignore_ascii_case(expected) {
            self.word();
            true
        } else {
            false
        }
    }

    /// Parse `name` or `table.name`; the unquoted form arrives as one token
    /// because `ident` accepts embedded dots.
    fn name_ref(&mut self) -> Result<(Option<String>, String), ()> {
        let first = self.ident()?;
        if first.is_empty() {
            return Err(());
        }
        if self.peek() == Some('.') {
            self.position += 1;
            let second = self.ident()?;
            if second.is_empty() || second.contains('.') {
                return Err(());
            }
            return Ok((Some(first), second));
        }
        match first.split_once('.') {
            Some((table, column))
                if !table.is_empty() && !column.is_empty() && !column.contains('.') =>
            {
                Ok((Some(table.to_string()), column.to_string()))
            }
            Some(_) => Err(()),
            None => Ok((None, first)),
        }
    }

    fn select_item(&mut self) -> Result<SqlSelectItem, ()> {
        self.skip_space();
        if self.peek() == Some('*') {
            self.position += 1;
            return Ok(SqlSelectItem {
                table: None,
                column: None,
                alias: None,
            });
        }
        let first = self.ident()?;
        if first.is_empty() {
            return Err(());
        }
        if first.ends_with('.') && self.peek() == Some('*') {
            self.position += 1;
            return Ok(SqlSelectItem {
                table: Some(first.trim_end_matches('.').to_string()),
                column: None,
                alias: None,
            });
        }
        if self.peek() == Some('.') {
            self.position += 1;
            if self.peek() == Some('*') {
                self.position += 1;
                return Ok(SqlSelectItem {
                    table: Some(first),
                    column: None,
                    alias: None,
                });
            }
            let second = self.ident()?;
            if second.is_empty() || second.contains('.') {
                return Err(());
            }
            return Ok(SqlSelectItem {
                table: Some(first),
                column: Some(second),
                alias: None,
            });
        }
        match first.split_once('.') {
            Some((table, column))
                if !table.is_empty() && !column.is_empty() && !column.contains('.') =>
            {
                Ok(SqlSelectItem {
                    table: Some(table.to_string()),
                    column: Some(column.to_string()),
                    alias: None,
                })
            }
            Some(_) => Err(()),
            None => Ok(SqlSelectItem {
                table: None,
                column: Some(first),
                alias: None,
            }),
        }
    }

    fn parse_optional_alias(&mut self, stop: &[&str]) -> Result<Option<String>, ()> {
        self.skip_space();
        if self.peek().is_none() {
            return Ok(None);
        }
        if self.consume_word("AS") {
            let alias = self.ident()?;
            return if alias.is_empty() {
                Err(())
            } else {
                Ok(Some(alias))
            };
        }
        let word = self.peek_word();
        if word.is_empty()
            || stop
                .iter()
                .any(|keyword| word.eq_ignore_ascii_case(keyword))
        {
            return Ok(None);
        }
        match self.peek() {
            Some(ch) if ch.is_ascii_alphabetic() || ch == '_' || ch == '`' || ch == '[' => {
                let alias = self.ident()?;
                if alias.is_empty() {
                    Err(())
                } else {
                    Ok(Some(alias))
                }
            }
            _ => Ok(None),
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
    let mut parameters = 0usize;
    cursor.expect_word("SELECT")?;
    let distinct = cursor.consume_word("DISTINCT");
    let columns = parse_select_list(&mut cursor)?;
    cursor.expect_word("FROM")?;
    let from = parse_from(&mut cursor, &mut parameters)?;
    let filter = if cursor.consume_word("WHERE") {
        Some(parse_expression(&mut cursor, &mut parameters)?)
    } else {
        None
    };
    let order = if cursor.consume_word("ORDER") {
        cursor.expect_word("BY")?;
        parse_order_list(&mut cursor)?
    } else {
        Vec::new()
    };
    if !cursor.at_end() {
        return Err(());
    }
    Ok(MsiQuery {
        distinct,
        columns,
        from,
        filter,
        order,
        parameter_count: parameters,
    })
}

fn parse_select_list(cursor: &mut SqlCursor) -> Result<Vec<SqlSelectItem>, ()> {
    let mut items = Vec::new();
    loop {
        let mut item = cursor.select_item()?;
        item.alias = cursor.parse_optional_alias(&["FROM"])?;
        if item.column.is_none() && item.alias.is_some() {
            return Err(());
        }
        items.push(item);
        cursor.skip_space();
        if cursor.peek() == Some(',') {
            cursor.position += 1;
            continue;
        }
        break;
    }
    Ok(items)
}

fn parse_table_ref(cursor: &mut SqlCursor) -> Result<SqlTableRef, ()> {
    let table = cursor.ident()?;
    if table.is_empty() {
        return Err(());
    }
    let alias =
        cursor.parse_optional_alias(&["INNER", "LEFT", "OUTER", "JOIN", "ON", "WHERE", "ORDER"])?;
    Ok(SqlTableRef { table, alias })
}

fn parse_from(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlFrom, ()> {
    let base = parse_table_ref(cursor)?;
    let mut joins = Vec::new();
    loop {
        let kind = if cursor.consume_word("INNER") {
            cursor.expect_word("JOIN")?;
            SqlJoinKind::Inner
        } else if cursor.consume_word("LEFT") {
            cursor.consume_word("OUTER");
            cursor.expect_word("JOIN")?;
            SqlJoinKind::LeftOuter
        } else if cursor.consume_word("JOIN") {
            SqlJoinKind::Inner
        } else {
            break;
        };
        let table = parse_table_ref(cursor)?;
        cursor.expect_word("ON")?;
        let on = parse_expression(cursor, parameters)?;
        joins.push(SqlJoin { kind, table, on });
    }
    Ok(SqlFrom { base, joins })
}

fn parse_order_list(cursor: &mut SqlCursor) -> Result<Vec<SqlOrderKey>, ()> {
    let mut keys = Vec::new();
    loop {
        let (table, name) = cursor.name_ref()?;
        let direction = if cursor.consume_word("DESC") {
            SqlDirection::Descending
        } else {
            cursor.consume_word("ASC");
            SqlDirection::Ascending
        };
        keys.push(SqlOrderKey {
            table,
            name,
            direction,
        });
        cursor.skip_space();
        if cursor.peek() == Some(',') {
            cursor.position += 1;
            continue;
        }
        break;
    }
    Ok(keys)
}

fn parse_expression(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    parse_or(cursor, parameters)
}

fn parse_or(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    let mut left = parse_and(cursor, parameters)?;
    while cursor.consume_word("OR") {
        let right = parse_and(cursor, parameters)?;
        left = SqlExpr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    let mut left = parse_primary(cursor, parameters)?;
    while cursor.consume_word("AND") {
        let right = parse_primary(cursor, parameters)?;
        left = SqlExpr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_primary(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    cursor.skip_space();
    if cursor.peek() == Some('(') {
        cursor.position += 1;
        let expression = parse_or(cursor, parameters)?;
        cursor.skip_space();
        if cursor.bump() != Some(')') {
            return Err(());
        }
        return Ok(expression);
    }
    parse_comparison(cursor, parameters)
}

fn parse_comparison(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    let left = parse_operand(cursor, parameters)?;
    cursor.skip_space();
    if cursor.consume_word("IS") {
        let negated = cursor.consume_word("NOT");
        cursor.expect_word("NULL")?;
        return Ok(SqlExpr::IsNull {
            value: Box::new(left),
            negated,
        });
    }
    let op = match cursor.peek() {
        Some('=') => {
            cursor.position += 1;
            if cursor.peek() == Some('=') {
                cursor.position += 1;
            }
            SqlCompareOp::Eq
        }
        Some('!') => {
            cursor.position += 1;
            if cursor.bump() != Some('=') {
                return Err(());
            }
            SqlCompareOp::Ne
        }
        Some('<') => {
            cursor.position += 1;
            match cursor.peek() {
                Some('=') => {
                    cursor.position += 1;
                    SqlCompareOp::Le
                }
                Some('>') => {
                    cursor.position += 1;
                    SqlCompareOp::Ne
                }
                _ => SqlCompareOp::Lt,
            }
        }
        Some('>') => {
            cursor.position += 1;
            if cursor.peek() == Some('=') {
                cursor.position += 1;
                SqlCompareOp::Ge
            } else {
                SqlCompareOp::Gt
            }
        }
        _ => return Err(()),
    };
    let right = parse_operand(cursor, parameters)?;
    Ok(SqlExpr::Compare {
        left: Box::new(left),
        op,
        right: Box::new(right),
    })
}

fn parse_operand(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    cursor.skip_space();
    match cursor.peek() {
        Some('?') => {
            cursor.position += 1;
            let index = *parameters;
            *parameters += 1;
            Ok(SqlExpr::Parameter(index))
        }
        Some('\'') | Some('"') => Ok(SqlExpr::Literal(cursor.literal()?)),
        Some(ch)
            if ch.is_ascii_digit()
                || (ch == '-'
                    && cursor
                        .chars
                        .get(cursor.position + 1)
                        .is_some_and(|next| next.is_ascii_digit()))
                || (ch == '+'
                    && cursor
                        .chars
                        .get(cursor.position + 1)
                        .is_some_and(|next| next.is_ascii_digit())) =>
        {
            Ok(SqlExpr::Literal(cursor.literal()?))
        }
        _ => {
            let (table, name) = cursor.name_ref()?;
            Ok(SqlExpr::Column { table, name })
        }
    }
}

fn resolve_query(database: &MsiDatabaseState, parsed: MsiQuery) -> Result<ResolvedQuery, u32> {
    let mut references: Vec<&SqlTableRef> = Vec::with_capacity(1 + parsed.from.joins.len());
    references.push(&parsed.from.base);
    for join in &parsed.from.joins {
        references.push(&join.table);
    }
    let mut tables: Vec<ResolvedTable> = Vec::with_capacity(references.len());
    for reference in references {
        if database.table(&reference.table).is_none() {
            // Kept as ERROR_INVALID_TABLE for compatibility with the original
            // view surface; unknown qualifiers/aliases use ERROR_UNKNOWN_TABLE.
            return Err(ERROR_INVALID_TABLE);
        }
        // A self-join is legal with distinct aliases; only colliding
        // qualifiers (and an unaliased repeat of the same table) are errors.
        let reference_label = reference
            .alias
            .as_deref()
            .unwrap_or(reference.table.as_str());
        let duplicate = tables.iter().any(|table: &ResolvedTable| {
            table.name.eq_ignore_ascii_case(reference_label)
                || table
                    .alias
                    .as_deref()
                    .is_some_and(|alias| alias.eq_ignore_ascii_case(reference_label))
                || (table.alias.is_none() && table.name.eq_ignore_ascii_case(&reference.table))
        });
        if duplicate {
            return Err(ERROR_BAD_QUERY_SYNTAX);
        }
        tables.push(ResolvedTable {
            name: reference.table.clone(),
            alias: reference.alias.clone(),
        });
    }

    let mut columns = Vec::new();
    for item in &parsed.columns {
        match &item.column {
            None => {
                let table_indices = match &item.table {
                    Some(qualifier) => vec![resolve_table_index(qualifier, &tables)?],
                    None => (0..tables.len()).collect(),
                };
                for table_index in table_indices {
                    let table = database
                        .table(&tables[table_index].name)
                        .ok_or(ERROR_INVALID_TABLE)?;
                    for (column_index, column) in table.columns.iter().enumerate() {
                        columns.push(ResolvedColumn {
                            table: table_index,
                            column: column_index,
                            label: column.name.clone(),
                            type_name: column.type_name(),
                        });
                    }
                }
            }
            Some(name) => {
                let (table_index, column_index) = resolve_column(
                    database,
                    &tables,
                    item.table.as_deref(),
                    name,
                    tables.len(),
                    ColumnScope::Select,
                )?;
                let table = database
                    .table(&tables[table_index].name)
                    .ok_or(ERROR_INVALID_TABLE)?;
                let column = table.columns.get(column_index).ok_or(ERROR_BAD_COLUMN)?;
                columns.push(ResolvedColumn {
                    table: table_index,
                    column: column_index,
                    label: item.alias.clone().unwrap_or_else(|| column.name.clone()),
                    type_name: column.type_name(),
                });
            }
        }
    }
    if columns.is_empty() {
        return Err(ERROR_BAD_QUERY_SYNTAX);
    }

    let mut expectations = vec![ParameterExpectation::Any; parsed.parameter_count];
    let mut joins = Vec::new();
    for (index, join) in parsed.from.joins.iter().enumerate() {
        let table_index = index + 1;
        let on = resolve_expr(
            database,
            &tables,
            &join.on,
            table_index + 1,
            &mut expectations,
        )?;
        joins.push(ResolvedJoin {
            table: table_index,
            kind: join.kind,
            on,
        });
    }
    let filter = match &parsed.filter {
        Some(expression) => Some(resolve_expr(
            database,
            &tables,
            expression,
            tables.len(),
            &mut expectations,
        )?),
        None => None,
    };
    let mut order = Vec::new();
    for parsed_key in &parsed.order {
        let direction = parsed_key.direction;
        let output = if parsed_key.table.is_none() {
            let matches: Vec<usize> = columns
                .iter()
                .enumerate()
                .filter(|(_, column)| column.label.eq_ignore_ascii_case(&parsed_key.name))
                .map(|(index, _)| index)
                .collect();
            match matches.len() {
                1 => Some(matches[0]),
                0 => None,
                _ => return Err(ERROR_BAD_COLUMN),
            }
        } else {
            None
        };
        let key = match output {
            Some(index) => OrderSource::Output(index),
            None => {
                let (table, column) = resolve_column(
                    database,
                    &tables,
                    parsed_key.table.as_deref(),
                    &parsed_key.name,
                    tables.len(),
                    ColumnScope::Expression,
                )?;
                OrderSource::Column { table, column }
            }
        };
        order.push(ResolvedOrder { key, direction });
    }

    Ok(ResolvedQuery {
        distinct: parsed.distinct,
        tables,
        columns,
        joins,
        filter,
        order,
        parameter_expectations: expectations,
    })
}

#[derive(Debug, Clone, Copy)]
enum ColumnScope {
    Select,
    Expression,
}

fn resolve_table_index(qualifier: &str, tables: &[ResolvedTable]) -> Result<usize, u32> {
    let mut matches = tables.iter().enumerate().filter(|(_, table)| {
        table.name.eq_ignore_ascii_case(qualifier)
            || table
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(qualifier))
    });
    let Some((index, _)) = matches.next() else {
        return Err(ERROR_UNKNOWN_TABLE);
    };
    if matches.next().is_some() {
        return Err(ERROR_BAD_QUERY_SYNTAX);
    }
    Ok(index)
}

fn resolve_column(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    qualifier: Option<&str>,
    name: &str,
    limit: usize,
    scope: ColumnScope,
) -> Result<(usize, usize), u32> {
    if let Some(qualifier) = qualifier {
        let table_index = resolve_table_index(qualifier, tables)?;
        if table_index >= limit {
            return Err(ERROR_UNKNOWN_TABLE);
        }
        let table = database
            .table(&tables[table_index].name)
            .ok_or(ERROR_INVALID_TABLE)?;
        let column_index = table
            .columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
            .ok_or(ERROR_BAD_COLUMN)?;
        return Ok((table_index, column_index));
    }
    let mut found = None;
    for table_index in 0..limit.min(tables.len()) {
        let table = database
            .table(&tables[table_index].name)
            .ok_or(ERROR_INVALID_TABLE)?;
        for (column_index, column) in table.columns.iter().enumerate() {
            if !column.name.eq_ignore_ascii_case(name) {
                continue;
            }
            if found.is_some() {
                return Err(ERROR_BAD_COLUMN);
            }
            found = Some((table_index, column_index));
        }
    }
    found.ok_or(match scope {
        // MSI's original view parser reported an unknown select-list name as
        // a malformed query; expression/ORDER BY names are bad columns.
        ColumnScope::Select => ERROR_BAD_QUERY_SYNTAX,
        ColumnScope::Expression => ERROR_BAD_COLUMN,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlColumnKind {
    Binary,
    String { width: u16 },
    Int,
}

fn column_kind(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    table: usize,
    column: usize,
) -> Result<SqlColumnKind, u32> {
    let meta = tables.get(table).ok_or(ERROR_BAD_QUERY_SYNTAX)?;
    let table = database.table(&meta.name).ok_or(ERROR_INVALID_TABLE)?;
    let column = table.columns.get(column).ok_or(ERROR_BAD_COLUMN)?;
    if column.is_binary() {
        Ok(SqlColumnKind::Binary)
    } else if column.is_string() {
        Ok(SqlColumnKind::String {
            width: column.width(),
        })
    } else {
        Ok(SqlColumnKind::Int)
    }
}

fn resolved_column_kind(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    expression: &ResolvedExpr,
) -> Result<Option<SqlColumnKind>, u32> {
    match expression {
        ResolvedExpr::Column { table, column } => {
            Ok(Some(column_kind(database, tables, *table, *column)?))
        }
        _ => Ok(None),
    }
}

fn coerce_operand(
    operand: &mut ResolvedExpr,
    kind: SqlColumnKind,
    expectations: &mut [ParameterExpectation],
) -> Result<(), u32> {
    match operand {
        ResolvedExpr::Literal(value) => match kind {
            SqlColumnKind::String { .. } => {
                if let MsiValue::Int(number) = value {
                    *value = MsiValue::Str(number.to_string());
                }
                Ok(())
            }
            SqlColumnKind::Int => match value {
                MsiValue::Int(_) => Ok(()),
                MsiValue::Str(text) => match text.trim().parse::<i32>() {
                    Ok(number) => {
                        *value = MsiValue::Int(number);
                        Ok(())
                    }
                    Err(_) => Err(ERROR_BAD_QUERY_SYNTAX),
                },
                _ => Err(ERROR_BAD_QUERY_SYNTAX),
            },
            SqlColumnKind::Binary => Err(ERROR_BAD_QUERY_SYNTAX),
        },
        ResolvedExpr::Parameter(index) => {
            let expectation = match kind {
                SqlColumnKind::String { width } => ParameterExpectation::String { width },
                SqlColumnKind::Int => ParameterExpectation::Int,
                SqlColumnKind::Binary => return Err(ERROR_BAD_QUERY_SYNTAX),
            };
            if let Some(slot) = expectations.get_mut(*index) {
                *slot = expectation;
            }
            Ok(())
        }
        _ => Err(ERROR_BAD_QUERY_SYNTAX),
    }
}

fn resolve_expr(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    expression: &SqlExpr,
    limit: usize,
    expectations: &mut [ParameterExpectation],
) -> Result<ResolvedExpr, u32> {
    match expression {
        SqlExpr::Column { table, name } => {
            let (table, column) = resolve_column(
                database,
                tables,
                table.as_deref(),
                name,
                limit,
                ColumnScope::Expression,
            )?;
            Ok(ResolvedExpr::Column { table, column })
        }
        SqlExpr::Literal(value) => Ok(ResolvedExpr::Literal(value.clone())),
        SqlExpr::Parameter(index) => {
            if *index >= expectations.len() {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
            Ok(ResolvedExpr::Parameter(*index))
        }
        SqlExpr::IsNull { value, negated } => {
            let value = resolve_expr(database, tables, value, limit, expectations)?;
            if !matches!(value, ResolvedExpr::Column { .. }) {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
            Ok(ResolvedExpr::IsNull {
                value: Box::new(value),
                negated: *negated,
            })
        }
        SqlExpr::Compare { left, op, right } => {
            let mut left = resolve_expr(database, tables, left, limit, expectations)?;
            let mut right = resolve_expr(database, tables, right, limit, expectations)?;
            let left_kind = resolved_column_kind(database, tables, &left)?;
            let right_kind = resolved_column_kind(database, tables, &right)?;
            match (left_kind, right_kind) {
                (Some(SqlColumnKind::Binary), _) | (_, Some(SqlColumnKind::Binary)) => {
                    return Err(ERROR_BAD_QUERY_SYNTAX);
                }
                (Some(left_kind), Some(right_kind)) => {
                    let compatible = matches!(
                        (left_kind, right_kind),
                        (SqlColumnKind::Int, SqlColumnKind::Int)
                            | (SqlColumnKind::String { .. }, SqlColumnKind::String { .. })
                    );
                    if !compatible {
                        return Err(ERROR_BAD_QUERY_SYNTAX);
                    }
                }
                (Some(kind), None) => coerce_operand(&mut right, kind, expectations)?,
                (None, Some(kind)) => coerce_operand(&mut left, kind, expectations)?,
                (None, None) => return Err(ERROR_BAD_QUERY_SYNTAX),
            }
            Ok(ResolvedExpr::Compare {
                left: Box::new(left),
                op: *op,
                right: Box::new(right),
            })
        }
        SqlExpr::And(left, right) => Ok(ResolvedExpr::And(
            Box::new(resolve_expr(database, tables, left, limit, expectations)?),
            Box::new(resolve_expr(database, tables, right, limit, expectations)?),
        )),
        SqlExpr::Or(left, right) => Ok(ResolvedExpr::Or(
            Box::new(resolve_expr(database, tables, left, limit, expectations)?),
            Box::new(resolve_expr(database, tables, right, limit, expectations)?),
        )),
    }
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
        let raw = u16::from_le_bytes([cell[0], cell[1]]);
        // A nullable integer cell of zero is MSI's NULL sentinel; the sign
        // bit is otherwise inverted around 0x8000 for stored integers.
        if column.is_nullable() && raw == 0 {
            return MsiValue::Null;
        }
        return MsiValue::Int(i32::from(raw) - 0x8000);
    }
    let raw = u32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]);
    if column.is_nullable() && raw == 0 {
        return MsiValue::Null;
    }
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
pub(crate) fn write_compound_file(streams: &[(String, Vec<u8>)]) -> Vec<u8> {
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

    const S32: u16 = MSITYPE_VALID | MSITYPE_STRING | 32;
    const S64: u16 = MSITYPE_VALID | MSITYPE_STRING | 64;
    const S255: u16 = MSITYPE_VALID | MSITYPE_STRING | 255;
    const S32_KEY: u16 = S32 | MSITYPE_KEY;
    const S32_NULL: u16 = S32 | MSITYPE_NULLABLE;
    const S64_NULL: u16 = S64 | MSITYPE_NULLABLE;
    const S255_NULL: u16 = S255 | MSITYPE_NULLABLE;
    const I2: u16 = MSITYPE_VALID | 2;
    const I2_NULL: u16 = I2 | MSITYPE_NULLABLE;
    const I2_KEY: u16 = I2 | MSITYPE_KEY;
    const I4_NULL: u16 = MSITYPE_VALID | 4 | MSITYPE_NULLABLE;

    const OK: u64 = ERROR_SUCCESS as u64;
    const INVALID_PARAMETER: u64 = ERROR_INVALID_PARAMETER as u64;
    const INVALID_DATATYPE: u64 = ERROR_INVALID_DATATYPE as u64;
    const INVALID_DATA: u64 = ERROR_INVALID_DATA as u64;
    const NO_MORE_ITEMS: u64 = ERROR_NO_MORE_ITEMS as u64;
    const FUNCTION_FAILED: u64 = ERROR_FUNCTION_FAILED as u64;

    fn column(name: &str, type_bits: u16) -> MsiColumn {
        MsiColumn {
            name: name.to_string(),
            type_bits,
        }
    }

    /// Three related tables plus a real `_Validation` table:
    /// Product 1..N Feature 1..N Component, with a dangling feature/product
    /// row and nullable Weight/Title columns for outer joins and NULL ordering.
    /// Product P3 and Feature 4 exercise null extension and Feature.Title is
    /// the string NULL used by IS NULL / ORDER BY tests (integer NULL cells in
    /// MSI streams use the i32::MIN sentinel).
    fn relational_compound() -> Vec<u8> {
        let mut database = MsiDatabaseState::empty(String::new());
        database.tables.insert(
            "Product".to_string(),
            MsiTable {
                name: "Product".to_string(),
                columns: vec![
                    column("ProductCode", S32_KEY),
                    column("Name", S64),
                    column("Price", I2_NULL),
                ],
                rows: vec![
                    vec![
                        MsiValue::Str("P1".to_string()),
                        MsiValue::Str("Alpha".to_string()),
                        MsiValue::Int(10),
                    ],
                    vec![
                        MsiValue::Str("P2".to_string()),
                        MsiValue::Str("Beta".to_string()),
                        MsiValue::Int(20),
                    ],
                    vec![
                        MsiValue::Str("P3".to_string()),
                        MsiValue::Str("Gamma".to_string()),
                        MsiValue::Int(5),
                    ],
                ],
            },
        );
        database.tables.insert(
            "Feature".to_string(),
            MsiTable {
                name: "Feature".to_string(),
                columns: vec![
                    column("FeatureId", I2_KEY),
                    column("ProductCode", S32),
                    column("Title", S64_NULL),
                    column("Weight", I2_NULL),
                ],
                rows: vec![
                    vec![
                        MsiValue::Int(1),
                        MsiValue::Str("P1".to_string()),
                        MsiValue::Str("Fast".to_string()),
                        MsiValue::Int(5),
                    ],
                    vec![
                        MsiValue::Int(2),
                        MsiValue::Str("P1".to_string()),
                        MsiValue::Str("Slow".to_string()),
                        MsiValue::Int(10),
                    ],
                    vec![
                        MsiValue::Int(3),
                        MsiValue::Str("P2".to_string()),
                        MsiValue::Str("Only".to_string()),
                        MsiValue::Int(1),
                    ],
                    vec![
                        MsiValue::Int(4),
                        MsiValue::Str("P9".to_string()),
                        MsiValue::Null,
                        MsiValue::Null,
                    ],
                    vec![
                        MsiValue::Int(5),
                        MsiValue::Str("P2".to_string()),
                        MsiValue::Str("Fast".to_string()),
                        MsiValue::Int(1),
                    ],
                ],
            },
        );
        database.tables.insert(
            "Component".to_string(),
            MsiTable {
                name: "Component".to_string(),
                columns: vec![
                    column("ComponentId", S32_KEY),
                    column("FeatureId", I2),
                    column("Label", S64_NULL),
                ],
                rows: vec![
                    vec![
                        MsiValue::Str("C1".to_string()),
                        MsiValue::Int(1),
                        MsiValue::Str("first".to_string()),
                    ],
                    vec![
                        MsiValue::Str("C2".to_string()),
                        MsiValue::Int(1),
                        MsiValue::Str("second".to_string()),
                    ],
                    vec![
                        MsiValue::Str("C3".to_string()),
                        MsiValue::Int(2),
                        MsiValue::Str("third".to_string()),
                    ],
                    vec![
                        MsiValue::Str("C4".to_string()),
                        MsiValue::Int(99),
                        MsiValue::Str("orphan".to_string()),
                    ],
                ],
            },
        );
        database.tables.insert(
            "_Validation".to_string(),
            MsiTable {
                name: "_Validation".to_string(),
                columns: vec![
                    column("Table", S64),
                    column("Column", S64),
                    column("Nullable", I2_NULL),
                    column("MinValue", I4_NULL),
                    column("MaxValue", I4_NULL),
                    column("KeyTable", S64_NULL),
                    column("KeyColumn", S64_NULL),
                    column("Category", S32_NULL),
                    column("Set", S255_NULL),
                    column("Description", S255_NULL),
                ],
                rows: vec![
                    vec![
                        MsiValue::Str("Feature".to_string()),
                        MsiValue::Str("Weight".to_string()),
                        MsiValue::Int(1),
                        MsiValue::Int(1),
                        MsiValue::Int(100),
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Null,
                    ],
                    vec![
                        MsiValue::Str("Product".to_string()),
                        MsiValue::Str("Price".to_string()),
                        MsiValue::Int(1),
                        MsiValue::Int(0),
                        MsiValue::Int(1000),
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Null,
                    ],
                    vec![
                        MsiValue::Str("Component".to_string()),
                        MsiValue::Str("FeatureId".to_string()),
                        MsiValue::Int(0),
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Str("Feature".to_string()),
                        MsiValue::Str("FeatureId".to_string()),
                        MsiValue::Null,
                        MsiValue::Null,
                        MsiValue::Null,
                    ],
                ],
            },
        );
        serialize_database(&database).expect("serialize relational fixture")
    }

    fn collect_rows(fixture: &mut Fixture, view: u64, fields: u32) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        loop {
            let (result, record) = fetch(fixture, view);
            if result == NO_MORE_ITEMS {
                break;
            }
            assert_eq!(result, OK, "fetch failed");
            let mut values = Vec::new();
            for field in 1..=fields {
                values.push(record_string(fixture, record, field).1);
            }
            rows.push(values);
        }
        rows
    }

    fn open_view_error(fixture: &mut Fixture, db: u64, sql: &str) -> u64 {
        write_wide(&mut fixture.memory, QUERY_PTR, sql);
        dispatch_x86(
            fixture,
            HostThunk::MsiDatabaseOpenViewW,
            &[db as u32, QUERY_PTR as u32, OUT_PTR as u32],
        )
    }

    fn new_record(fixture: &mut Fixture, fields: u32) -> u64 {
        dispatch_x86(fixture, HostThunk::MsiCreateRecord, &[fields]) as u32 as u64
    }

    fn set_record_int(fixture: &mut Fixture, record: u64, field: u32, value: i32) {
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::MsiRecordSetInteger,
                &[record as u32, field, value as u32]
            ),
            OK
        );
    }

    fn set_record_text(fixture: &mut Fixture, record: u64, field: u32, value: &str) {
        write_wide(&mut fixture.memory, STRING_PTR, value);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::MsiRecordSetStringW,
                &[record as u32, field, STRING_PTR as u32]
            ),
            OK
        );
    }

    fn modify(fixture: &mut Fixture, view: u64, mode: u32, record: u64) -> u64 {
        dispatch_x86(
            fixture,
            HostThunk::MsiViewModify,
            &[view as u32, mode, record as u32],
        )
    }

    #[test]
    fn msi_sql_joins_left_outer_null_extension_and_order() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-join");
            let (db, _path) = open_fixture(&mut fixture, "join.msi", &relational_compound());

            let view = open_view(
                &mut fixture,
                db,
                "SELECT p.Name, f.Title FROM Product p INNER JOIN Feature f \
                 ON p.ProductCode = f.ProductCode ORDER BY p.Name ASC, f.FeatureId ASC",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 2),
                vec![
                    vec!["Alpha".to_string(), "Fast".to_string()],
                    vec!["Alpha".to_string(), "Slow".to_string()],
                    vec!["Beta".to_string(), "Only".to_string()],
                    vec!["Beta".to_string(), "Fast".to_string()],
                ]
            );

            // Two outer joins: Gamma has no Feature and Beta's features have
            // no Component, so both projections must carry NULL extension.
            let view = open_view(
                &mut fixture,
                db,
                "SELECT p.Name, f.Title, c.Label FROM Product AS p \
                 LEFT OUTER JOIN Feature AS f ON p.ProductCode = f.ProductCode \
                 LEFT JOIN Component c ON f.FeatureId = c.FeatureId \
                 ORDER BY p.Name, f.FeatureId, c.ComponentId",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 3),
                vec![
                    vec!["Alpha".to_string(), "Fast".to_string(), "first".to_string()],
                    vec![
                        "Alpha".to_string(),
                        "Fast".to_string(),
                        "second".to_string()
                    ],
                    vec!["Alpha".to_string(), "Slow".to_string(), "third".to_string()],
                    vec!["Beta".to_string(), "Only".to_string(), String::new()],
                    vec!["Beta".to_string(), "Fast".to_string(), String::new()],
                    vec!["Gamma".to_string(), String::new(), String::new()],
                ]
            );

            // INNER JOIN drops the unmatched Product row entirely.
            let inner = open_view(
                &mut fixture,
                db,
                "SELECT p.Name FROM Product p INNER JOIN Feature f \
                 ON f.ProductCode = p.ProductCode",
            );
            assert_eq!(execute(&mut fixture, inner), OK);
            assert_eq!(
                collect_rows(&mut fixture, inner, 1),
                vec![
                    vec!["Alpha".to_string()],
                    vec!["Alpha".to_string()],
                    vec!["Beta".to_string()],
                    vec!["Beta".to_string()],
                ]
            );
        });
    }

    #[test]
    fn msi_sql_where_groups_is_null_distinct_and_order_keys() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-where");
            let (db, _path) = open_fixture(&mut fixture, "where.msi", &relational_compound());

            let view = open_view(
                &mut fixture,
                db,
                "SELECT DISTINCT p.ProductCode FROM Product p INNER JOIN Feature f \
                 ON p.ProductCode = f.ProductCode ORDER BY p.ProductCode DESC",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![vec!["P2".to_string()], vec!["P1".to_string()]]
            );

            for (sql, expected) in [
                (
                    "SELECT FeatureId FROM Feature WHERE (Weight >= 5 AND Weight <= 10) OR Title IS NULL ORDER BY FeatureId",
                    vec![
                        vec!["1".to_string()],
                        vec!["2".to_string()],
                        vec!["4".to_string()],
                    ],
                ),
                (
                    "SELECT FeatureId FROM Feature WHERE Title IS NOT NULL ORDER BY FeatureId",
                    vec![
                        vec!["1".to_string()],
                        vec!["2".to_string()],
                        vec!["3".to_string()],
                        vec!["5".to_string()],
                    ],
                ),
                (
                    "SELECT Name FROM Product WHERE Price <> 10 ORDER BY Name",
                    vec![vec!["Beta".to_string()], vec!["Gamma".to_string()]],
                ),
                (
                    "SELECT Name FROM Product WHERE Price != 10 ORDER BY Name",
                    vec![vec!["Beta".to_string()], vec!["Gamma".to_string()]],
                ),
                (
                    "SELECT Name FROM Product WHERE Price < 20 ORDER BY Name",
                    vec![vec!["Alpha".to_string()], vec!["Gamma".to_string()]],
                ),
                (
                    "SELECT Name FROM Product WHERE Price <= 10 ORDER BY Name",
                    vec![vec!["Alpha".to_string()], vec!["Gamma".to_string()]],
                ),
                (
                    "SELECT Name FROM Product WHERE Price > 10 ORDER BY Name",
                    vec![vec!["Beta".to_string()]],
                ),
                (
                    "SELECT Name FROM Product WHERE Price >= 20 ORDER BY Name",
                    vec![vec!["Beta".to_string()]],
                ),
            ] {
                let view = open_view(&mut fixture, db, sql);
                assert_eq!(execute(&mut fixture, view), OK, "{sql}");
                assert_eq!(collect_rows(&mut fixture, view, 1), expected, "{sql}");
            }

            // Integer NULL columns use the same msivalue::Null sentinel.
            let view = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Weight IS NULL",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![vec!["4".to_string()]]
            );
            let view = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature ORDER BY Weight ASC, FeatureId DESC",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![
                    vec!["4".to_string()],
                    vec!["5".to_string()],
                    vec!["3".to_string()],
                    vec!["1".to_string()],
                    vec!["2".to_string()],
                ]
            );

            // NULL sorts first ascending and last descending (MSI/SQL Server).
            let view = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature ORDER BY Title ASC, FeatureId DESC",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![
                    vec!["4".to_string()],
                    vec!["5".to_string()],
                    vec!["1".to_string()],
                    vec!["3".to_string()],
                    vec!["2".to_string()],
                ]
            );
            let view = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature ORDER BY Title DESC, FeatureId ASC",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![
                    vec!["2".to_string()],
                    vec!["3".to_string()],
                    vec!["1".to_string()],
                    vec!["5".to_string()],
                    vec!["4".to_string()],
                ]
            );
        });
    }

    #[test]
    fn msi_sql_aliases_resolve_columns_and_labels() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-alias");
            let (db, _path) = open_fixture(&mut fixture, "alias.msi", &relational_compound());

            let view = open_view(
                &mut fixture,
                db,
                "SELECT p.Name AS Item, f.Title AS Part FROM Product AS p \
                 INNER JOIN Feature f ON p.ProductCode = f.ProductCode \
                 WHERE p.Price = 10 ORDER BY Item, Part DESC",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 2),
                vec![
                    vec!["Alpha".to_string(), "Slow".to_string()],
                    vec!["Alpha".to_string(), "Fast".to_string()],
                ]
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewGetColumnInfo,
                    &[view as u32, 0, OUT_PTR as u32]
                ),
                OK
            );
            let names = guest_pointer(&fixture.memory, OUT_PTR);
            assert_eq!(
                record_string(&mut fixture, names, 1),
                (0, "Item".to_string())
            );
            assert_eq!(
                record_string(&mut fixture, names, 2),
                (0, "Part".to_string())
            );

            // A table alias does not hide the real table name as a qualifier.
            let view = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product p WHERE Product.Price = 20",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![vec!["Beta".to_string()]]
            );

            // Unqualified names resolve when exactly one FROM table has them.
            let view = open_view(
                &mut fixture,
                db,
                "SELECT Title FROM Product p INNER JOIN Feature f \
                 ON p.ProductCode = f.ProductCode WHERE Title = 'Only'",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![vec!["Only".to_string()]]
            );

            // A self-join is legal when both instances have distinct aliases.
            let view = open_view(
                &mut fixture,
                db,
                "SELECT a.Name, b.Name FROM Product a INNER JOIN Product b \
                 ON a.ProductCode = b.ProductCode WHERE b.Price = 20",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 2),
                vec![vec!["Beta".to_string(), "Beta".to_string()]]
            );
        });
    }

    #[test]
    fn msi_sql_parameterized_execute_validates_type_and_size() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-params");
            let (db, _path) = open_fixture(&mut fixture, "params.msi", &relational_compound());

            let view = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE Price > ? ORDER BY Name",
            );
            assert_ne!(view, 0);
            assert_eq!(execute(&mut fixture, view), INVALID_PARAMETER);

            let record = new_record(&mut fixture, 1);
            set_record_int(&mut fixture, record, 1, 15);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewExecute,
                    &[view as u32, record as u32]
                ),
                OK
            );
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![vec!["Beta".to_string()]]
            );

            let bad = new_record(&mut fixture, 1);
            set_record_text(&mut fixture, bad, 1, "not-an-integer");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewExecute,
                    &[view as u32, bad as u32]
                ),
                INVALID_DATATYPE
            );
            let extra = new_record(&mut fixture, 2);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewExecute,
                    &[view as u32, extra as u32]
                ),
                INVALID_PARAMETER
            );

            let left = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE ? < Price ORDER BY Name",
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewExecute,
                    &[left as u32, record as u32]
                ),
                OK
            );
            assert_eq!(
                collect_rows(&mut fixture, left, 1),
                vec![vec!["Beta".to_string()]]
            );

            let two = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE Price >= ? AND Price <= ? ORDER BY Name",
            );
            let bounds = new_record(&mut fixture, 2);
            set_record_int(&mut fixture, bounds, 1, 10);
            set_record_int(&mut fixture, bounds, 2, 20);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewExecute,
                    &[two as u32, bounds as u32]
                ),
                OK
            );
            assert_eq!(
                collect_rows(&mut fixture, two, 1),
                vec![vec!["Alpha".to_string()], vec!["Beta".to_string()]]
            );

            let code = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE ProductCode = ?",
            );
            let long = "p".repeat(33);
            let oversized = new_record(&mut fixture, 1);
            set_record_text(&mut fixture, oversized, 1, &long);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewExecute,
                    &[code as u32, oversized as u32]
                ),
                INVALID_DATATYPE
            );
            let key = new_record(&mut fixture, 1);
            set_record_text(&mut fixture, key, 1, "P1");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MsiViewExecute,
                    &[code as u32, key as u32]
                ),
                OK
            );
            assert_eq!(
                collect_rows(&mut fixture, code, 1),
                vec![vec!["Alpha".to_string()]]
            );

            // A '?' inside a quoted literal is data, not a parameter.
            let literal = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE Name = '?'",
            );
            assert_ne!(literal, 0);
            assert_eq!(execute(&mut fixture, literal), OK);
            assert!(collect_rows(&mut fixture, literal, 1).is_empty());

            // Constant/column type mismatch is rejected at open time.
            assert_eq!(
                open_view_error(
                    &mut fixture,
                    db,
                    "SELECT * FROM Product WHERE Price = 'abc'"
                ),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
        });
    }

    #[test]
    fn msi_view_seek_refresh_and_validation_table() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-modify-depth");
            let (db, _path) = open_fixture(&mut fixture, "depth.msi", &relational_compound());

            let view = open_view(
                &mut fixture,
                db,
                "SELECT * FROM Feature ORDER BY FeatureId ASC",
            );
            assert_eq!(execute(&mut fixture, view), OK);

            // SEEK by primary key (record fields 1..n in key order).
            let seek = new_record(&mut fixture, 1);
            set_record_int(&mut fixture, seek, 1, 2);
            assert_eq!(
                modify(&mut fixture, view, 7, seek),
                u64::from(ERROR_SUCCESS)
            );
            let (result, fetched) = fetch(&mut fixture, view);
            assert_eq!(result, OK);
            assert_eq!(record_integer(&mut fixture, fetched, 1), 2);
            assert_eq!(
                record_string(&mut fixture, fetched, 3),
                (0, "Slow".to_string())
            );

            // REFRESH re-reads the fetched row after an UPDATE elsewhere.
            let update = new_record(&mut fixture, 3);
            set_record_int(&mut fixture, update, 0, 2);
            set_record_text(&mut fixture, update, 3, "SlowRenamed");
            assert_eq!(
                modify(&mut fixture, view, 2, update),
                u64::from(ERROR_SUCCESS)
            );
            assert_eq!(
                modify(&mut fixture, view, 8, fetched),
                u64::from(ERROR_SUCCESS)
            );
            assert_eq!(
                record_string(&mut fixture, fetched, 3),
                (0, "SlowRenamed".to_string())
            );

            // VALIDATE: structural + _Validation rules.
            let valid = new_record(&mut fixture, 4);
            set_record_int(&mut fixture, valid, 1, 6);
            set_record_text(&mut fixture, valid, 2, "P1");
            set_record_text(&mut fixture, valid, 3, "Valid");
            set_record_int(&mut fixture, valid, 4, 50);
            assert_eq!(
                modify(&mut fixture, view, 10, valid),
                u64::from(ERROR_SUCCESS)
            );
            assert_eq!(
                modify(&mut fixture, view, 11, valid),
                u64::from(ERROR_SUCCESS)
            );

            let missing_key = new_record(&mut fixture, 4);
            set_record_text(&mut fixture, missing_key, 2, "P1");
            set_record_text(&mut fixture, missing_key, 3, "NoKey");
            set_record_int(&mut fixture, missing_key, 4, 1);
            assert_eq!(modify(&mut fixture, view, 10, missing_key), INVALID_DATA);

            let above_max = new_record(&mut fixture, 4);
            set_record_int(&mut fixture, above_max, 1, 7);
            set_record_text(&mut fixture, above_max, 2, "P1");
            set_record_text(&mut fixture, above_max, 3, "TooHeavy");
            set_record_int(&mut fixture, above_max, 4, 101);
            assert_eq!(modify(&mut fixture, view, 10, above_max), INVALID_DATA);

            let below_min = new_record(&mut fixture, 4);
            set_record_int(&mut fixture, below_min, 1, 7);
            set_record_text(&mut fixture, below_min, 2, "P1");
            set_record_text(&mut fixture, below_min, 3, "TooLight");
            set_record_int(&mut fixture, below_min, 4, 0);
            assert_eq!(modify(&mut fixture, view, 10, below_min), INVALID_DATA);

            let long_title = new_record(&mut fixture, 4);
            set_record_int(&mut fixture, long_title, 1, 8);
            set_record_text(&mut fixture, long_title, 2, "P1");
            set_record_text(&mut fixture, long_title, 3, &"t".repeat(65));
            set_record_int(&mut fixture, long_title, 4, 1);
            assert_eq!(modify(&mut fixture, view, 10, long_title), INVALID_DATA);

            // KeyTable/KeyColumn foreign key validation.
            let components = open_view(&mut fixture, db, "SELECT * FROM Component");
            let dangling = new_record(&mut fixture, 3);
            set_record_text(&mut fixture, dangling, 1, "C9");
            set_record_int(&mut fixture, dangling, 2, 99);
            set_record_text(&mut fixture, dangling, 3, "dangling");
            assert_eq!(modify(&mut fixture, components, 10, dangling), INVALID_DATA);
            let joined = new_record(&mut fixture, 3);
            set_record_text(&mut fixture, joined, 1, "C5");
            set_record_int(&mut fixture, joined, 2, 1);
            set_record_text(&mut fixture, joined, 3, "joined");
            assert_eq!(
                modify(&mut fixture, components, 10, joined),
                u64::from(ERROR_SUCCESS)
            );

            // REFRESH of a row deleted after the fetch reports no more items.
            let stale = new_record(&mut fixture, 1);
            set_record_int(&mut fixture, stale, 0, 5);
            let delete = new_record(&mut fixture, 1);
            set_record_int(&mut fixture, delete, 0, 5);
            assert_eq!(
                modify(&mut fixture, view, 6, delete),
                u64::from(ERROR_SUCCESS)
            );
            assert_eq!(modify(&mut fixture, view, 8, stale), FUNCTION_FAILED);
        });
    }

    #[test]
    fn msi_sql_error_matrix() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-errors");
            let (db, _path) = open_fixture(&mut fixture, "errors.msi", &relational_compound());

            for (sql, expected) in [
                ("SELECT * FROM MissingTable", ERROR_INVALID_TABLE),
                (
                    "SELECT * FROM Product p WHERE Missing.Price = 1",
                    ERROR_UNKNOWN_TABLE,
                ),
                ("SELECT * FROM Product WHERE Missing = 1", ERROR_BAD_COLUMN),
                (
                    "SELECT * FROM Product p INNER JOIN Feature f \
                     ON p.ProductCode = f.ProductCode WHERE ProductCode = 'P1'",
                    ERROR_BAD_COLUMN,
                ),
                ("SELECT * FROM Product ORDER BY Missing", ERROR_BAD_COLUMN),
                ("SELECT * FROM Product ORDER BY p.Name", ERROR_UNKNOWN_TABLE),
                ("SELECT Missing FROM Product", ERROR_BAD_QUERY_SYNTAX),
                ("SELECT p.Missing FROM Product p", ERROR_BAD_COLUMN),
                ("SELECT q.* FROM Product p", ERROR_UNKNOWN_TABLE),
                (
                    "SELECT * FROM Product p INNER JOIN Feature p \
                     ON p.ProductCode = p.ProductCode",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT * FROM Product p INNER JOIN Feature f \
                     ON p.ProductCode = f.FeatureId",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT * FROM Product WHERE Price =",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT * FROM Product WHERE (Price = 1",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                ("SELECT * FROM Product ORDER Name", ERROR_BAD_QUERY_SYNTAX),
                (
                    "SELECT * FROM Product LEFT JOIN Feature ON",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT * FROM Product WHERE Price IS 1",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                ("SELECT * FROM Product WHERE = 1", ERROR_BAD_QUERY_SYNTAX),
            ] {
                assert_eq!(
                    open_view_error(&mut fixture, db, sql),
                    u64::from(expected),
                    "{sql}"
                );
            }

            // A valid query still opens after the error matrix.
            let view = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title IS NULL",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 1),
                vec![vec!["4".to_string()]]
            );
        });
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
