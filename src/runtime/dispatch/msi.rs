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

/// One `SELECT` item.  A `None` column is `*`/`table.*`; `expression`
/// carries aggregates, literals, parameters and scalar subqueries.
#[derive(Debug, Clone)]
struct SqlSelectItem {
    table: Option<String>,
    column: Option<String>,
    alias: Option<String>,
    expression: Option<SqlExpr>,
}

/// A table reference in `FROM`, with an optional `AS`/bare alias.
#[derive(Debug, Clone)]
struct SqlTableRef {
    table: String,
    alias: Option<String>,
    derived: Option<Box<MsiQuery>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlJoinKind {
    Inner,
    LeftOuter,
    RightOuter,
    FullOuter,
    Cross,
}

#[derive(Debug, Clone)]
struct SqlJoin {
    kind: SqlJoinKind,
    table: SqlTableRef,
    on: Option<SqlExpr>,
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

/// The supported expression set: a column reference (optionally
/// `Table.Column` or `Alias.Column`), an integer/string literal, a positional
/// `?` parameter, `IS [NOT] NULL`, comparisons, `[NOT] LIKE ... [ESCAPE c]`,
/// `[NOT] BETWEEN`, `[NOT] IN (list|subquery)`, unary `NOT`, parentheses,
/// `AND`/`OR`, aggregates and scalar subqueries.
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
    Not(Box<SqlExpr>),
    Like {
        value: Box<SqlExpr>,
        pattern: Box<SqlExpr>,
        escape: Option<char>,
        negated: bool,
    },
    Between {
        value: Box<SqlExpr>,
        low: Box<SqlExpr>,
        high: Box<SqlExpr>,
        negated: bool,
    },
    InList {
        value: Box<SqlExpr>,
        items: Vec<SqlExpr>,
        negated: bool,
    },
    InQuery {
        value: Box<SqlExpr>,
        query: Box<MsiQuery>,
        negated: bool,
    },
    ScalarQuery(Box<MsiQuery>),
    Exists {
        query: Box<MsiQuery>,
        negated: bool,
    },
    Unary {
        op: SqlUnaryOp,
        value: Box<SqlExpr>,
    },
    Binary {
        op: SqlBinaryOp,
        left: Box<SqlExpr>,
        right: Box<SqlExpr>,
    },
    Function {
        function: SqlFunction,
        arguments: Vec<SqlExpr>,
    },
    Aggregate {
        function: SqlAggregate,
        argument: Option<Box<SqlExpr>>,
        distinct: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlUnaryOp {
    Negate,
    Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlBinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlFunction {
    Upper,
    Lower,
    Length,
    Substring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlAggregate {
    Count,
    Sum,
    Average,
    Min,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlDirection {
    Ascending,
    Descending,
}

#[derive(Debug, Clone)]
struct SqlOrderKey {
    expr: SqlExpr,
    direction: SqlDirection,
}

#[derive(Debug, Clone)]
struct SqlUnionPart {
    all: bool,
    query: Box<MsiQuery>,
}

/// A parsed SELECT statement before schema resolution.  MSI SQL surface:
/// `SELECT [DISTINCT] *|exprlist FROM table [alias]
///  [{INNER|LEFT|RIGHT|FULL [OUTER]|CROSS} JOIN table [alias] [ON expr]]...
///  [WHERE expr] [GROUP BY exprlist] [HAVING expr]
///  [UNION [ALL] SELECT ...]... [ORDER BY expr [ASC|DESC], ...]`.
#[derive(Debug, Clone)]
struct MsiQuery {
    distinct: bool,
    columns: Vec<SqlSelectItem>,
    from: SqlFrom,
    filter: Option<SqlExpr>,
    group_by: Vec<SqlExpr>,
    having: Option<SqlExpr>,
    order: Vec<SqlOrderKey>,
    unions: Vec<SqlUnionPart>,
    parameter_count: usize,
}

/// A table after FROM resolution (index 0 is the base table).
#[derive(Debug, Clone)]
struct ResolvedTable {
    name: String,
    alias: Option<String>,
    columns: Vec<MsiColumn>,
    derived: Option<Box<ResolvedQuery>>,
}

/// One projected output column and its label/type for `MsiViewGetColumnInfo`.
/// `expression` is set for aggregate/literal/parameter/subquery items; a
/// plain column keeps the direct (table, column) pair.
#[derive(Debug, Clone)]
struct ResolvedColumn {
    table: usize,
    column: usize,
    label: String,
    type_name: String,
    expression: Option<ResolvedExpr>,
}

#[derive(Debug, Clone)]
struct ResolvedJoin {
    table: usize,
    kind: SqlJoinKind,
    on: Option<ResolvedExpr>,
}

#[derive(Debug, Clone)]
enum OrderSource {
    Column { table: usize, column: usize },
    Output(usize),
    Expr(ResolvedExpr),
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
    Not(Box<ResolvedExpr>),
    Like {
        value: Box<ResolvedExpr>,
        pattern: Box<ResolvedExpr>,
        escape: Option<char>,
        negated: bool,
    },
    Between {
        value: Box<ResolvedExpr>,
        low: Box<ResolvedExpr>,
        high: Box<ResolvedExpr>,
        negated: bool,
    },
    InList {
        value: Box<ResolvedExpr>,
        items: Vec<ResolvedExpr>,
        negated: bool,
    },
    InQuery {
        value: Box<ResolvedExpr>,
        query: Box<ResolvedQuery>,
        negated: bool,
    },
    ScalarQuery(Box<ResolvedQuery>),
    OuterColumn {
        level: usize,
        table: usize,
        column: usize,
        kind: SqlColumnKind,
    },
    Exists {
        query: Box<ResolvedQuery>,
        negated: bool,
    },
    Unary {
        op: SqlUnaryOp,
        value: Box<ResolvedExpr>,
    },
    Binary {
        op: SqlBinaryOp,
        left: Box<ResolvedExpr>,
        right: Box<ResolvedExpr>,
    },
    Function {
        function: SqlFunction,
        arguments: Vec<ResolvedExpr>,
    },
    Aggregate {
        function: SqlAggregate,
        argument: Option<Box<ResolvedExpr>>,
        distinct: bool,
    },
}

#[derive(Debug, Clone)]
struct ResolvedUnion {
    all: bool,
    query: Box<ResolvedQuery>,
}

#[derive(Debug, Clone)]
struct ResolvedQuery {
    distinct: bool,
    tables: Vec<ResolvedTable>,
    columns: Vec<ResolvedColumn>,
    joins: Vec<ResolvedJoin>,
    filter: Option<ResolvedExpr>,
    group_by: Vec<ResolvedExpr>,
    having: Option<ResolvedExpr>,
    grouped: bool,
    order: Vec<ResolvedOrder>,
    unions: Vec<ResolvedUnion>,
    parameter_expectations: Vec<ParameterExpectation>,
}

/// A projected view row plus the source row index in each FROM table
/// (`None` for the null-extended side of an outer join).  `group` retains
/// the source rows of an aggregate group so ORDER BY aggregate expressions
/// can be evaluated after projection.
#[derive(Debug, Clone)]
struct ViewRow {
    values: Vec<MsiValue>,
    source: Vec<Option<usize>>,
    group: Option<Vec<Vec<Option<usize>>>>,
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

/// A directory entry in an OLE compound file.  The tree pointers and the
/// per-storage CLSID/timestamps are retained so nested storages can be
/// resolved by path and round-tripped through the writer.
#[derive(Debug, Clone)]
pub(crate) struct CompoundEntry {
    pub(crate) name: String,
    pub(crate) kind: u8,
    pub(crate) start: u32,
    pub(crate) size: u64,
    pub(crate) left: u32,
    pub(crate) right: u32,
    pub(crate) child: u32,
    pub(crate) clsid: [u8; 16],
    #[allow(dead_code)] // parsed/written for CFB timestamp round-trip coverage
    pub(crate) created: u64,
    #[allow(dead_code)] // parsed/written for CFB timestamp round-trip coverage
    pub(crate) modified: u64,
}

impl CompoundEntry {
    /// The element name with the MSI stream-name encoding removed.
    pub(crate) fn decoded_name(&self) -> String {
        decode_stream_name(&self.name)
            .trim_start_matches('\u{4840}')
            .to_string()
    }
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
            let left = le_u32(chunk, 0x44).unwrap_or(NOSTREAM);
            let right = le_u32(chunk, 0x48).unwrap_or(NOSTREAM);
            let child = le_u32(chunk, 0x4C).unwrap_or(NOSTREAM);
            let mut clsid = [0_u8; 16];
            if let Some(bytes) = chunk.get(0x50..0x60) {
                clsid.copy_from_slice(bytes);
            }
            let created = le_u64(chunk, 0x64).unwrap_or(0);
            let modified = le_u64(chunk, 0x6C).unwrap_or(0);
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
                left,
                right,
                child,
                clsid,
                created,
                modified,
            });
        }
        Self::validate_directory(&entries)?;

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

    /// Reject directory trees that reference absent entries or contain
    /// sibling/child cycles.  A compound file without a root storage is also
    /// malformed.  Free entries are not traversed (their link fields are
    /// ignored storage).
    fn validate_directory(entries: &[CompoundEntry]) -> Result<(), String> {
        let mut root_index = None;
        for (index, entry) in entries.iter().enumerate() {
            if !matches!(entry.kind, 0 | 1 | 2 | 5) {
                return Err(format!("directory entry {index} has invalid type"));
            }
            if entry.kind == 5 {
                if root_index.is_some() {
                    return Err("compound file has multiple root storages".to_string());
                }
                root_index = Some(index);
            }
            if entry.kind == 0 {
                continue;
            }
            for (pointer, edge) in [
                (entry.left, "left"),
                (entry.right, "right"),
                (entry.child, "child"),
            ] {
                if pointer == NOSTREAM {
                    continue;
                }
                let target = pointer as usize;
                if target >= entries.len() {
                    return Err(format!(
                        "directory entry {index} {edge} pointer references absent entry {target}"
                    ));
                }
                if entries[target].kind == 0 {
                    return Err(format!(
                        "directory entry {index} {edge} pointer references a free entry"
                    ));
                }
            }
        }
        if root_index.is_none() {
            return Err("compound file has no root storage".to_string());
        }

        let mut colors = vec![0_u8; entries.len()];
        fn visit(index: usize, entries: &[CompoundEntry], colors: &mut [u8]) -> Result<(), String> {
            match colors[index] {
                1 => return Err("cyclic compound-file directory tree".to_string()),
                2 => return Ok(()),
                _ => {}
            }
            colors[index] = 1;
            if entries[index].kind != 0 {
                for pointer in [
                    entries[index].left,
                    entries[index].right,
                    entries[index].child,
                ] {
                    if pointer != NOSTREAM {
                        visit(pointer as usize, entries, colors)?;
                    }
                }
            }
            colors[index] = 2;
            Ok(())
        }
        for index in 0..entries.len() {
            visit(index, entries, &mut colors)?;
        }
        Ok(())
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

    pub(crate) fn root_entry(&self) -> Option<&CompoundEntry> {
        self.entries.iter().find(|entry| entry.kind == 5)
    }

    /// Enumerate the directory entries below `storage` in sibling order.
    fn child_indices(&self, storage: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let Some(storage_entry) = self.entries.get(storage) else {
            return out;
        };
        let mut stack = Vec::new();
        let mut current = storage_entry.child;
        while current != NOSTREAM || !stack.is_empty() {
            while current != NOSTREAM {
                let Some(entry) = self.entries.get(current as usize) else {
                    return out;
                };
                stack.push(current);
                current = entry.left;
            }
            let Some(index) = stack.pop() else {
                break;
            };
            let Some(entry) = self.entries.get(index as usize) else {
                break;
            };
            out.push(index as usize);
            current = entry.right;
        }
        out
    }

    /// Resolve a storage or stream path such as
    /// `Root/Storage/Sub/Stream`.  Both `/` and `\` separators are accepted,
    /// a leading `Root`/`Root Entry` component is optional, and names match
    /// case-insensitively.
    pub(crate) fn entry_index_at(&self, path: &str) -> Option<usize> {
        let root = self.entries.iter().position(|entry| entry.kind == 5)?;
        let root_name = self.entries[root].decoded_name();
        let mut current = root;
        for part in path.split(|ch| ch == '/' || ch == '\\') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if current == root
                && (part.eq_ignore_ascii_case("Root")
                    || part.eq_ignore_ascii_case("Root Entry")
                    || part.eq_ignore_ascii_case(&root_name))
            {
                continue;
            }
            let entry = self.entries.get(current)?;
            if entry.kind != 1 && entry.kind != 5 {
                return None;
            }
            current = self.child_indices(current).into_iter().find(|index| {
                let child = &self.entries[*index];
                child.decoded_name().eq_ignore_ascii_case(part)
                    || child.name.eq_ignore_ascii_case(part)
            })?;
        }
        Some(current)
    }

    pub(crate) fn entry_at(&self, path: &str) -> Option<&CompoundEntry> {
        self.entry_index_at(path)
            .and_then(|index| self.entries.get(index))
    }

    /// Resolve `path` to a storage entry (the root or a child storage).
    pub(crate) fn storage_at(&self, path: &str) -> Option<&CompoundEntry> {
        self.entry_at(path)
            .filter(|entry| entry.kind == 1 || entry.kind == 5)
    }

    /// Resolve `path` to a stream entry.
    pub(crate) fn stream_entry_at(&self, path: &str) -> Option<&CompoundEntry> {
        self.entry_at(path).filter(|entry| entry.kind == 2)
    }

    /// The direct children of a storage (streams and child storages).
    pub(crate) fn children(&self, path: &str) -> Option<Vec<CompoundEntry>> {
        let index = self.entry_index_at(path)?;
        let entry = self.entries.get(index)?;
        if entry.kind != 1 && entry.kind != 5 {
            return None;
        }
        Some(
            self.child_indices(index)
                .into_iter()
                .filter_map(|child| self.entries.get(child).cloned())
                .filter(|child| child.kind == 1 || child.kind == 2)
                .collect(),
        )
    }

    pub(crate) fn stream_at(&self, path: &str) -> Option<Vec<u8>> {
        let index = self.entry_index_at(path)?;
        let entry = self.entries.get(index)?;
        if entry.kind != 2 {
            return None;
        }
        self.read_entry(entry).ok()
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

    fn modify_target_index(query: &ResolvedQuery) -> Option<usize> {
        if query.tables.len() == 1 {
            return query
                .tables
                .first()
                .filter(|table| table.derived.is_none())
                .map(|_| 0);
        }
        let mut target = None;
        for column in &query.columns {
            if column.expression.is_some() {
                continue;
            }
            match target {
                None => target = Some(column.table),
                Some(existing) if existing == column.table => {}
                Some(_) => return None,
            }
        }
        target.filter(|index| {
            query
                .tables
                .get(*index)
                .is_some_and(|table| table.derived.is_none())
        })
    }

    fn remap_modify_record(query: &ResolvedQuery, target: usize, record: &MsiRecord) -> MsiRecord {
        let width = query
            .tables
            .get(target)
            .map_or(0, |table| table.columns.len());
        let mut remapped = MsiRecord::new(width);
        if let Some(selected) = record.fields.first() {
            remapped.fields[0] = selected.clone();
        }
        for (slot, column) in query.columns.iter().enumerate() {
            if column.expression.is_some() || column.table != target {
                continue;
            }
            let Some(value) = record.fields.get(slot + 1) else {
                continue;
            };
            if let Some(field) = remapped.fields.get_mut(column.column + 1) {
                *field = value.clone();
            }
        }
        remapped
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
        record.fields[0] = MsiValue::Int(
            Self::modify_target_index(&query)
                .and_then(|table| row.source.get(table).copied().flatten())
                .map(|index| index as i32 + 1)
                .unwrap_or(0),
        );
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
        let target_index = Self::modify_target_index(&view.query);
        let base_table = target_index.map(|index| view.query.tables[index].name.clone());
        let record = match target_index {
            Some(target) => Self::remap_modify_record(&view.query, target, &record),
            None => record,
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
                return self.msi_seek_view(
                    handle,
                    &view,
                    base_table.as_deref(),
                    target_index,
                    &record,
                );
            }
            8 => {
                return self.msi_refresh_view(
                    handle,
                    &view,
                    base_table.as_deref(),
                    target_index,
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
        target_index: Option<usize>,
        record: &MsiRecord,
    ) -> u32 {
        let (Some(name), Some(target_index)) = (base_table, target_index) else {
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
            .position(|row| row.source.get(target_index).copied().flatten() == Some(row_index))
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
        target_index: Option<usize>,
        record_handle: u64,
        record: &MsiRecord,
    ) -> u32 {
        let (Some(name), Some(target_index)) = (base_table, target_index) else {
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
        let Some(position) = view
            .rows
            .iter()
            .position(|row| row.source.get(target_index).copied().flatten() == Some(row_index))
        else {
            return ERROR_NO_MORE_ITEMS;
        };
        let source = view.rows[position].source.clone();
        let derived = match materialize_derived(database, &view.query, &view.bound) {
            Ok(derived) => derived,
            Err(code) => return code,
        };
        if let Some(filter) = &view.query.filter {
            match eval_expr(
                database,
                &view.query,
                &source,
                &view.bound,
                None,
                filter,
                &derived,
                &[],
            ) {
                Ok(true) => {}
                Ok(false) => return ERROR_NO_MORE_ITEMS,
                Err(code) => return code,
            }
        }
        let values = match project_row(
            database,
            &view.query,
            &source,
            &view.bound,
            None,
            &derived,
            &[],
        ) {
            Ok(values) => values,
            Err(code) => return code,
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
        ch.to_lowercase().next().unwrap_or(ch)
    }
}

fn sql_string_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.to_lowercase().cmp(&right.to_lowercase())
}

fn msi_value_equal(left: &MsiValue, right: &MsiValue) -> bool {
    match (left, right) {
        (MsiValue::Null, MsiValue::Null) => true,
        (MsiValue::Int(left), MsiValue::Int(right)) => left == right,
        (MsiValue::Str(left), MsiValue::Str(right)) => sql_string_cmp(left, right).is_eq(),
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

#[derive(Debug, Clone, Copy)]
struct OuterFrame<'a> {
    tables: &'a [ResolvedTable],
    derived: &'a [Option<Vec<Vec<MsiValue>>>],
    source: &'a [Option<usize>],
}

fn source_value(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    derived: &[Option<Vec<Vec<MsiValue>>>],
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
    if meta.derived.is_some() {
        return derived
            .get(table)
            .and_then(|rows| rows.as_ref())
            .and_then(|rows| rows.get(*row_index))
            .and_then(|row| row.get(column))
            .cloned()
            .unwrap_or(MsiValue::Null);
    }
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

fn table_row_count(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    derived: &[Option<Vec<Vec<MsiValue>>>],
    table: usize,
) -> Result<usize, u32> {
    let meta = query.tables.get(table).ok_or(ERROR_BAD_QUERY_SYNTAX)?;
    if meta.derived.is_some() {
        return Ok(derived
            .get(table)
            .and_then(|rows| rows.as_ref())
            .map_or(0, Vec::len));
    }
    database
        .table(&meta.name)
        .map(|table| table.rows.len())
        .ok_or(ERROR_INVALID_TABLE)
}

fn eval_aggregate(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    parameters: &[MsiValue],
    group: Option<&[Vec<Option<usize>>]>,
    function: SqlAggregate,
    argument: Option<&ResolvedExpr>,
    distinct: bool,
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<MsiValue, u32> {
    let Some(group) = group else {
        return Ok(MsiValue::Null);
    };
    match function {
        SqlAggregate::Count => {
            let Some(argument) = argument else {
                return Ok(MsiValue::Int(group.len() as i32));
            };
            let mut count = 0i64;
            let mut seen: Vec<MsiValue> = Vec::new();
            for source in group {
                let value = eval_value(
                    database, query, source, parameters, None, argument, derived, outer,
                )?;
                if matches!(value, MsiValue::Null) {
                    continue;
                }
                if distinct
                    && seen
                        .iter()
                        .any(|existing| msi_value_equal(existing, &value))
                {
                    continue;
                }
                if distinct {
                    seen.push(value);
                }
                count += 1;
            }
            Ok(MsiValue::Int(count as i32))
        }
        SqlAggregate::Sum | SqlAggregate::Average => {
            let Some(argument) = argument else {
                return Ok(MsiValue::Null);
            };
            let mut total = 0i64;
            let mut count = 0i64;
            let mut seen: Vec<MsiValue> = Vec::new();
            for source in group {
                let value = eval_value(
                    database, query, source, parameters, None, argument, derived, outer,
                )?;
                let MsiValue::Int(number) = value else {
                    continue;
                };
                if distinct {
                    let value = MsiValue::Int(number);
                    if seen
                        .iter()
                        .any(|existing| msi_value_equal(existing, &value))
                    {
                        continue;
                    }
                    seen.push(value);
                }
                total += i64::from(number);
                count += 1;
            }
            if count == 0 {
                return Ok(MsiValue::Null);
            }
            if function == SqlAggregate::Average {
                total /= count;
            }
            Ok(MsiValue::Int(
                total.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
            ))
        }
        SqlAggregate::Min | SqlAggregate::Max => {
            let Some(argument) = argument else {
                return Ok(MsiValue::Null);
            };
            let mut best: Option<MsiValue> = None;
            for source in group {
                let value = eval_value(
                    database, query, source, parameters, None, argument, derived, outer,
                )?;
                if matches!(value, MsiValue::Null) {
                    continue;
                }
                let replace = match &best {
                    None => true,
                    Some(current) => {
                        let ordering = compare_order_values(&value, current);
                        if function == SqlAggregate::Min {
                            ordering.is_lt()
                        } else {
                            ordering.is_gt()
                        }
                    }
                };
                if replace {
                    best = Some(value);
                }
            }
            Ok(best.unwrap_or(MsiValue::Null))
        }
    }
}

fn eval_binary(op: SqlBinaryOp, left: MsiValue, right: MsiValue) -> Result<MsiValue, u32> {
    let (MsiValue::Int(left), MsiValue::Int(right)) = (left, right) else {
        return Ok(MsiValue::Null);
    };
    let left = i64::from(left);
    let right = i64::from(right);
    let value = match op {
        SqlBinaryOp::Add => left + right,
        SqlBinaryOp::Subtract => left - right,
        SqlBinaryOp::Multiply => left * right,
        SqlBinaryOp::Divide => {
            if right == 0 {
                return Err(ERROR_FUNCTION_FAILED);
            }
            left / right
        }
        SqlBinaryOp::Modulo => {
            if right == 0 {
                return Err(ERROR_FUNCTION_FAILED);
            }
            left % right
        }
    };
    Ok(MsiValue::Int(
        value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
    ))
}

fn eval_function(function: SqlFunction, arguments: Vec<MsiValue>) -> Result<MsiValue, u32> {
    match function {
        SqlFunction::Upper => {
            let value = arguments.into_iter().next().unwrap_or(MsiValue::Null);
            let MsiValue::Str(text) = value else {
                return Ok(MsiValue::Null);
            };
            Ok(MsiValue::Str(text.to_uppercase()))
        }
        SqlFunction::Lower => {
            let value = arguments.into_iter().next().unwrap_or(MsiValue::Null);
            let MsiValue::Str(text) = value else {
                return Ok(MsiValue::Null);
            };
            Ok(MsiValue::Str(text.to_lowercase()))
        }
        SqlFunction::Length => {
            let value = arguments.into_iter().next().unwrap_or(MsiValue::Null);
            let MsiValue::Str(text) = value else {
                return Ok(MsiValue::Null);
            };
            Ok(MsiValue::Int(text.chars().count() as i32))
        }
        SqlFunction::Substring => {
            if arguments.len() != 3 {
                return Ok(MsiValue::Null);
            }
            let (MsiValue::Str(text), MsiValue::Int(start), MsiValue::Int(length)) =
                (&arguments[0], &arguments[1], &arguments[2])
            else {
                return Ok(MsiValue::Null);
            };
            let start = (*start).max(1) as usize - 1;
            let length = (*length).max(0) as usize;
            Ok(MsiValue::Str(
                text.chars().skip(start).take(length).collect(),
            ))
        }
    }
}

fn eval_value(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
    parameters: &[MsiValue],
    group: Option<&[Vec<Option<usize>>]>,
    expression: &ResolvedExpr,
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<MsiValue, u32> {
    match expression {
        ResolvedExpr::Column { table, column } => Ok(source_value(
            database,
            &query.tables,
            derived,
            source,
            *table,
            *column,
        )),
        ResolvedExpr::OuterColumn {
            level,
            table,
            column,
            ..
        } => {
            let Some(frame) = outer.get(level.saturating_sub(1)) else {
                return Ok(MsiValue::Null);
            };
            Ok(source_value(
                database,
                frame.tables,
                frame.derived,
                frame.source,
                *table,
                *column,
            ))
        }
        ResolvedExpr::Literal(value) => Ok(value.clone()),
        ResolvedExpr::Parameter(index) => {
            Ok(parameters.get(*index).cloned().unwrap_or(MsiValue::Null))
        }
        ResolvedExpr::Aggregate {
            function,
            argument,
            distinct,
        } => eval_aggregate(
            database,
            query,
            parameters,
            group,
            *function,
            argument.as_deref(),
            *distinct,
            derived,
            outer,
        ),
        ResolvedExpr::ScalarQuery(subquery) => {
            let mut nested: Vec<OuterFrame<'_>> = Vec::with_capacity(outer.len() + 1);
            nested.push(OuterFrame {
                tables: &query.tables,
                derived,
                source,
            });
            nested.extend_from_slice(outer);
            let rows = execute_query_with_outer(database, subquery, parameters, &nested)?;
            if rows.len() > 1 {
                return Err(ERROR_FUNCTION_FAILED);
            }
            Ok(rows
                .into_iter()
                .next()
                .and_then(|row| row.values.into_iter().next())
                .unwrap_or(MsiValue::Null))
        }
        ResolvedExpr::Exists {
            query: subquery,
            negated,
        } => {
            let mut nested: Vec<OuterFrame<'_>> = Vec::with_capacity(outer.len() + 1);
            nested.push(OuterFrame {
                tables: &query.tables,
                derived,
                source,
            });
            nested.extend_from_slice(outer);
            let rows = execute_query_with_outer(database, subquery, parameters, &nested)?;
            let found = !rows.is_empty();
            Ok(MsiValue::Int(i32::from(if *negated {
                !found
            } else {
                found
            })))
        }
        ResolvedExpr::Unary { op, value } => {
            let value = eval_value(
                database, query, source, parameters, group, value, derived, outer,
            )?;
            match (op, value) {
                (_, MsiValue::Null) => Ok(MsiValue::Null),
                (SqlUnaryOp::Plus, value @ MsiValue::Int(_)) => Ok(value),
                (SqlUnaryOp::Negate, MsiValue::Int(number)) => Ok(MsiValue::Int(
                    (-i64::from(number)).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                )),
                _ => Ok(MsiValue::Null),
            }
        }
        ResolvedExpr::Binary { op, left, right } => {
            let left = eval_value(
                database, query, source, parameters, group, left, derived, outer,
            )?;
            let right = eval_value(
                database, query, source, parameters, group, right, derived, outer,
            )?;
            eval_binary(*op, left, right)
        }
        ResolvedExpr::Function {
            function,
            arguments,
        } => {
            let mut values = Vec::with_capacity(arguments.len());
            for argument in arguments {
                values.push(eval_value(
                    database, query, source, parameters, group, argument, derived, outer,
                )?);
            }
            eval_function(*function, values)
        }
        _ => Ok(MsiValue::Null),
    }
}

fn like_match(text: &str, pattern: &str, escape: Option<char>) -> bool {
    let text: Vec<char> = text.chars().map(sql_lower).collect();
    let pattern: Vec<char> = pattern.chars().collect();

    fn matches(text: &[char], pattern: &[char], escape: Option<char>) -> bool {
        let Some((&head, rest)) = pattern.split_first() else {
            return text.is_empty();
        };
        if Some(head) == escape {
            let Some((&literal, tail)) = rest.split_first() else {
                return false;
            };
            return text.first().is_some_and(|ch| *ch == sql_lower(literal))
                && matches(&text[1..], tail, escape);
        }
        match head {
            '%' => {
                let mut start = 0;
                loop {
                    if matches(&text[start..], rest, escape) {
                        return true;
                    }
                    if start >= text.len() {
                        return false;
                    }
                    start += 1;
                }
            }
            '_' => !text.is_empty() && matches(&text[1..], rest, escape),
            '[' => {
                let mut index = 0;
                let mut negated = false;
                if matches!(rest.first(), Some('^') | Some('!')) {
                    negated = true;
                    index += 1;
                }
                let mut class_match = false;
                let mut first = true;
                let mut closed = false;
                while index < rest.len() {
                    if rest[index] == ']' && !first {
                        closed = true;
                        break;
                    }
                    first = false;
                    let mut ch = rest[index];
                    if Some(ch) == escape && index + 1 < rest.len() {
                        index += 1;
                        ch = rest[index];
                    }
                    if index + 2 < rest.len() && rest[index + 1] == '-' && rest[index + 2] != ']' {
                        let start = sql_lower(ch);
                        let end = sql_lower(rest[index + 2]);
                        if text.first().is_some_and(|c| *c >= start && *c <= end) {
                            class_match = true;
                        }
                        index += 3;
                    } else {
                        if text.first().is_some_and(|c| *c == sql_lower(ch)) {
                            class_match = true;
                        }
                        index += 1;
                    }
                }
                if !closed || !text.first().is_some_and(|_| class_match != negated) {
                    return false;
                }
                matches(&text[1..], &rest[index + 1..], escape)
            }
            other => {
                text.first().is_some_and(|ch| *ch == sql_lower(other))
                    && matches(&text[1..], rest, escape)
            }
        }
    }

    matches(&text, &pattern, escape)
}

fn eval_expr(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
    parameters: &[MsiValue],
    group: Option<&[Vec<Option<usize>>]>,
    expression: &ResolvedExpr,
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<bool, u32> {
    match expression {
        ResolvedExpr::And(left, right) => Ok(eval_expr(
            database, query, source, parameters, group, left, derived, outer,
        )? && eval_expr(
            database, query, source, parameters, group, right, derived, outer,
        )?),
        ResolvedExpr::Or(left, right) => Ok(eval_expr(
            database, query, source, parameters, group, left, derived, outer,
        )? || eval_expr(
            database, query, source, parameters, group, right, derived, outer,
        )?),
        ResolvedExpr::Not(inner) => Ok(!eval_expr(
            database, query, source, parameters, group, inner, derived, outer,
        )?),
        ResolvedExpr::Compare { left, op, right } => Ok(compare_msi_values(
            &eval_value(
                database, query, source, parameters, group, left, derived, outer,
            )?,
            *op,
            &eval_value(
                database, query, source, parameters, group, right, derived, outer,
            )?,
        )),
        ResolvedExpr::IsNull { value, negated } => {
            let is_null = matches!(
                eval_value(
                    database, query, source, parameters, group, value, derived, outer,
                )?,
                MsiValue::Null
            );
            Ok(if *negated { !is_null } else { is_null })
        }
        ResolvedExpr::Like {
            value,
            pattern,
            escape,
            negated,
        } => {
            let value = eval_value(
                database, query, source, parameters, group, value, derived, outer,
            )?;
            let pattern = eval_value(
                database, query, source, parameters, group, pattern, derived, outer,
            )?;
            let (MsiValue::Str(text), MsiValue::Str(pattern)) = (value, pattern) else {
                return Ok(false);
            };
            let matched = like_match(&text, &pattern, *escape);
            Ok(if *negated { !matched } else { matched })
        }
        ResolvedExpr::Between {
            value,
            low,
            high,
            negated,
        } => {
            let value = eval_value(
                database, query, source, parameters, group, value, derived, outer,
            )?;
            let low = eval_value(
                database, query, source, parameters, group, low, derived, outer,
            )?;
            let high = eval_value(
                database, query, source, parameters, group, high, derived, outer,
            )?;
            if matches!(value, MsiValue::Null)
                || matches!(low, MsiValue::Null)
                || matches!(high, MsiValue::Null)
            {
                return Ok(false);
            }
            let matched = compare_msi_values(&value, SqlCompareOp::Ge, &low)
                && compare_msi_values(&value, SqlCompareOp::Le, &high);
            Ok(if *negated { !matched } else { matched })
        }
        ResolvedExpr::InList {
            value,
            items,
            negated,
        } => {
            let value = eval_value(
                database, query, source, parameters, group, value, derived, outer,
            )?;
            if matches!(value, MsiValue::Null) {
                return Ok(false);
            }
            let mut found = false;
            let mut has_null = false;
            for item in items {
                let item = eval_value(
                    database, query, source, parameters, group, item, derived, outer,
                )?;
                if matches!(item, MsiValue::Null) {
                    has_null = true;
                } else if msi_value_equal(&value, &item) {
                    found = true;
                }
            }
            Ok(if *negated { !found && !has_null } else { found })
        }
        ResolvedExpr::InQuery {
            value,
            query: subquery,
            negated,
        } => {
            let value = eval_value(
                database, query, source, parameters, group, value, derived, outer,
            )?;
            if matches!(value, MsiValue::Null) {
                return Ok(false);
            }
            let mut nested: Vec<OuterFrame<'_>> = Vec::with_capacity(outer.len() + 1);
            nested.push(OuterFrame {
                tables: &query.tables,
                derived,
                source,
            });
            nested.extend_from_slice(outer);
            let rows = execute_query_with_outer(database, subquery, parameters, &nested)?;
            let mut found = false;
            let mut has_null = false;
            for row in rows {
                match row.values.first() {
                    Some(MsiValue::Null) => has_null = true,
                    Some(item) => {
                        if msi_value_equal(&value, item) {
                            found = true;
                        }
                    }
                    None => {}
                }
            }
            Ok(if *negated { !found && !has_null } else { found })
        }
        ResolvedExpr::Exists {
            query: subquery,
            negated,
        } => {
            let mut nested: Vec<OuterFrame<'_>> = Vec::with_capacity(outer.len() + 1);
            nested.push(OuterFrame {
                tables: &query.tables,
                derived,
                source,
            });
            nested.extend_from_slice(outer);
            let rows = execute_query_with_outer(database, subquery, parameters, &nested)?;
            let found = !rows.is_empty();
            Ok(if *negated { !found } else { found })
        }
        _ => Ok(false),
    }
}

fn project_row(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
    parameters: &[MsiValue],
    group: Option<&[Vec<Option<usize>>]>,
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<Vec<MsiValue>, u32> {
    query
        .columns
        .iter()
        .map(|column| match &column.expression {
            Some(expression) => eval_value(
                database, query, source, parameters, group, expression, derived, outer,
            ),
            None => Ok(source_value(
                database,
                &query.tables,
                derived,
                source,
                column.table,
                column.column,
            )),
        })
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
    parameters: &[MsiValue],
    group: Option<&[Vec<Option<usize>>]>,
    key: &OrderSource,
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<MsiValue, u32> {
    match key {
        OrderSource::Output(index) => Ok(values.get(*index).cloned().unwrap_or(MsiValue::Null)),
        OrderSource::Column { table, column } => Ok(source_value(
            database,
            &query.tables,
            derived,
            source,
            *table,
            *column,
        )),
        OrderSource::Expr(expression) => eval_value(
            database, query, source, parameters, group, expression, derived, outer,
        ),
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

fn sort_rows(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    parameters: &[MsiValue],
    rows: &mut [ViewRow],
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<(), u32> {
    let error = std::cell::Cell::new(None);
    rows.sort_by(|left, right| {
        for order in &query.order {
            let left_value = order_value(
                database,
                query,
                &left.source,
                &left.values,
                parameters,
                left.group.as_deref(),
                &order.key,
                derived,
                outer,
            );
            let right_value = order_value(
                database,
                query,
                &right.source,
                &right.values,
                parameters,
                right.group.as_deref(),
                &order.key,
                derived,
                outer,
            );
            let left_value = match left_value {
                Ok(value) => value,
                Err(code) => {
                    error.set(Some(code));
                    MsiValue::Null
                }
            };
            let right_value = match right_value {
                Ok(value) => value,
                Err(code) => {
                    error.set(Some(code));
                    MsiValue::Null
                }
            };
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
    match error.get() {
        Some(code) => Err(code),
        None => Ok(()),
    }
}

fn join_matches(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    source: &[Option<usize>],
    parameters: &[MsiValue],
    on: &Option<ResolvedExpr>,
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<bool, u32> {
    match on {
        Some(on) => eval_expr(
            database, query, source, parameters, None, on, derived, outer,
        ),
        None => Ok(true),
    }
}

fn materialize_derived(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    parameters: &[MsiValue],
) -> Result<Vec<Option<Vec<Vec<MsiValue>>>>, u32> {
    let mut rows = Vec::with_capacity(query.tables.len());
    for table in &query.tables {
        match &table.derived {
            Some(subquery) => {
                let result = execute_query(database, subquery, parameters)?;
                rows.push(Some(result.into_iter().map(|row| row.values).collect()));
            }
            None => rows.push(None),
        }
    }
    Ok(rows)
}

fn execute_query(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    parameters: &[MsiValue],
) -> Result<Vec<ViewRow>, u32> {
    execute_query_with_outer(database, query, parameters, &[])
}

fn execute_query_with_outer(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    parameters: &[MsiValue],
    outer: &[OuterFrame<'_>],
) -> Result<Vec<ViewRow>, u32> {
    let derived = materialize_derived(database, query, parameters)?;
    let mut rows = execute_query_core(database, query, parameters, &derived, outer)?;
    if !query.unions.is_empty() {
        for union in &query.unions {
            let mut part = execute_query_with_outer(database, &union.query, parameters, outer)?;
            rows.append(&mut part);
        }
        if query.unions.iter().any(|union| !union.all) {
            deduplicate_rows(&mut rows);
        }
    }
    if !query.order.is_empty() {
        sort_rows(database, query, parameters, &mut rows, &derived, outer)?;
    }
    Ok(rows)
}

fn execute_query_core(
    database: &MsiDatabaseState,
    query: &ResolvedQuery,
    parameters: &[MsiValue],
    derived: &[Option<Vec<Vec<MsiValue>>>],
    outer: &[OuterFrame<'_>],
) -> Result<Vec<ViewRow>, u32> {
    let Some(base) = query.tables.first() else {
        return Err(ERROR_BAD_QUERY_SYNTAX);
    };
    if base.derived.is_none() && database.table(&base.name).is_none() {
        return Err(ERROR_INVALID_TABLE);
    }
    let base_rows = table_row_count(database, query, derived, 0)?;
    let mut partial: Vec<Vec<Option<usize>>> =
        (0..base_rows).map(|index| vec![Some(index)]).collect();
    for join in &query.joins {
        let Some(meta) = query.tables.get(join.table) else {
            return Err(ERROR_BAD_QUERY_SYNTAX);
        };
        if meta.derived.is_none() && database.table(&meta.name).is_none() {
            return Err(ERROR_INVALID_TABLE);
        }
        let row_count = table_row_count(database, query, derived, join.table)?;
        let width = join.table;
        let mut combined = Vec::new();
        match join.kind {
            SqlJoinKind::Cross => {
                for source in partial {
                    for row_index in 0..row_count {
                        let mut candidate = source.clone();
                        candidate.push(Some(row_index));
                        combined.push(candidate);
                    }
                }
            }
            SqlJoinKind::Inner | SqlJoinKind::LeftOuter => {
                for source in partial {
                    let mut matched = false;
                    for row_index in 0..row_count {
                        let mut candidate = source.clone();
                        candidate.push(Some(row_index));
                        if join_matches(
                            database, query, &candidate, parameters, &join.on, derived, outer,
                        )? {
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
            }
            SqlJoinKind::RightOuter => {
                let mut right_matched = vec![false; row_count];
                for source in &partial {
                    for row_index in 0..row_count {
                        let mut candidate = source.clone();
                        candidate.push(Some(row_index));
                        if join_matches(
                            database, query, &candidate, parameters, &join.on, derived, outer,
                        )? {
                            right_matched[row_index] = true;
                            combined.push(candidate);
                        }
                    }
                }
                for (row_index, matched) in right_matched.iter().enumerate() {
                    if !matched {
                        let mut candidate = vec![None; width];
                        candidate.push(Some(row_index));
                        combined.push(candidate);
                    }
                }
            }
            SqlJoinKind::FullOuter => {
                let mut right_matched = vec![false; row_count];
                for source in partial {
                    let mut matched = false;
                    for row_index in 0..row_count {
                        let mut candidate = source.clone();
                        candidate.push(Some(row_index));
                        if join_matches(
                            database, query, &candidate, parameters, &join.on, derived, outer,
                        )? {
                            matched = true;
                            right_matched[row_index] = true;
                            combined.push(candidate);
                        }
                    }
                    if !matched {
                        let mut candidate = source;
                        candidate.push(None);
                        combined.push(candidate);
                    }
                }
                for (row_index, matched) in right_matched.iter().enumerate() {
                    if !matched {
                        let mut candidate = vec![None; width];
                        candidate.push(Some(row_index));
                        combined.push(candidate);
                    }
                }
            }
        }
        partial = combined;
    }
    let mut filtered = Vec::with_capacity(partial.len());
    for source in partial {
        let keep = match &query.filter {
            Some(filter) => eval_expr(
                database, query, &source, parameters, None, filter, derived, outer,
            )?,
            None => true,
        };
        if keep {
            filtered.push(source);
        }
    }
    let mut rows = Vec::new();
    if query.grouped {
        let mut groups: Vec<(Vec<MsiValue>, Vec<Vec<Option<usize>>>)> = Vec::new();
        for source in filtered {
            let mut key = Vec::with_capacity(query.group_by.len());
            for expression in &query.group_by {
                key.push(eval_value(
                    database, query, &source, parameters, None, expression, derived, outer,
                )?);
            }
            if let Some((_, members)) = groups.iter_mut().find(|(existing, _)| {
                existing.len() == key.len()
                    && existing
                        .iter()
                        .zip(&key)
                        .all(|(left, right)| msi_value_equal(left, right))
            }) {
                members.push(source);
            } else {
                groups.push((key, vec![source]));
            }
        }
        if groups.is_empty() && query.group_by.is_empty() {
            let members: Vec<Vec<Option<usize>>> = Vec::new();
            let source = vec![None; query.tables.len()];
            let keep = match &query.having {
                Some(having) => eval_expr(
                    database,
                    query,
                    &source,
                    parameters,
                    Some(&members),
                    having,
                    derived,
                    outer,
                )?,
                None => true,
            };
            if keep {
                let values = project_row(
                    database,
                    query,
                    &source,
                    parameters,
                    Some(&members),
                    derived,
                    outer,
                )?;
                rows.push(ViewRow {
                    values,
                    source,
                    group: Some(members),
                });
            }
        }
        for (_, members) in groups {
            let source = members
                .first()
                .cloned()
                .unwrap_or_else(|| vec![None; query.tables.len()]);
            if let Some(having) = &query.having {
                if !eval_expr(
                    database,
                    query,
                    &source,
                    parameters,
                    Some(&members),
                    having,
                    derived,
                    outer,
                )? {
                    continue;
                }
            }
            let values = project_row(
                database,
                query,
                &source,
                parameters,
                Some(&members),
                derived,
                outer,
            )?;
            rows.push(ViewRow {
                values,
                source,
                group: Some(members),
            });
        }
    } else {
        for source in filtered {
            let values = project_row(database, query, &source, parameters, None, derived, outer)?;
            rows.push(ViewRow {
                values,
                source,
                group: None,
            });
        }
    }
    if query.distinct {
        deduplicate_rows(&mut rows);
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

    /// True when the cursor is at `(` followed by `SELECT`.
    fn select_follows_paren(&self) -> bool {
        let Some('(') = self.peek() else {
            return false;
        };
        let mut position = self.position + 1;
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
            .is_some_and(|ch| ch.is_ascii_alphabetic())
        {
            position += 1;
        }
        self.chars[start..position]
            .iter()
            .collect::<String>()
            .eq_ignore_ascii_case("SELECT")
    }

    fn select_item(&mut self, parameters: &mut usize) -> Result<SqlSelectItem, ()> {
        self.skip_space();
        let start = self.position;
        if self.peek() == Some('*') {
            self.position += 1;
            return Ok(SqlSelectItem {
                table: None,
                column: None,
                alias: None,
                expression: None,
            });
        }
        if let Some(ch) = self.peek() {
            if ch.is_ascii_alphabetic() || ch == '_' || ch == '`' || ch == '[' {
                let first = self.ident()?;
                if first.ends_with('.') && self.peek() == Some('*') {
                    self.position += 1;
                    return Ok(SqlSelectItem {
                        table: Some(first.trim_end_matches('.').to_string()),
                        column: None,
                        alias: None,
                        expression: None,
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
                            expression: None,
                        });
                    }
                }
                self.position = start;
            }
        }
        let expression = parse_or(self, parameters)?;
        if let SqlExpr::Column { table, name } = expression {
            return Ok(SqlSelectItem {
                table,
                column: Some(name),
                alias: None,
                expression: None,
            });
        }
        Ok(SqlSelectItem {
            table: None,
            column: None,
            alias: None,
            expression: Some(expression),
        })
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
    let mut query = parse_query(&mut cursor, &mut parameters)?;
    if !cursor.at_end() {
        return Err(());
    }
    query.parameter_count = parameters;
    Ok(query)
}

fn parse_query(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<MsiQuery, ()> {
    let mut query = parse_query_core(cursor, parameters)?;
    while cursor.consume_word("UNION") {
        let all = cursor.consume_word("ALL");
        let part = parse_query_core(cursor, parameters)?;
        query.unions.push(SqlUnionPart {
            all,
            query: Box::new(part),
        });
    }
    if cursor.consume_word("ORDER") {
        cursor.expect_word("BY")?;
        query.order = parse_order_list(cursor, parameters)?;
    }
    Ok(query)
}

fn parse_query_core(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<MsiQuery, ()> {
    cursor.expect_word("SELECT")?;
    let distinct = cursor.consume_word("DISTINCT");
    let columns = parse_select_list(cursor, parameters)?;
    cursor.expect_word("FROM")?;
    let from = parse_from(cursor, parameters)?;
    let filter = if cursor.consume_word("WHERE") {
        Some(parse_expression(cursor, parameters)?)
    } else {
        None
    };
    let group_by = if cursor.consume_word("GROUP") {
        cursor.expect_word("BY")?;
        parse_group_list(cursor, parameters)?
    } else {
        Vec::new()
    };
    let having = if cursor.consume_word("HAVING") {
        Some(parse_expression(cursor, parameters)?)
    } else {
        None
    };
    Ok(MsiQuery {
        distinct,
        columns,
        from,
        filter,
        group_by,
        having,
        order: Vec::new(),
        unions: Vec::new(),
        parameter_count: *parameters,
    })
}

fn parse_select_list(
    cursor: &mut SqlCursor,
    parameters: &mut usize,
) -> Result<Vec<SqlSelectItem>, ()> {
    let mut items = Vec::new();
    loop {
        let mut item = cursor.select_item(parameters)?;
        item.alias = cursor.parse_optional_alias(&["FROM"])?;
        if item.column.is_none() && item.expression.is_none() && item.alias.is_some() {
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

fn parse_group_list(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<Vec<SqlExpr>, ()> {
    let mut items = Vec::new();
    loop {
        items.push(parse_arithmetic(cursor, parameters)?);
        cursor.skip_space();
        if cursor.peek() == Some(',') {
            cursor.position += 1;
            continue;
        }
        break;
    }
    Ok(items)
}

fn parse_table_ref(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlTableRef, ()> {
    cursor.skip_space();
    if cursor.select_follows_paren() {
        cursor.position += 1;
        let query = parse_query(cursor, parameters)?;
        cursor.skip_space();
        if cursor.bump() != Some(')') {
            return Err(());
        }
        let alias = cursor
            .parse_optional_alias(&[
                "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "OUTER", "JOIN", "ON", "WHERE", "GROUP",
                "HAVING", "ORDER", "UNION",
            ])?
            .ok_or(())?;
        return Ok(SqlTableRef {
            table: alias.clone(),
            alias: Some(alias),
            derived: Some(Box::new(query)),
        });
    }
    let table = cursor.ident()?;
    if table.is_empty() {
        return Err(());
    }
    let alias = cursor.parse_optional_alias(&[
        "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "OUTER", "JOIN", "ON", "WHERE", "GROUP",
        "HAVING", "ORDER", "UNION",
    ])?;
    Ok(SqlTableRef {
        table,
        alias,
        derived: None,
    })
}

fn parse_from(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlFrom, ()> {
    let base = parse_table_ref(cursor, parameters)?;
    let mut joins = Vec::new();
    loop {
        let kind = if cursor.consume_word("INNER") {
            cursor.expect_word("JOIN")?;
            SqlJoinKind::Inner
        } else if cursor.consume_word("LEFT") {
            cursor.consume_word("OUTER");
            cursor.expect_word("JOIN")?;
            SqlJoinKind::LeftOuter
        } else if cursor.consume_word("RIGHT") {
            cursor.consume_word("OUTER");
            cursor.expect_word("JOIN")?;
            SqlJoinKind::RightOuter
        } else if cursor.consume_word("FULL") {
            cursor.consume_word("OUTER");
            cursor.expect_word("JOIN")?;
            SqlJoinKind::FullOuter
        } else if cursor.consume_word("CROSS") {
            cursor.expect_word("JOIN")?;
            SqlJoinKind::Cross
        } else if cursor.consume_word("JOIN") {
            SqlJoinKind::Inner
        } else {
            break;
        };
        let table = parse_table_ref(cursor, parameters)?;
        let on = if kind == SqlJoinKind::Cross {
            None
        } else {
            cursor.expect_word("ON")?;
            Some(parse_expression(cursor, parameters)?)
        };
        joins.push(SqlJoin { kind, table, on });
    }
    Ok(SqlFrom { base, joins })
}

fn parse_order_list(
    cursor: &mut SqlCursor,
    parameters: &mut usize,
) -> Result<Vec<SqlOrderKey>, ()> {
    let mut keys = Vec::new();
    loop {
        let expr = parse_arithmetic(cursor, parameters)?;
        let direction = if cursor.consume_word("DESC") {
            SqlDirection::Descending
        } else {
            cursor.consume_word("ASC");
            SqlDirection::Ascending
        };
        keys.push(SqlOrderKey { expr, direction });
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
    if cursor.consume_word("EXISTS") {
        cursor.skip_space();
        if cursor.bump() != Some('(') {
            return Err(());
        }
        let query = parse_query(cursor, parameters)?;
        cursor.skip_space();
        if cursor.bump() != Some(')') {
            return Err(());
        }
        return Ok(SqlExpr::Exists {
            query: Box::new(query),
            negated: false,
        });
    }
    if cursor.consume_word("NOT") {
        cursor.skip_space();
        if cursor.consume_word("EXISTS") {
            cursor.skip_space();
            if cursor.bump() != Some('(') {
                return Err(());
            }
            let query = parse_query(cursor, parameters)?;
            cursor.skip_space();
            if cursor.bump() != Some(')') {
                return Err(());
            }
            return Ok(SqlExpr::Exists {
                query: Box::new(query),
                negated: true,
            });
        }
        return Ok(SqlExpr::Not(Box::new(parse_primary(cursor, parameters)?)));
    }
    parse_comparison(cursor, parameters)
}

fn parse_comparison(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    let left = parse_arithmetic(cursor, parameters)?;
    cursor.skip_space();
    if cursor.consume_word("IS") {
        let negated = cursor.consume_word("NOT");
        cursor.expect_word("NULL")?;
        return Ok(SqlExpr::IsNull {
            value: Box::new(left),
            negated,
        });
    }
    let negated = cursor.consume_word("NOT");
    if negated
        && !matches!(
            cursor.peek_word().to_ascii_uppercase().as_str(),
            "IN" | "LIKE" | "BETWEEN"
        )
    {
        return Err(());
    }
    if cursor.consume_word("IN") {
        cursor.skip_space();
        if cursor.peek() != Some('(') {
            return Err(());
        }
        if cursor.select_follows_paren() {
            cursor.position += 1;
            let query = parse_query(cursor, parameters)?;
            cursor.skip_space();
            if cursor.bump() != Some(')') {
                return Err(());
            }
            return Ok(SqlExpr::InQuery {
                value: Box::new(left),
                query: Box::new(query),
                negated,
            });
        }
        cursor.position += 1;
        let mut items = Vec::new();
        loop {
            cursor.skip_space();
            if cursor.peek() == Some(')') {
                cursor.position += 1;
                break;
            }
            items.push(parse_arithmetic(cursor, parameters)?);
            cursor.skip_space();
            if cursor.peek() == Some(',') {
                cursor.position += 1;
                continue;
            }
            if cursor.peek() == Some(')') {
                cursor.position += 1;
                break;
            }
            return Err(());
        }
        return Ok(SqlExpr::InList {
            value: Box::new(left),
            items,
            negated,
        });
    }
    if cursor.consume_word("LIKE") {
        let pattern = parse_arithmetic(cursor, parameters)?;
        let escape = if cursor.consume_word("ESCAPE") {
            match cursor.literal()? {
                MsiValue::Str(text) if text.chars().count() == 1 => text.chars().next(),
                _ => return Err(()),
            }
        } else {
            None
        };
        return Ok(SqlExpr::Like {
            value: Box::new(left),
            pattern: Box::new(pattern),
            escape,
            negated,
        });
    }
    if cursor.consume_word("BETWEEN") {
        let low = parse_arithmetic(cursor, parameters)?;
        cursor.expect_word("AND")?;
        let high = parse_arithmetic(cursor, parameters)?;
        return Ok(SqlExpr::Between {
            value: Box::new(left),
            low: Box::new(low),
            high: Box::new(high),
            negated,
        });
    }
    if negated {
        return Err(());
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
        _ => return Ok(left),
    };
    let right = parse_arithmetic(cursor, parameters)?;
    Ok(SqlExpr::Compare {
        left: Box::new(left),
        op,
        right: Box::new(right),
    })
}

fn parse_arithmetic(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    let mut left = parse_term(cursor, parameters)?;
    loop {
        cursor.skip_space();
        let op = match cursor.peek() {
            Some('+') => SqlBinaryOp::Add,
            Some('-') => SqlBinaryOp::Subtract,
            _ => break,
        };
        cursor.position += 1;
        let right = parse_term(cursor, parameters)?;
        left = SqlExpr::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        };
    }
    Ok(left)
}

fn parse_term(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    let mut left = parse_unary(cursor, parameters)?;
    loop {
        cursor.skip_space();
        let op = match cursor.peek() {
            Some('*') => SqlBinaryOp::Multiply,
            Some('/') => SqlBinaryOp::Divide,
            Some('%') => SqlBinaryOp::Modulo,
            _ => break,
        };
        cursor.position += 1;
        let right = parse_unary(cursor, parameters)?;
        left = SqlExpr::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        };
    }
    Ok(left)
}

fn parse_unary(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    cursor.skip_space();
    let op = match cursor.peek() {
        Some('-') => Some(SqlUnaryOp::Negate),
        Some('+') => Some(SqlUnaryOp::Plus),
        _ => None,
    };
    if let Some(op) = op {
        cursor.position += 1;
        let value = parse_unary(cursor, parameters)?;
        return Ok(SqlExpr::Unary {
            op,
            value: Box::new(value),
        });
    }
    parse_operand(cursor, parameters)
}

fn parse_operand(cursor: &mut SqlCursor, parameters: &mut usize) -> Result<SqlExpr, ()> {
    cursor.skip_space();
    match cursor.peek() {
        Some('(') if cursor.select_follows_paren() => {
            cursor.position += 1;
            let query = parse_query(cursor, parameters)?;
            cursor.skip_space();
            if cursor.bump() != Some(')') {
                return Err(());
            }
            Ok(SqlExpr::ScalarQuery(Box::new(query)))
        }
        Some('(') => {
            cursor.position += 1;
            let expression = parse_or(cursor, parameters)?;
            cursor.skip_space();
            if cursor.bump() != Some(')') {
                return Err(());
            }
            Ok(expression)
        }
        Some('?') => {
            cursor.position += 1;
            let index = *parameters;
            *parameters += 1;
            Ok(SqlExpr::Parameter(index))
        }
        Some('\'') | Some('"') => Ok(SqlExpr::Literal(cursor.literal()?)),
        Some(ch) if ch.is_ascii_digit() => Ok(SqlExpr::Literal(cursor.literal()?)),
        _ => {
            let start = cursor.position;
            let word = cursor.word();
            cursor.skip_space();
            if !word.is_empty() && cursor.peek() == Some('(') {
                let aggregate = if word.eq_ignore_ascii_case("COUNT") {
                    Some(SqlAggregate::Count)
                } else if word.eq_ignore_ascii_case("SUM") {
                    Some(SqlAggregate::Sum)
                } else if word.eq_ignore_ascii_case("AVG") {
                    Some(SqlAggregate::Average)
                } else if word.eq_ignore_ascii_case("MIN") {
                    Some(SqlAggregate::Min)
                } else if word.eq_ignore_ascii_case("MAX") {
                    Some(SqlAggregate::Max)
                } else {
                    None
                };
                if let Some(function) = aggregate {
                    cursor.position += 1;
                    cursor.skip_space();
                    let distinct = cursor.consume_word("DISTINCT");
                    cursor.skip_space();
                    let argument = if function == SqlAggregate::Count && cursor.peek() == Some('*')
                    {
                        if distinct {
                            return Err(());
                        }
                        cursor.position += 1;
                        None
                    } else {
                        Some(Box::new(parse_arithmetic(cursor, parameters)?))
                    };
                    cursor.skip_space();
                    if cursor.bump() != Some(')') {
                        return Err(());
                    }
                    return Ok(SqlExpr::Aggregate {
                        function,
                        argument,
                        distinct,
                    });
                }
                let function = if word.eq_ignore_ascii_case("UPPER") {
                    Some(SqlFunction::Upper)
                } else if word.eq_ignore_ascii_case("LOWER") {
                    Some(SqlFunction::Lower)
                } else if word.eq_ignore_ascii_case("LENGTH") {
                    Some(SqlFunction::Length)
                } else if word.eq_ignore_ascii_case("SUBSTRING") {
                    Some(SqlFunction::Substring)
                } else {
                    None
                };
                if let Some(function) = function {
                    cursor.position += 1;
                    let mut arguments = Vec::new();
                    cursor.skip_space();
                    if cursor.peek() != Some(')') {
                        loop {
                            arguments.push(parse_arithmetic(cursor, parameters)?);
                            cursor.skip_space();
                            if cursor.peek() == Some(',') {
                                cursor.position += 1;
                                continue;
                            }
                            break;
                        }
                    }
                    cursor.skip_space();
                    if cursor.bump() != Some(')') {
                        return Err(());
                    }
                    let expected = if function == SqlFunction::Substring {
                        3
                    } else {
                        1
                    };
                    if arguments.len() != expected {
                        return Err(());
                    }
                    return Ok(SqlExpr::Function {
                        function,
                        arguments,
                    });
                }
                return Err(());
            }
            cursor.position = start;
            let (table, name) = cursor.name_ref()?;
            Ok(SqlExpr::Column { table, name })
        }
    }
}

fn resolve_query(database: &MsiDatabaseState, parsed: MsiQuery) -> Result<ResolvedQuery, u32> {
    let mut expectations = vec![ParameterExpectation::Any; parsed.parameter_count];
    resolve_query_with(database, parsed, &mut expectations, &[])
}

fn resolve_query_with(
    database: &MsiDatabaseState,
    parsed: MsiQuery,
    expectations: &mut [ParameterExpectation],
    outer: &[&[ResolvedTable]],
) -> Result<ResolvedQuery, u32> {
    let MsiQuery {
        distinct,
        columns: select_items,
        from,
        filter: parsed_filter,
        group_by: parsed_group_by,
        having: parsed_having,
        order: parsed_order,
        unions: parsed_unions,
        parameter_count: _,
    } = parsed;
    let mut references: Vec<&SqlTableRef> = Vec::with_capacity(1 + from.joins.len());
    references.push(&from.base);
    for join in &from.joins {
        references.push(&join.table);
    }
    let mut tables: Vec<ResolvedTable> = Vec::with_capacity(references.len());
    for reference in references {
        let (columns, derived) = match &reference.derived {
            Some(query) => {
                let resolved = resolve_query_with(database, (**query).clone(), expectations, &[])?;
                (derived_columns(&resolved.columns), Some(Box::new(resolved)))
            }
            None => {
                let table = database
                    .table(&reference.table)
                    .ok_or(ERROR_INVALID_TABLE)?;
                (table.columns.clone(), None)
            }
        };
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
            columns,
            derived,
        });
    }

    let mut columns = Vec::new();
    let mut aliases: Vec<(String, ResolvedExpr)> = Vec::new();
    for item in &select_items {
        if let Some(expression) = &item.expression {
            let resolved = resolve_expr(
                database,
                &tables,
                expression,
                tables.len(),
                expectations,
                &[],
                outer,
            )?;
            if contains_resolved_aggregate(&resolved) && aggregate_contains_aggregate(&resolved) {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
            let label = item
                .alias
                .clone()
                .unwrap_or_else(|| expression_label(expression));
            if let Some(alias) = &item.alias {
                aliases.push((alias.clone(), resolved.clone()));
            }
            columns.push(ResolvedColumn {
                table: 0,
                column: 0,
                label,
                type_name: resolved_expression_type_name(database, &tables, &resolved)?,
                expression: Some(resolved),
            });
            continue;
        }
        match &item.column {
            None => {
                let table_indices = match &item.table {
                    Some(qualifier) => vec![resolve_table_index(qualifier, &tables)?],
                    None => (0..tables.len()).collect(),
                };
                for table_index in table_indices {
                    let table = tables.get(table_index).ok_or(ERROR_INVALID_TABLE)?;
                    for (column_index, column) in table.columns.iter().enumerate() {
                        columns.push(ResolvedColumn {
                            table: table_index,
                            column: column_index,
                            label: column.name.clone(),
                            type_name: column.type_name(),
                            expression: None,
                        });
                    }
                }
            }
            Some(name) => {
                match resolve_column(
                    database,
                    &tables,
                    item.table.as_deref(),
                    name,
                    tables.len(),
                    ColumnScope::Select,
                ) {
                    Ok((table_index, column_index)) => {
                        let table = tables.get(table_index).ok_or(ERROR_INVALID_TABLE)?;
                        let column = table.columns.get(column_index).ok_or(ERROR_BAD_COLUMN)?;
                        let label = item.alias.clone().unwrap_or_else(|| column.name.clone());
                        if let Some(alias) = &item.alias {
                            aliases.push((
                                alias.clone(),
                                ResolvedExpr::Column {
                                    table: table_index,
                                    column: column_index,
                                },
                            ));
                        }
                        columns.push(ResolvedColumn {
                            table: table_index,
                            column: column_index,
                            label,
                            type_name: column.type_name(),
                            expression: None,
                        });
                    }
                    Err(code) => {
                        let outer_expr = SqlExpr::Column {
                            table: item.table.clone(),
                            name: name.clone(),
                        };
                        let Ok(resolved) = resolve_expr(
                            database,
                            &tables,
                            &outer_expr,
                            tables.len(),
                            expectations,
                            &[],
                            outer,
                        ) else {
                            return Err(code);
                        };
                        if !matches!(resolved, ResolvedExpr::OuterColumn { .. }) {
                            return Err(code); // coverage: unreachable — with no aliases in scope the fallback can only resolve an outer column or fail
                        }
                        let label = item.alias.clone().unwrap_or_else(|| name.clone());
                        let type_name =
                            resolved_expression_type_name(database, &tables, &resolved)?;
                        if let Some(alias) = &item.alias {
                            aliases.push((alias.clone(), resolved.clone()));
                        }
                        columns.push(ResolvedColumn {
                            table: 0,
                            column: 0,
                            label,
                            type_name,
                            expression: Some(resolved),
                        });
                    }
                }
            }
        }
    }
    if columns.is_empty() {
        return Err(ERROR_BAD_QUERY_SYNTAX);
    }

    let mut group_by = Vec::new();
    for expression in &parsed_group_by {
        let resolved = match group_ordinal(expression) {
            Some(ordinal) => {
                if ordinal == 0 || ordinal > columns.len() {
                    return Err(ERROR_BAD_COLUMN);
                }
                resolved_column_expression(&columns[ordinal - 1])
            }
            None => resolve_expr(
                database,
                &tables,
                expression,
                tables.len(),
                expectations,
                &aliases,
                outer,
            )?,
        };
        if contains_resolved_aggregate(&resolved) {
            return Err(ERROR_BAD_QUERY_SYNTAX);
        }
        group_by.push(resolved);
    }
    let having = match &parsed_having {
        Some(expression) => Some(resolve_expr(
            database,
            &tables,
            expression,
            tables.len(),
            expectations,
            &aliases,
            outer,
        )?),
        None => None,
    };

    let mut joins = Vec::new();
    for (index, join) in from.joins.iter().enumerate() {
        let table_index = index + 1;
        let on = match &join.on {
            Some(expression) => Some(resolve_expr(
                database,
                &tables,
                expression,
                table_index + 1,
                expectations,
                &[],
                outer,
            )?),
            None => None,
        };
        if on.as_ref().is_some_and(contains_resolved_aggregate) {
            return Err(ERROR_BAD_QUERY_SYNTAX);
        }
        joins.push(ResolvedJoin {
            table: table_index,
            kind: join.kind,
            on,
        });
    }
    let filter = match &parsed_filter {
        Some(expression) => {
            let resolved = resolve_expr(
                database,
                &tables,
                expression,
                tables.len(),
                expectations,
                &[],
                outer,
            )?;
            if contains_resolved_aggregate(&resolved) {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
            Some(resolved)
        }
        None => None,
    };

    let mut order = Vec::new();
    for parsed_key in &parsed_order {
        let direction = parsed_key.direction;
        let key = match &parsed_key.expr {
            SqlExpr::Literal(MsiValue::Int(ordinal)) if *ordinal >= 1 => {
                let index = (*ordinal - 1) as usize;
                if index >= columns.len() {
                    return Err(ERROR_BAD_COLUMN);
                }
                OrderSource::Output(index)
            }
            SqlExpr::Column { table, name } => {
                if table.is_none() && name.chars().all(|ch| ch.is_ascii_digit()) {
                    let ordinal = name.parse::<usize>().unwrap_or(0);
                    if ordinal == 0 || ordinal > columns.len() {
                        return Err(ERROR_BAD_COLUMN);
                    }
                    OrderSource::Output(ordinal - 1)
                } else if table.is_none() {
                    let matches: Vec<usize> = columns
                        .iter()
                        .enumerate()
                        .filter(|(_, column)| column.label.eq_ignore_ascii_case(name))
                        .map(|(index, _)| index)
                        .collect();
                    match matches.len() {
                        1 => OrderSource::Output(matches[0]),
                        0 => {
                            let (table, column) = resolve_column(
                                database,
                                &tables,
                                None,
                                name,
                                tables.len(),
                                ColumnScope::Expression,
                            )?;
                            OrderSource::Column { table, column }
                        }
                        _ => return Err(ERROR_BAD_COLUMN),
                    }
                } else {
                    let (table_index, column_index) = resolve_column(
                        database,
                        &tables,
                        table.as_deref(),
                        name,
                        tables.len(),
                        ColumnScope::Expression,
                    )?;
                    OrderSource::Column {
                        table: table_index,
                        column: column_index,
                    }
                }
            }
            expression => OrderSource::Expr(resolve_expr(
                database,
                &tables,
                expression,
                tables.len(),
                expectations,
                &aliases,
                outer,
            )?),
        };
        order.push(ResolvedOrder { key, direction });
    }

    let has_aggregates = columns.iter().any(|column| {
        column
            .expression
            .as_ref()
            .is_some_and(contains_resolved_aggregate)
    }) || having.as_ref().is_some_and(contains_resolved_aggregate)
        || order.iter().any(|order| match &order.key {
            OrderSource::Expr(expression) => contains_resolved_aggregate(expression),
            _ => false,
        });
    let grouped = has_aggregates || !group_by.is_empty();
    if grouped {
        for column in &columns {
            if !grouped_expression_valid(&resolved_column_expression(column), &group_by) {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
        }
        if having
            .as_ref()
            .is_some_and(|having| !grouped_expression_valid(having, &group_by))
        {
            return Err(ERROR_BAD_QUERY_SYNTAX);
        }
        for order in &order {
            let valid = match &order.key {
                OrderSource::Expr(expression) => grouped_expression_valid(expression, &group_by),
                OrderSource::Column { table, column } => grouped_expression_valid(
                    &ResolvedExpr::Column {
                        table: *table,
                        column: *column,
                    },
                    &group_by,
                ),
                OrderSource::Output(_) => true,
            };
            if !valid {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
        }
    }

    let mut unions = Vec::new();
    for part in parsed_unions {
        let resolved = resolve_query_with(database, *part.query, expectations, outer)?;
        if resolved.columns.len() != columns.len() {
            return Err(ERROR_BAD_QUERY_SYNTAX);
        }
        for (left, right) in columns.iter().zip(&resolved.columns) {
            if !types_compatible(&left.type_name, &right.type_name) {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
        }
        unions.push(ResolvedUnion {
            all: part.all,
            query: Box::new(resolved),
        });
    }

    Ok(ResolvedQuery {
        distinct,
        tables,
        columns,
        joins,
        filter,
        group_by,
        having,
        grouped,
        order,
        unions,
        parameter_expectations: expectations.to_vec(),
    })
}

fn resolved_column_expression(column: &ResolvedColumn) -> ResolvedExpr {
    column.expression.clone().unwrap_or(ResolvedExpr::Column {
        table: column.table,
        column: column.column,
    })
}

fn column_from_type_name(name: &str, type_name: &str) -> MsiColumn {
    let type_bits = if let Some(width) = type_name.strip_prefix('s') {
        MSITYPE_VALID | MSITYPE_STRING | width.parse::<u16>().unwrap_or(0)
    } else if let Some(width) = type_name.strip_prefix('i') {
        width.parse::<u16>().unwrap_or(4).max(2)
    } else if type_name.starts_with('v') {
        MSITYPE_VALID | MSITYPE_STRING
    } else {
        MSITYPE_VALID | MSITYPE_STRING
    };
    MsiColumn {
        name: name.to_string(),
        type_bits,
    }
}

fn derived_columns(columns: &[ResolvedColumn]) -> Vec<MsiColumn> {
    columns
        .iter()
        .map(|column| column_from_type_name(&column.label, &column.type_name))
        .collect()
}

fn group_ordinal(expression: &SqlExpr) -> Option<usize> {
    match expression {
        SqlExpr::Literal(MsiValue::Int(ordinal)) if *ordinal >= 0 => Some(*ordinal as usize),
        SqlExpr::Column { table: None, name } if name.chars().all(|ch| ch.is_ascii_digit()) => {
            name.parse::<usize>().ok()
        }
        _ => None,
    }
}

fn contains_resolved_aggregate(expression: &ResolvedExpr) -> bool {
    match expression {
        ResolvedExpr::Aggregate { .. } => true,
        ResolvedExpr::IsNull { value, .. }
        | ResolvedExpr::Not(value)
        | ResolvedExpr::Unary { value, .. } => contains_resolved_aggregate(value),
        ResolvedExpr::Compare { left, right, .. }
        | ResolvedExpr::And(left, right)
        | ResolvedExpr::Or(left, right)
        | ResolvedExpr::Binary { left, right, .. } => {
            contains_resolved_aggregate(left) || contains_resolved_aggregate(right)
        }
        ResolvedExpr::Like { value, pattern, .. } => {
            contains_resolved_aggregate(value) || contains_resolved_aggregate(pattern)
        }
        ResolvedExpr::Function { arguments, .. } => {
            arguments.iter().any(contains_resolved_aggregate)
        }
        ResolvedExpr::Between {
            value, low, high, ..
        } => {
            contains_resolved_aggregate(value)
                || contains_resolved_aggregate(low)
                || contains_resolved_aggregate(high)
        }
        ResolvedExpr::InList { value, items, .. } => {
            contains_resolved_aggregate(value) || items.iter().any(contains_resolved_aggregate)
        }
        ResolvedExpr::InQuery { value, .. } => contains_resolved_aggregate(value),
        _ => false,
    }
}

fn aggregate_contains_aggregate(expression: &ResolvedExpr) -> bool {
    match expression {
        ResolvedExpr::Aggregate { argument, .. } => {
            argument.as_deref().is_some_and(contains_resolved_aggregate)
        }
        _ => false,
    }
}

fn resolved_expressions_match(left: &ResolvedExpr, right: &ResolvedExpr) -> bool {
    match (left, right) {
        (
            ResolvedExpr::Column {
                table: left_table,
                column: left_column,
            },
            ResolvedExpr::Column {
                table: right_table,
                column: right_column,
            },
        ) => left_table == right_table && left_column == right_column,
        (
            ResolvedExpr::OuterColumn {
                level: left_level,
                table: left_table,
                column: left_column,
                ..
            },
            ResolvedExpr::OuterColumn {
                level: right_level,
                table: right_table,
                column: right_column,
                ..
            },
        ) => left_level == right_level && left_table == right_table && left_column == right_column,
        (ResolvedExpr::Literal(left), ResolvedExpr::Literal(right)) => left == right,
        (ResolvedExpr::Parameter(left), ResolvedExpr::Parameter(right)) => left == right,
        (
            ResolvedExpr::IsNull {
                value: left,
                negated: left_negated,
            },
            ResolvedExpr::IsNull {
                value: right,
                negated: right_negated,
            },
        ) => left_negated == right_negated && resolved_expressions_match(left, right),
        (
            ResolvedExpr::Compare {
                left: left_left,
                op: left_op,
                right: left_right,
            },
            ResolvedExpr::Compare {
                left: right_left,
                op: right_op,
                right: right_right,
            },
        ) => {
            left_op == right_op
                && resolved_expressions_match(left_left, right_left)
                && resolved_expressions_match(left_right, right_right)
        }
        (ResolvedExpr::And(left_left, left_right), ResolvedExpr::And(right_left, right_right))
        | (ResolvedExpr::Or(left_left, left_right), ResolvedExpr::Or(right_left, right_right)) => {
            resolved_expressions_match(left_left, right_left)
                && resolved_expressions_match(left_right, right_right)
        }
        (ResolvedExpr::Not(left), ResolvedExpr::Not(right)) => {
            resolved_expressions_match(left, right)
        }
        (
            ResolvedExpr::Unary {
                op: left_op,
                value: left,
            },
            ResolvedExpr::Unary {
                op: right_op,
                value: right,
            },
        ) => left_op == right_op && resolved_expressions_match(left, right),
        (
            ResolvedExpr::Binary {
                op: left_op,
                left: left_left,
                right: left_right,
            },
            ResolvedExpr::Binary {
                op: right_op,
                left: right_left,
                right: right_right,
            },
        ) => {
            left_op == right_op
                && resolved_expressions_match(left_left, right_left)
                && resolved_expressions_match(left_right, right_right)
        }
        (
            ResolvedExpr::Function {
                function: left_function,
                arguments: left_arguments,
            },
            ResolvedExpr::Function {
                function: right_function,
                arguments: right_arguments,
            },
        ) => {
            left_function == right_function
                && left_arguments.len() == right_arguments.len()
                && left_arguments
                    .iter()
                    .zip(right_arguments)
                    .all(|(left, right)| resolved_expressions_match(left, right))
        }
        _ => false,
    }
}

fn grouped_expression_valid(expression: &ResolvedExpr, group_by: &[ResolvedExpr]) -> bool {
    if group_by
        .iter()
        .any(|key| resolved_expressions_match(key, expression))
    {
        return true;
    }
    match expression {
        ResolvedExpr::Aggregate { .. } => true,
        ResolvedExpr::Column { table, column } => group_by.iter().any(|key| {
            matches!(
                key,
                ResolvedExpr::Column {
                    table: key_table,
                    column: key_column,
                } if key_table == table && key_column == column
            )
        }),
        ResolvedExpr::Literal(_)
        | ResolvedExpr::Parameter(_)
        | ResolvedExpr::OuterColumn { .. } => true,
        ResolvedExpr::ScalarQuery(_) | ResolvedExpr::Exists { .. } => true,
        ResolvedExpr::IsNull { value, .. }
        | ResolvedExpr::Not(value)
        | ResolvedExpr::Unary { value, .. } => grouped_expression_valid(value, group_by),
        ResolvedExpr::Compare { left, right, .. }
        | ResolvedExpr::And(left, right)
        | ResolvedExpr::Or(left, right)
        | ResolvedExpr::Binary { left, right, .. } => {
            grouped_expression_valid(left, group_by) && grouped_expression_valid(right, group_by)
        }
        ResolvedExpr::Function { arguments, .. } => arguments
            .iter()
            .all(|argument| grouped_expression_valid(argument, group_by)),
        ResolvedExpr::Like { value, pattern, .. } => {
            grouped_expression_valid(value, group_by) && grouped_expression_valid(pattern, group_by)
        }
        ResolvedExpr::Between {
            value, low, high, ..
        } => {
            grouped_expression_valid(value, group_by)
                && grouped_expression_valid(low, group_by)
                && grouped_expression_valid(high, group_by)
        }
        ResolvedExpr::InList { value, items, .. } => {
            grouped_expression_valid(value, group_by)
                && items
                    .iter()
                    .all(|item| grouped_expression_valid(item, group_by))
        }
        ResolvedExpr::InQuery { value, .. } => grouped_expression_valid(value, group_by),
    }
}

fn type_kind(name: &str) -> Option<SqlColumnKind> {
    if name.starts_with('i') {
        Some(SqlColumnKind::Int)
    } else if name.starts_with('s') {
        Some(SqlColumnKind::String { width: 0 })
    } else if name.starts_with('v') {
        Some(SqlColumnKind::Binary)
    } else {
        None
    }
}

fn types_compatible(left: &str, right: &str) -> bool {
    match (type_kind(left), type_kind(right)) {
        (Some(SqlColumnKind::Int), Some(SqlColumnKind::Int)) => true,
        (Some(SqlColumnKind::String { .. }), Some(SqlColumnKind::String { .. })) => true,
        (Some(SqlColumnKind::Binary), Some(SqlColumnKind::Binary)) => true,
        (None, None) => left.eq_ignore_ascii_case(right),
        _ => false,
    }
}

fn expression_label(expression: &SqlExpr) -> String {
    match expression {
        SqlExpr::Aggregate { function, .. } => match function {
            SqlAggregate::Count => "COUNT".to_string(),
            SqlAggregate::Sum => "SUM".to_string(),
            SqlAggregate::Average => "AVG".to_string(),
            SqlAggregate::Min => "MIN".to_string(),
            SqlAggregate::Max => "MAX".to_string(),
        },
        SqlExpr::Column { name, .. } => name.clone(),
        _ => "Expr".to_string(),
    }
}

fn resolved_expression_type_name(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    expression: &ResolvedExpr,
) -> Result<String, u32> {
    match expression {
        ResolvedExpr::Column { table, column } => {
            let kind = column_kind(database, tables, *table, *column)?;
            Ok(match kind {
                SqlColumnKind::Binary => "v0".to_string(),
                SqlColumnKind::String { width } => format!("s{width}"),
                SqlColumnKind::Int => "i4".to_string(),
            })
        }
        ResolvedExpr::OuterColumn { kind, .. } => Ok(match kind {
            SqlColumnKind::Binary => "v0".to_string(),
            SqlColumnKind::String { width } => format!("s{width}"),
            SqlColumnKind::Int => "i4".to_string(),
        }),
        ResolvedExpr::Unary { .. } | ResolvedExpr::Binary { .. } => Ok("i4".to_string()),
        ResolvedExpr::Exists { .. } => Ok("i4".to_string()),
        ResolvedExpr::Function { function, .. } => Ok(match function {
            SqlFunction::Length => "i4".to_string(),
            SqlFunction::Upper | SqlFunction::Lower | SqlFunction::Substring => "s0".to_string(),
        }),
        ResolvedExpr::Literal(MsiValue::Int(_)) => Ok("i4".to_string()),
        ResolvedExpr::Literal(MsiValue::Str(_)) => Ok("s0".to_string()),
        ResolvedExpr::Literal(MsiValue::Stream(_)) => Ok("v0".to_string()),
        ResolvedExpr::Literal(MsiValue::Null) => Ok("s0".to_string()),
        ResolvedExpr::Aggregate {
            function, argument, ..
        } => match function {
            SqlAggregate::Count | SqlAggregate::Sum | SqlAggregate::Average => Ok("i4".to_string()),
            SqlAggregate::Min | SqlAggregate::Max => match argument.as_deref() {
                Some(argument) => resolved_expression_type_name(database, tables, argument),
                None => Ok("i4".to_string()),
            },
        },
        ResolvedExpr::ScalarQuery(query) => Ok(query
            .columns
            .first()
            .map(|column| column.type_name.clone())
            .unwrap_or_else(|| "s0".to_string())),
        _ => Ok("s0".to_string()),
    }
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
    let _ = database;
    if let Some(qualifier) = qualifier {
        let table_index = resolve_table_index(qualifier, tables)?;
        if table_index >= limit {
            return Err(ERROR_UNKNOWN_TABLE);
        }
        let table = tables.get(table_index).ok_or(ERROR_INVALID_TABLE)?;
        let column_index = table
            .columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
            .ok_or(ERROR_BAD_COLUMN)?;
        return Ok((table_index, column_index));
    }
    let mut found = None;
    for table_index in 0..limit.min(tables.len()) {
        let table = tables.get(table_index).ok_or(ERROR_INVALID_TABLE)?;
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
    let _ = database;
    let meta = tables.get(table).ok_or(ERROR_BAD_QUERY_SYNTAX)?;
    let column = meta.columns.get(column).ok_or(ERROR_BAD_COLUMN)?;
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
        ResolvedExpr::OuterColumn { kind, .. } => Ok(Some(*kind)),
        ResolvedExpr::Unary { .. } | ResolvedExpr::Binary { .. } => Ok(Some(SqlColumnKind::Int)),
        ResolvedExpr::Exists { .. } => Ok(Some(SqlColumnKind::Int)),
        ResolvedExpr::Function { function, .. } => Ok(Some(match function {
            SqlFunction::Length => SqlColumnKind::Int,
            SqlFunction::Upper | SqlFunction::Lower | SqlFunction::Substring => {
                SqlColumnKind::String { width: 0 }
            }
        })),
        ResolvedExpr::Literal(MsiValue::Int(_)) => Ok(Some(SqlColumnKind::Int)),
        ResolvedExpr::Literal(MsiValue::Str(_)) => Ok(Some(SqlColumnKind::String { width: 0 })),
        ResolvedExpr::Literal(MsiValue::Stream(_)) => Ok(Some(SqlColumnKind::Binary)),
        ResolvedExpr::Aggregate {
            function, argument, ..
        } => match function {
            SqlAggregate::Count | SqlAggregate::Sum | SqlAggregate::Average => {
                Ok(Some(SqlColumnKind::Int))
            }
            SqlAggregate::Min | SqlAggregate::Max => match argument.as_deref() {
                Some(argument) => resolved_column_kind(database, tables, argument),
                None => Ok(None),
            },
        },
        ResolvedExpr::ScalarQuery(query) => Ok(query
            .columns
            .first()
            .and_then(|column| type_kind(&column.type_name))),
        _ => Ok(None),
    }
}

fn kinds_compatible(left: SqlColumnKind, right: SqlColumnKind) -> bool {
    matches!(
        (left, right),
        (SqlColumnKind::Int, SqlColumnKind::Int)
            | (SqlColumnKind::String { .. }, SqlColumnKind::String { .. })
            | (SqlColumnKind::Binary, SqlColumnKind::Binary)
    )
}

fn coerce_against(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    operand: &mut ResolvedExpr,
    kind: SqlColumnKind,
    expectations: &mut [ParameterExpectation],
) -> Result<(), u32> {
    if let Some(existing) = resolved_column_kind(database, tables, operand)? {
        if kinds_compatible(existing, kind) {
            return Ok(());
        }
        if matches!(
            operand,
            ResolvedExpr::Literal(_) | ResolvedExpr::Parameter(_)
        ) {
            return coerce_operand(operand, kind, expectations);
        }
        return Err(ERROR_BAD_QUERY_SYNTAX);
    }
    coerce_operand(operand, kind, expectations)
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

fn resolve_outer_column(
    outer: &[&[ResolvedTable]],
    qualifier: Option<&str>,
    name: &str,
) -> Result<ResolvedExpr, u32> {
    for (depth, scope) in outer.iter().enumerate() {
        let Some((table, column)) = column_candidate(scope, qualifier, name)? else {
            continue;
        };
        let kind = scope
            .get(table)
            .and_then(|meta| meta.columns.get(column))
            .map(msi_column_kind)
            .ok_or(ERROR_BAD_COLUMN)?;
        return Ok(ResolvedExpr::OuterColumn {
            level: depth + 1,
            table,
            column,
            kind,
        });
    }
    Err(if qualifier.is_some() {
        ERROR_UNKNOWN_TABLE
    } else {
        ERROR_BAD_COLUMN
    })
}

fn column_candidate(
    tables: &[ResolvedTable],
    qualifier: Option<&str>,
    name: &str,
) -> Result<Option<(usize, usize)>, u32> {
    if let Some(qualifier) = qualifier {
        let Some(table_index) = tables.iter().position(|table| {
            table.name.eq_ignore_ascii_case(qualifier)
                || table
                    .alias
                    .as_deref()
                    .is_some_and(|alias| alias.eq_ignore_ascii_case(qualifier))
        }) else {
            return Ok(None);
        };
        let table = tables.get(table_index).ok_or(ERROR_INVALID_TABLE)?;
        let column = table
            .columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
            .ok_or(ERROR_BAD_COLUMN)?;
        return Ok(Some((table_index, column)));
    }
    let mut found = None;
    for (table_index, table) in tables.iter().enumerate() {
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
    Ok(found)
}

fn msi_column_kind(column: &MsiColumn) -> SqlColumnKind {
    if column.is_binary() {
        SqlColumnKind::Binary
    } else if column.is_string() {
        SqlColumnKind::String {
            width: column.width(),
        }
    } else {
        SqlColumnKind::Int
    }
}

fn resolve_expr(
    database: &MsiDatabaseState,
    tables: &[ResolvedTable],
    expression: &SqlExpr,
    limit: usize,
    expectations: &mut [ParameterExpectation],
    aliases: &[(String, ResolvedExpr)],
    outer: &[&[ResolvedTable]],
) -> Result<ResolvedExpr, u32> {
    match expression {
        SqlExpr::Column { table, name } => {
            if table.is_none() {
                if let Some((_, alias)) = aliases
                    .iter()
                    .find(|(alias, _)| alias.eq_ignore_ascii_case(name))
                {
                    return Ok(alias.clone());
                }
            }
            match column_candidate(&tables[..limit.min(tables.len())], table.as_deref(), name)? {
                Some((table, column)) => Ok(ResolvedExpr::Column { table, column }),
                None => resolve_outer_column(outer, table.as_deref(), name),
            }
        }
        SqlExpr::Literal(value) => Ok(ResolvedExpr::Literal(value.clone())),
        SqlExpr::Parameter(index) => {
            if *index >= expectations.len() {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
            Ok(ResolvedExpr::Parameter(*index))
        }
        SqlExpr::IsNull { value, negated } => {
            let value = resolve_expr(database, tables, value, limit, expectations, aliases, outer)?;
            Ok(ResolvedExpr::IsNull {
                value: Box::new(value),
                negated: *negated,
            })
        }
        SqlExpr::Compare { left, op, right } => {
            let mut left =
                resolve_expr(database, tables, left, limit, expectations, aliases, outer)?;
            let mut right =
                resolve_expr(database, tables, right, limit, expectations, aliases, outer)?;
            let left_kind = resolved_column_kind(database, tables, &left)?;
            let right_kind = resolved_column_kind(database, tables, &right)?;
            match (left_kind, right_kind) {
                (Some(SqlColumnKind::Binary), _) | (_, Some(SqlColumnKind::Binary)) => {
                    return Err(ERROR_BAD_QUERY_SYNTAX);
                }
                (Some(left_kind), Some(right_kind)) if kinds_compatible(left_kind, right_kind) => {}
                (Some(left_kind), Some(right_kind)) => {
                    if matches!(right, ResolvedExpr::Literal(_) | ResolvedExpr::Parameter(_)) {
                        coerce_operand(&mut right, left_kind, expectations)?;
                    } else if matches!(left, ResolvedExpr::Literal(_) | ResolvedExpr::Parameter(_))
                    {
                        coerce_operand(&mut left, right_kind, expectations)?;
                    } else {
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
            Box::new(resolve_expr(
                database,
                tables,
                left,
                limit,
                expectations,
                aliases,
                outer,
            )?),
            Box::new(resolve_expr(
                database,
                tables,
                right,
                limit,
                expectations,
                aliases,
                outer,
            )?),
        )),
        SqlExpr::Or(left, right) => Ok(ResolvedExpr::Or(
            Box::new(resolve_expr(
                database,
                tables,
                left,
                limit,
                expectations,
                aliases,
                outer,
            )?),
            Box::new(resolve_expr(
                database,
                tables,
                right,
                limit,
                expectations,
                aliases,
                outer,
            )?),
        )),
        SqlExpr::Not(inner) => Ok(ResolvedExpr::Not(Box::new(resolve_expr(
            database,
            tables,
            inner,
            limit,
            expectations,
            aliases,
            outer,
        )?))),
        SqlExpr::Like {
            value,
            pattern,
            escape,
            negated,
        } => {
            let value = resolve_expr(database, tables, value, limit, expectations, aliases, outer)?;
            let mut pattern = resolve_expr(
                database,
                tables,
                pattern,
                limit,
                expectations,
                aliases,
                outer,
            )?;
            match resolved_column_kind(database, tables, &value)? {
                Some(SqlColumnKind::String { .. }) | None => {}
                Some(_) => return Err(ERROR_BAD_QUERY_SYNTAX),
            }
            match resolved_column_kind(database, tables, &pattern)? {
                Some(SqlColumnKind::String { .. }) => {}
                Some(_) => return Err(ERROR_BAD_QUERY_SYNTAX),
                None => {
                    coerce_operand(
                        &mut pattern,
                        SqlColumnKind::String { width: 0 },
                        expectations,
                    )?;
                }
            }
            Ok(ResolvedExpr::Like {
                value: Box::new(value),
                pattern: Box::new(pattern),
                escape: *escape,
                negated: *negated,
            })
        }
        SqlExpr::Between {
            value,
            low,
            high,
            negated,
        } => {
            let mut value =
                resolve_expr(database, tables, value, limit, expectations, aliases, outer)?;
            let mut low = resolve_expr(database, tables, low, limit, expectations, aliases, outer)?;
            let mut high =
                resolve_expr(database, tables, high, limit, expectations, aliases, outer)?;
            let kind = resolved_column_kind(database, tables, &value)?
                .or(resolved_column_kind(database, tables, &low)?)
                .or(resolved_column_kind(database, tables, &high)?);
            if let Some(kind) = kind {
                if kind == SqlColumnKind::Binary {
                    return Err(ERROR_BAD_QUERY_SYNTAX);
                }
                coerce_against(database, tables, &mut value, kind, expectations)?;
                coerce_against(database, tables, &mut low, kind, expectations)?;
                coerce_against(database, tables, &mut high, kind, expectations)?;
            }
            Ok(ResolvedExpr::Between {
                value: Box::new(value),
                low: Box::new(low),
                high: Box::new(high),
                negated: *negated,
            })
        }
        SqlExpr::InList {
            value,
            items,
            negated,
        } => {
            let mut value =
                resolve_expr(database, tables, value, limit, expectations, aliases, outer)?;
            let mut resolved_items = Vec::with_capacity(items.len());
            for item in items {
                resolved_items.push(resolve_expr(
                    database,
                    tables,
                    item,
                    limit,
                    expectations,
                    aliases,
                    outer,
                )?);
            }
            let mut kind = resolved_column_kind(database, tables, &value)?;
            if kind.is_none() {
                for item in &resolved_items {
                    kind = resolved_column_kind(database, tables, item)?;
                    if kind.is_some() {
                        break;
                    }
                }
            }
            if let Some(kind) = kind {
                if kind == SqlColumnKind::Binary {
                    return Err(ERROR_BAD_QUERY_SYNTAX);
                }
                coerce_against(database, tables, &mut value, kind, expectations)?;
                for item in &mut resolved_items {
                    coerce_against(database, tables, item, kind, expectations)?;
                }
            }
            Ok(ResolvedExpr::InList {
                value: Box::new(value),
                items: resolved_items,
                negated: *negated,
            })
        }
        SqlExpr::InQuery {
            value,
            query,
            negated,
        } => {
            let mut value =
                resolve_expr(database, tables, value, limit, expectations, aliases, outer)?;
            let mut nested: Vec<&[ResolvedTable]> = Vec::with_capacity(outer.len() + 1);
            nested.push(tables);
            nested.extend_from_slice(outer);
            let resolved = resolve_query_with(database, (**query).clone(), expectations, &nested)?;
            if resolved.columns.len() != 1 {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
            let subquery_kind = type_kind(&resolved.columns[0].type_name);
            match (
                resolved_column_kind(database, tables, &value)?,
                subquery_kind,
            ) {
                (Some(SqlColumnKind::Binary), _) | (_, Some(SqlColumnKind::Binary)) => {
                    return Err(ERROR_BAD_QUERY_SYNTAX);
                }
                (Some(left), Some(right)) if kinds_compatible(left, right) => {}
                (Some(_), Some(_)) => return Err(ERROR_BAD_QUERY_SYNTAX),
                (None, Some(kind)) => coerce_operand(&mut value, kind, expectations)?,
                _ => {}
            }
            Ok(ResolvedExpr::InQuery {
                value: Box::new(value),
                query: Box::new(resolved),
                negated: *negated,
            })
        }
        SqlExpr::ScalarQuery(query) => {
            let mut nested: Vec<&[ResolvedTable]> = Vec::with_capacity(outer.len() + 1);
            nested.push(tables);
            nested.extend_from_slice(outer);
            let resolved = resolve_query_with(database, (**query).clone(), expectations, &nested)?;
            if resolved.columns.len() != 1 {
                return Err(ERROR_BAD_QUERY_SYNTAX);
            }
            Ok(ResolvedExpr::ScalarQuery(Box::new(resolved)))
        }
        SqlExpr::Exists { query, negated } => {
            let mut nested: Vec<&[ResolvedTable]> = Vec::with_capacity(outer.len() + 1);
            nested.push(tables);
            nested.extend_from_slice(outer);
            let resolved = resolve_query_with(database, (**query).clone(), expectations, &nested)?;
            Ok(ResolvedExpr::Exists {
                query: Box::new(resolved),
                negated: *negated,
            })
        }
        SqlExpr::Unary { op, value } => {
            let mut value =
                resolve_expr(database, tables, value, limit, expectations, aliases, outer)?;
            coerce_against(
                database,
                tables,
                &mut value,
                SqlColumnKind::Int,
                expectations,
            )?;
            Ok(ResolvedExpr::Unary {
                op: *op,
                value: Box::new(value),
            })
        }
        SqlExpr::Binary { op, left, right } => {
            let mut left =
                resolve_expr(database, tables, left, limit, expectations, aliases, outer)?;
            let mut right =
                resolve_expr(database, tables, right, limit, expectations, aliases, outer)?;
            coerce_against(
                database,
                tables,
                &mut left,
                SqlColumnKind::Int,
                expectations,
            )?;
            coerce_against(
                database,
                tables,
                &mut right,
                SqlColumnKind::Int,
                expectations,
            )?;
            Ok(ResolvedExpr::Binary {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
            })
        }
        SqlExpr::Function {
            function,
            arguments,
        } => {
            let mut resolved = Vec::with_capacity(arguments.len());
            for argument in arguments {
                resolved.push(resolve_expr(
                    database,
                    tables,
                    argument,
                    limit,
                    expectations,
                    aliases,
                    outer,
                )?);
            }
            match function {
                SqlFunction::Upper | SqlFunction::Lower | SqlFunction::Length => {
                    if let Some(argument) = resolved.first_mut() {
                        coerce_against(
                            database,
                            tables,
                            argument,
                            SqlColumnKind::String { width: 0 },
                            expectations,
                        )?;
                    }
                }
                SqlFunction::Substring => {
                    if let Some(argument) = resolved.first_mut() {
                        coerce_against(
                            database,
                            tables,
                            argument,
                            SqlColumnKind::String { width: 0 },
                            expectations,
                        )?;
                    }
                    for argument in resolved.iter_mut().skip(1) {
                        coerce_against(
                            database,
                            tables,
                            argument,
                            SqlColumnKind::Int,
                            expectations,
                        )?;
                    }
                }
            }
            Ok(ResolvedExpr::Function {
                function: *function,
                arguments: resolved,
            })
        }
        SqlExpr::Aggregate {
            function,
            argument,
            distinct,
        } => {
            let argument = match argument {
                Some(argument) => {
                    let resolved = resolve_expr(
                        database,
                        tables,
                        argument,
                        limit,
                        expectations,
                        aliases,
                        outer,
                    )?;
                    if contains_resolved_aggregate(&resolved) {
                        return Err(ERROR_BAD_QUERY_SYNTAX);
                    }
                    Some(Box::new(resolved))
                }
                None => None,
            };
            Ok(ResolvedExpr::Aggregate {
                function: *function,
                argument,
                distinct: *distinct,
            })
        }
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

/// One node in a compound-file storage tree.  `children` preserves element
/// order so storage enumeration round-trips through a commit.
#[derive(Debug, Clone, Default)]
pub(crate) struct CompoundTree {
    pub(crate) name: String,
    pub(crate) clsid: Option<[u8; 16]>,
    pub(crate) created: u64,
    pub(crate) modified: u64,
    pub(crate) children: Vec<CompoundTreeChild>,
}

#[derive(Debug, Clone)]
pub(crate) enum CompoundTreeChild {
    Stream {
        name: String,
        data: Vec<u8>,
        created: u64,
        modified: u64,
    },
    Storage(CompoundTree),
}

impl CompoundTree {
    pub(crate) fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub(crate) fn stream(name: &str, data: Vec<u8>) -> CompoundTreeChild {
        CompoundTreeChild::Stream {
            name: name.to_string(),
            data,
            created: 0,
            modified: 0,
        }
    }
}

/// Write a flat CFB v3 compound file (a root storage holding `streams`).
pub(crate) fn write_compound_file(streams: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut root = CompoundTree::new("Root Entry");
    root.children = streams
        .iter()
        .map(|(name, data)| CompoundTree::stream(name, data.clone()))
        .collect();
    write_compound_tree(&root)
}

/// Write a CFB v3 compound file with a real storage tree.  Streams shorter
/// than 4096 bytes go into the mini stream (miniFAT); larger ones get regular
/// FAT chains; the FAT itself spills into DIFAT sectors past 109 FAT sectors.
pub(crate) fn write_compound_tree(root: &CompoundTree) -> Vec<u8> {
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
    fn collect_stream_data<'a>(node: &'a CompoundTree, out: &mut Vec<&'a [u8]>) {
        for child in &node.children {
            match child {
                CompoundTreeChild::Stream { data, .. } => out.push(data.as_slice()),
                CompoundTreeChild::Storage(storage) => collect_stream_data(storage, out),
            }
        }
    }

    fn count_nodes(node: &CompoundTree) -> usize {
        let mut count = 1usize;
        for child in &node.children {
            count += match child {
                CompoundTreeChild::Stream { .. } => 1,
                CompoundTreeChild::Storage(storage) => count_nodes(storage),
            };
        }
        count
    }

    let mut stream_data = Vec::new();
    collect_stream_data(root, &mut stream_data);
    let mut layouts = Vec::with_capacity(stream_data.len());
    for data in &stream_data {
        let data = *data;
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

    let entry_count = count_nodes(root);
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

    struct DirectoryRecord {
        name: String,
        kind: u8,
        clsid: Option<[u8; 16]>,
        created: u64,
        modified: u64,
        start: u32,
        size: u64,
        child: u32,
        right: u32,
    }

    fn flatten_tree(
        node: &CompoundTree,
        layouts: &[Layout],
        cursor: &mut usize,
        out: &mut Vec<DirectoryRecord>,
    ) -> usize {
        let index = out.len();
        out.push(DirectoryRecord {
            name: node.name.clone(),
            kind: 1,
            clsid: node.clsid,
            created: node.created,
            modified: node.modified,
            start: ENDOFCHAIN,
            size: 0,
            child: NOSTREAM,
            right: NOSTREAM,
        });
        let mut previous: Option<usize> = None;
        for child in &node.children {
            let child_index = match child {
                CompoundTreeChild::Stream {
                    name,
                    data,
                    created,
                    modified,
                } => {
                    let (start, size) = match layouts.get(*cursor) {
                        Some(Layout::Mini(start)) | Some(Layout::Big(start)) => {
                            (*start, data.len() as u64)
                        }
                        None => (ENDOFCHAIN, data.len() as u64),
                    };
                    *cursor += 1;
                    out.push(DirectoryRecord {
                        name: name.clone(),
                        kind: 2,
                        clsid: None,
                        created: *created,
                        modified: *modified,
                        start,
                        size,
                        child: NOSTREAM,
                        right: NOSTREAM,
                    });
                    out.len() - 1
                }
                CompoundTreeChild::Storage(storage) => flatten_tree(storage, layouts, cursor, out),
            };
            if let Some(previous) = previous {
                out[previous].right = child_index as u32;
            } else {
                out[index].child = child_index as u32;
            }
            previous = Some(child_index);
        }
        index
    }

    let mut records = Vec::with_capacity(entry_count);
    let mut stream_cursor = 0usize;
    flatten_tree(root, &layouts, &mut stream_cursor, &mut records);
    if let Some(root_record) = records.first_mut() {
        root_record.name = "Root Entry".to_string();
        root_record.kind = 5;
        root_record.start = mini_start;
        root_record.size = mini_size;
    }
    let mut directory = Vec::with_capacity(dir_sector_count * SECTOR);
    for record in &records {
        push_directory_entry(
            &mut directory,
            &record.name,
            record.kind,
            NOSTREAM,
            record.right,
            record.child,
            record.start,
            record.size,
            record.clsid.as_ref(),
            record.created,
            record.modified,
        );
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

#[allow(clippy::too_many_arguments)]
fn push_directory_entry(
    out: &mut Vec<u8>,
    name: &str,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
    clsid: Option<&[u8; 16]>,
    created: u64,
    modified: u64,
) {
    let units: Vec<u16> = name.encode_utf16().take(31).collect();
    let mut entry = vec![0u8; 128];
    for (index, unit) in units.iter().enumerate() {
        entry[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    entry[0x40..0x42].copy_from_slice(&(((units.len() + 1) * 2) as u16).to_le_bytes());
    entry[0x42] = kind;
    entry[0x43] = 1;
    entry[0x44..0x48].copy_from_slice(&left.to_le_bytes());
    entry[0x48..0x4C].copy_from_slice(&right.to_le_bytes());
    entry[0x4C..0x50].copy_from_slice(&child.to_le_bytes());
    if let Some(clsid) = clsid {
        entry[0x50..0x60].copy_from_slice(clsid);
    }
    entry[0x64..0x6C].copy_from_slice(&created.to_le_bytes());
    entry[0x6C..0x74].copy_from_slice(&modified.to_le_bytes());
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
            "Doc".to_string(),
            MsiTable {
                name: "Doc".to_string(),
                columns: vec![column("DocId", S32_KEY), column("Body", S64)],
                rows: vec![
                    vec![
                        MsiValue::Str("d1".to_string()),
                        MsiValue::Str("100%".to_string()),
                    ],
                    vec![
                        MsiValue::Str("d2".to_string()),
                        MsiValue::Str("a_b".to_string()),
                    ],
                    vec![
                        MsiValue::Str("d3".to_string()),
                        MsiValue::Str("abc".to_string()),
                    ],
                ],
            },
        );
        database.tables.insert(
            "Label".to_string(),
            MsiTable {
                name: "Label".to_string(),
                columns: vec![column("LabelId", S32_KEY), column("Text", S64)],
                rows: vec![
                    vec![
                        MsiValue::Str("L1".to_string()),
                        MsiValue::Str("Äpfel".to_string()),
                    ],
                    vec![
                        MsiValue::Str("L2".to_string()),
                        MsiValue::Str("ÉCLAIR".to_string()),
                    ],
                    vec![
                        MsiValue::Str("L3".to_string()),
                        MsiValue::Str("straße".to_string()),
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
    fn msi_sql_correlated_subqueries_and_derived_tables() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-correlated");
            let (db, _path) = open_fixture(&mut fixture, "correlated.msi", &relational_compound());

            for (sql, fields, expected) in [
                (
                    "SELECT p.Name, (SELECT COUNT(*) FROM Feature f \
                     WHERE f.ProductCode = p.ProductCode) AS Cnt \
                     FROM Product p ORDER BY p.Name",
                    2,
                    vec![
                        vec!["Alpha".to_string(), "2".to_string()],
                        vec!["Beta".to_string(), "2".to_string()],
                        vec!["Gamma".to_string(), "0".to_string()],
                    ],
                ),
                (
                    "SELECT p.Name FROM Product p WHERE p.Price > \
                     (SELECT AVG(f.Weight) FROM Feature f \
                      WHERE f.ProductCode = p.ProductCode) ORDER BY p.Name",
                    1,
                    vec![vec!["Alpha".to_string()], vec!["Beta".to_string()]],
                ),
                (
                    "SELECT p.Name FROM Product p WHERE EXISTS \
                     (SELECT 1 FROM Feature f WHERE f.ProductCode = p.ProductCode \
                      AND f.Weight >= 10) ORDER BY p.Name",
                    1,
                    vec![vec!["Alpha".to_string()]],
                ),
                (
                    "SELECT p.Name FROM Product p WHERE NOT EXISTS \
                     (SELECT 1 FROM Feature f WHERE f.ProductCode = p.ProductCode) \
                     ORDER BY p.Name",
                    1,
                    vec![vec!["Gamma".to_string()]],
                ),
                (
                    "SELECT p.Name FROM Product p WHERE p.ProductCode IN \
                     (SELECT f.ProductCode FROM Feature f WHERE f.Weight >= p.Price) \
                     ORDER BY p.Name",
                    1,
                    vec![vec!["Alpha".to_string()]],
                ),
                (
                    "SELECT p.Name FROM Product p WHERE EXISTS \
                     (SELECT 1 FROM Feature f WHERE f.ProductCode = p.ProductCode \
                      AND EXISTS (SELECT 1 FROM Component c \
                                  WHERE c.FeatureId = f.FeatureId AND c.Label = 'third')) \
                     ORDER BY p.Name",
                    1,
                    vec![vec!["Alpha".to_string()]],
                ),
                (
                    "SELECT d.Name, d.Price FROM \
                     (SELECT Name, Price FROM Product WHERE Price >= 10) AS d \
                     WHERE d.Price < 20 ORDER BY d.Name",
                    2,
                    vec![vec!["Alpha".to_string(), "10".to_string()]],
                ),
                (
                    "SELECT d.Code, COUNT(*) AS Cnt FROM \
                     (SELECT ProductCode AS Code FROM Feature WHERE Weight IS NOT NULL) d \
                     GROUP BY d.Code ORDER BY d.Code",
                    2,
                    vec![
                        vec!["P1".to_string(), "2".to_string()],
                        vec!["P2".to_string(), "2".to_string()],
                    ],
                ),
                (
                    "SELECT d.Name, f.Title FROM \
                     (SELECT ProductCode, Name FROM Product) d INNER JOIN Feature f \
                     ON d.ProductCode = f.ProductCode WHERE f.Weight = 10 \
                     ORDER BY d.Name",
                    2,
                    vec![vec!["Alpha".to_string(), "Slow".to_string()]],
                ),
                (
                    "SELECT d.Name FROM (SELECT * FROM Product WHERE Price = 5) d \
                     ORDER BY d.Name",
                    1,
                    vec![vec!["Gamma".to_string()]],
                ),
            ] {
                let view = open_view(&mut fixture, db, sql);
                assert_eq!(execute(&mut fixture, view), OK, "{sql}");
                assert_eq!(collect_rows(&mut fixture, view, fields), expected, "{sql}");
            }

            assert_eq!(
                open_view_error(
                    &mut fixture,
                    db,
                    "SELECT d.Name FROM (SELECT Name FROM Product)"
                ),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
            assert_eq!(
                open_view_error(
                    &mut fixture,
                    db,
                    "SELECT p.Name FROM Product p WHERE EXISTS \
                     (SELECT 1 FROM Feature f WHERE f.Missing = p.ProductCode)"
                ),
                u64::from(ERROR_BAD_COLUMN)
            );
        });
    }

    #[test]
    fn msi_sql_group_ordinals_distinct_aggregates_and_having_subqueries() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-group-depth");
            let (db, _path) = open_fixture(&mut fixture, "groupdepth.msi", &relational_compound());

            let ordinal = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode, COUNT(*) AS Cnt, SUM(Weight) AS Total \
                 FROM Feature GROUP BY 1 ORDER BY 1",
            );
            assert_eq!(execute(&mut fixture, ordinal), OK);
            assert_eq!(
                collect_rows(&mut fixture, ordinal, 3),
                vec![
                    vec!["P1".to_string(), "2".to_string(), "15".to_string()],
                    vec!["P2".to_string(), "2".to_string(), "2".to_string()],
                    vec!["P9".to_string(), "1".to_string(), String::new()],
                ]
            );

            let distinct = open_view(
                &mut fixture,
                db,
                "SELECT COUNT(DISTINCT ProductCode) AS Codes, \
                 COUNT(DISTINCT Weight) AS Weights, \
                 SUM(DISTINCT Weight) AS S, AVG(DISTINCT Weight) AS A FROM Feature",
            );
            assert_eq!(execute(&mut fixture, distinct), OK);
            assert_eq!(
                collect_rows(&mut fixture, distinct, 4),
                vec![vec![
                    "3".to_string(),
                    "3".to_string(),
                    "16".to_string(),
                    "5".to_string(),
                ]]
            );

            let distinct_group = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode, COUNT(DISTINCT Weight) AS Cnt FROM Feature \
                 GROUP BY 1 ORDER BY 1",
            );
            assert_eq!(execute(&mut fixture, distinct_group), OK);
            assert_eq!(
                collect_rows(&mut fixture, distinct_group, 2),
                vec![
                    vec!["P1".to_string(), "2".to_string()],
                    vec!["P2".to_string(), "1".to_string()],
                    vec!["P9".to_string(), "0".to_string()],
                ]
            );

            let having_exists = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode, COUNT(*) AS Cnt FROM Feature GROUP BY ProductCode \
                 HAVING EXISTS (SELECT 1 FROM Product p \
                                WHERE p.ProductCode = Feature.ProductCode) \
                 ORDER BY ProductCode",
            );
            assert_eq!(execute(&mut fixture, having_exists), OK);
            assert_eq!(
                collect_rows(&mut fixture, having_exists, 2),
                vec![
                    vec!["P1".to_string(), "2".to_string()],
                    vec!["P2".to_string(), "2".to_string()],
                ]
            );

            let having_scalar = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode, COUNT(*) AS Cnt FROM Feature GROUP BY ProductCode \
                 HAVING COUNT(*) > (SELECT COUNT(*) FROM Product WHERE Price < 10) \
                 ORDER BY ProductCode",
            );
            assert_eq!(execute(&mut fixture, having_scalar), OK);
            assert_eq!(
                collect_rows(&mut fixture, having_scalar, 2),
                vec![
                    vec!["P1".to_string(), "2".to_string()],
                    vec!["P2".to_string(), "2".to_string()],
                ]
            );

            let aggregate_arithmetic = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode, SUM(Weight) + COUNT(*) AS X FROM Feature \
                 GROUP BY 1 ORDER BY 1",
            );
            assert_eq!(execute(&mut fixture, aggregate_arithmetic), OK);
            assert_eq!(
                collect_rows(&mut fixture, aggregate_arithmetic, 2),
                vec![
                    vec!["P1".to_string(), "17".to_string()],
                    vec!["P2".to_string(), "4".to_string()],
                    vec!["P9".to_string(), String::new()],
                ]
            );

            let expression_ordinal = open_view(
                &mut fixture,
                db,
                "SELECT Weight + 1 AS X, COUNT(*) AS Cnt FROM Feature \
                 WHERE Weight IS NOT NULL GROUP BY 1 ORDER BY 1",
            );
            assert_eq!(execute(&mut fixture, expression_ordinal), OK);
            assert_eq!(
                collect_rows(&mut fixture, expression_ordinal, 2),
                vec![
                    vec!["2".to_string(), "2".to_string()],
                    vec!["6".to_string(), "1".to_string()],
                    vec!["11".to_string(), "1".to_string()],
                ]
            );

            assert_eq!(
                open_view_error(
                    &mut fixture,
                    db,
                    "SELECT ProductCode, COUNT(*) FROM Feature GROUP BY 2"
                ),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
            assert_eq!(
                open_view_error(
                    &mut fixture,
                    db,
                    "SELECT ProductCode, COUNT(*) FROM Feature GROUP BY 0"
                ),
                u64::from(ERROR_BAD_COLUMN)
            );
        });
    }

    #[test]
    fn msi_sql_joined_view_modify_targets_one_table_or_errors() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-joined-modify");
            let (db, _path) =
                open_fixture(&mut fixture, "joinedmodify.msi", &relational_compound());

            let view = open_view(
                &mut fixture,
                db,
                "SELECT f.FeatureId, f.Title FROM Feature f INNER JOIN Product p \
                 ON p.ProductCode = f.ProductCode ORDER BY f.FeatureId",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            let (result, update) = fetch(&mut fixture, view);
            assert_eq!(result, OK);
            set_record_text(&mut fixture, update, 2, "Joined");
            assert_eq!(modify(&mut fixture, view, 2, update), OK);

            let check = open_view(
                &mut fixture,
                db,
                "SELECT Title FROM Feature WHERE FeatureId = 1",
            );
            assert_eq!(execute(&mut fixture, check), OK);
            assert_eq!(
                collect_rows(&mut fixture, check, 1),
                vec![vec!["Joined".to_string()]]
            );

            let ambiguous = open_view(
                &mut fixture,
                db,
                "SELECT p.Name, f.Title FROM Product p INNER JOIN Feature f \
                 ON p.ProductCode = f.ProductCode",
            );
            assert_eq!(execute(&mut fixture, ambiguous), OK);
            let record = new_record(&mut fixture, 1);
            set_record_int(&mut fixture, record, 0, 1);
            assert_eq!(modify(&mut fixture, ambiguous, 2, record), FUNCTION_FAILED);

            let derived = open_view(
                &mut fixture,
                db,
                "SELECT d.Name FROM (SELECT Name FROM Product) d",
            );
            assert_eq!(execute(&mut fixture, derived), OK);
            let record = new_record(&mut fixture, 1);
            set_record_int(&mut fixture, record, 0, 1);
            assert_eq!(modify(&mut fixture, derived, 2, record), FUNCTION_FAILED);
        });
    }

    #[test]
    fn msi_sql_extended_error_matrix() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-errors-ext");
            let (db, _path) = open_fixture(&mut fixture, "errorsext.msi", &relational_compound());

            for (sql, expected) in [
                ("SELECT Name, COUNT(*) FROM Product", ERROR_BAD_QUERY_SYNTAX),
                (
                    "SELECT Name, SUM(Price) FROM Product",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT Name, COUNT(*) FROM Product HAVING COUNT(*) > 1",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT Name FROM Product WHERE COUNT(*) > 1",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT COUNT(*) FROM Feature HAVING Weight > 1",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT COUNT(*) FROM Feature ORDER BY Weight",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT COUNT(SUM(Weight)) FROM Feature",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT ProductCode, COUNT(*) AS Cnt FROM Feature GROUP BY ProductCode \
                     HAVING Missing > 1",
                    ERROR_BAD_COLUMN,
                ),
                (
                    "SELECT ProductCode, COUNT(*) AS Cnt FROM Feature GROUP BY ProductCode \
                     ORDER BY Missing",
                    ERROR_BAD_COLUMN,
                ),
                (
                    "SELECT ProductCode FROM Feature GROUP BY Missing",
                    ERROR_BAD_COLUMN,
                ),
                ("SELECT Name FROM Product ORDER BY 5", ERROR_BAD_COLUMN),
                (
                    "SELECT Name FROM Product UNION SELECT FeatureId FROM Feature",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT ProductCode FROM Product UNION \
                     SELECT FeatureId, ProductCode FROM Feature",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT Name FROM Product WHERE Price = \
                     (SELECT FeatureId, Weight FROM Feature)",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT Name FROM Product WHERE ProductCode IN \
                     (SELECT ProductCode, Title FROM Feature)",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
                (
                    "SELECT Name FROM Product WHERE Price IN (SELECT ProductCode FROM Feature)",
                    ERROR_BAD_QUERY_SYNTAX,
                ),
            ] {
                assert_eq!(
                    open_view_error(&mut fixture, db, sql),
                    u64::from(expected),
                    "{sql}"
                );
            }

            let valid = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode, COUNT(*) AS Cnt FROM Feature GROUP BY ProductCode \
                 HAVING COUNT(*) >= 1 ORDER BY ProductCode",
            );
            assert_eq!(execute(&mut fixture, valid), OK);
            assert_eq!(
                collect_rows(&mut fixture, valid, 2),
                vec![
                    vec!["P1".to_string(), "2".to_string()],
                    vec!["P2".to_string(), "2".to_string()],
                    vec!["P9".to_string(), "1".to_string()],
                ]
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

    #[test]
    fn msi_compound_stream_entry_lookup_edges() {
        let compound = CompoundFile::parse(fixture_compound()).expect("parse fixture compound");
        assert_eq!(
            compound
                .stream_entry_at("TestTable")
                .map(|entry| entry.kind),
            Some(2)
        );
        assert_eq!(
            compound
                .stream_entry_at("TestTable.Alpha")
                .map(|entry| entry.kind),
            Some(2)
        );
        assert_eq!(
            compound
                .stream_entry_at("Root Entry")
                .map(|entry| entry.kind),
            None
        );
        assert_eq!(
            compound.stream_entry_at("Missing").map(|entry| entry.kind),
            None
        );
        assert_eq!(
            column_from_type_name("Data", "v0").type_bits,
            MSITYPE_VALID | MSITYPE_STRING
        );
        assert_eq!(
            column_from_type_name("Data", "unknown").type_bits,
            MSITYPE_VALID | MSITYPE_STRING
        );
    }

    #[test]
    fn msi_internal_expression_error_edges() {
        let mut database = MsiDatabaseState::empty(String::new());
        database.tables.insert(
            "T".to_string(),
            MsiTable {
                name: "T".to_string(),
                columns: vec![column("A", I2), column("B", S64)],
                rows: vec![
                    vec![MsiValue::Int(1), MsiValue::Str("one".to_string())],
                    vec![MsiValue::Int(2), MsiValue::Str("two".to_string())],
                ],
            },
        );
        database.tables.insert(
            "U".to_string(),
            MsiTable {
                name: "U".to_string(),
                columns: vec![column("A", I2)],
                rows: vec![vec![MsiValue::Int(1)]],
            },
        );
        let query = resolve_query(&database, parse_select("SELECT A, B FROM T").unwrap()).unwrap();
        let derived = vec![None; query.tables.len()];
        let tables = query.tables.clone();

        assert_eq!(
            eval_value(
                &database,
                &query,
                &[],
                &[],
                None,
                &ResolvedExpr::OuterColumn {
                    level: 9,
                    table: 0,
                    column: 0,
                    kind: SqlColumnKind::Int,
                },
                &derived,
                &[]
            ),
            Ok(MsiValue::Null)
        );
        assert_eq!(
            eval_value(
                &database,
                &query,
                &[],
                &[],
                None,
                &ResolvedExpr::ScalarQuery(Box::new(query.clone())),
                &derived,
                &[]
            ),
            Err(ERROR_FUNCTION_FAILED)
        );
        assert_eq!(
            eval_value(
                &database,
                &query,
                &[],
                &[],
                None,
                &ResolvedExpr::Unary {
                    op: SqlUnaryOp::Negate,
                    value: Box::new(ResolvedExpr::Literal(MsiValue::Int(5))),
                },
                &derived,
                &[]
            ),
            Ok(MsiValue::Int(-5))
        );
        assert_eq!(
            eval_value(
                &database,
                &query,
                &[],
                &[],
                None,
                &ResolvedExpr::Unary {
                    op: SqlUnaryOp::Plus,
                    value: Box::new(ResolvedExpr::Literal(MsiValue::Int(5))),
                },
                &derived,
                &[]
            ),
            Ok(MsiValue::Int(5))
        );
        assert_eq!(
            eval_value(
                &database,
                &query,
                &[],
                &[],
                None,
                &ResolvedExpr::Unary {
                    op: SqlUnaryOp::Negate,
                    value: Box::new(ResolvedExpr::Literal(MsiValue::Null)),
                },
                &derived,
                &[]
            ),
            Ok(MsiValue::Null)
        );
        assert_eq!(
            eval_value(
                &database,
                &query,
                &[],
                &[],
                None,
                &ResolvedExpr::Unary {
                    op: SqlUnaryOp::Negate,
                    value: Box::new(ResolvedExpr::Literal(MsiValue::Str("x".to_string()))),
                },
                &derived,
                &[]
            ),
            Ok(MsiValue::Null)
        );

        assert_eq!(
            eval_binary(SqlBinaryOp::Subtract, MsiValue::Int(7), MsiValue::Int(4)),
            Ok(MsiValue::Int(3))
        );
        assert_eq!(
            eval_binary(SqlBinaryOp::Multiply, MsiValue::Int(7), MsiValue::Int(4)),
            Ok(MsiValue::Int(28))
        );
        assert_eq!(
            eval_binary(SqlBinaryOp::Divide, MsiValue::Int(7), MsiValue::Int(0)),
            Err(ERROR_FUNCTION_FAILED)
        );
        assert_eq!(
            eval_binary(SqlBinaryOp::Modulo, MsiValue::Int(7), MsiValue::Int(0)),
            Err(ERROR_FUNCTION_FAILED)
        );
        assert_eq!(
            eval_binary(SqlBinaryOp::Divide, MsiValue::Int(7), MsiValue::Int(2)),
            Ok(MsiValue::Int(3))
        );
        assert_eq!(
            eval_binary(SqlBinaryOp::Modulo, MsiValue::Int(7), MsiValue::Int(2)),
            Ok(MsiValue::Int(1))
        );

        assert_eq!(
            eval_function(SqlFunction::Upper, vec![MsiValue::Str("ab".to_string())]),
            Ok(MsiValue::Str("AB".to_string()))
        );
        assert_eq!(
            eval_function(SqlFunction::Lower, vec![MsiValue::Str("AB".to_string())]),
            Ok(MsiValue::Str("ab".to_string()))
        );
        assert_eq!(
            eval_function(SqlFunction::Length, vec![MsiValue::Str("hé".to_string())]),
            Ok(MsiValue::Int(2))
        );
        assert_eq!(
            eval_function(SqlFunction::Upper, vec![MsiValue::Int(1)]),
            Ok(MsiValue::Null)
        );
        assert_eq!(
            eval_function(
                SqlFunction::Substring,
                vec![MsiValue::Str("abc".to_string())]
            ),
            Ok(MsiValue::Null)
        );
        assert_eq!(
            eval_function(
                SqlFunction::Substring,
                vec![
                    MsiValue::Str("abc".to_string()),
                    MsiValue::Str("1".to_string()),
                    MsiValue::Int(1)
                ]
            ),
            Ok(MsiValue::Null)
        );
        assert_eq!(
            eval_function(
                SqlFunction::Substring,
                vec![
                    MsiValue::Str("abcdef".to_string()),
                    MsiValue::Int(-3),
                    MsiValue::Int(2)
                ]
            ),
            Ok(MsiValue::Str("ab".to_string()))
        );
        assert_eq!(
            eval_function(
                SqlFunction::Substring,
                vec![
                    MsiValue::Str("abcdef".to_string()),
                    MsiValue::Int(2),
                    MsiValue::Int(-1)
                ]
            ),
            Ok(MsiValue::Str(String::new()))
        );

        assert_eq!(
            eval_aggregate(
                &database,
                &query,
                &[],
                None,
                SqlAggregate::Count,
                None,
                false,
                &derived,
                &[]
            ),
            Ok(MsiValue::Null)
        );
        let error_argument = ResolvedExpr::Binary {
            op: SqlBinaryOp::Divide,
            left: Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            right: Box::new(ResolvedExpr::Literal(MsiValue::Int(0))),
        };
        let group = vec![vec![Some(0)]];
        assert_eq!(
            eval_aggregate(
                &database,
                &query,
                &[],
                Some(&group),
                SqlAggregate::Count,
                Some(&error_argument),
                false,
                &derived,
                &[]
            ),
            Err(ERROR_FUNCTION_FAILED)
        );
        assert_eq!(
            eval_aggregate(
                &database,
                &query,
                &[],
                Some(&group),
                SqlAggregate::Sum,
                None,
                false,
                &derived,
                &[]
            ),
            Ok(MsiValue::Null)
        );
        assert_eq!(
            eval_aggregate(
                &database,
                &query,
                &[],
                Some(&group),
                SqlAggregate::Sum,
                Some(&error_argument),
                false,
                &derived,
                &[]
            ),
            Err(ERROR_FUNCTION_FAILED)
        );
        assert_eq!(
            eval_aggregate(
                &database,
                &query,
                &[],
                Some(&group),
                SqlAggregate::Min,
                None,
                false,
                &derived,
                &[]
            ),
            Ok(MsiValue::Null)
        );
        assert_eq!(
            eval_aggregate(
                &database,
                &query,
                &[],
                Some(&group),
                SqlAggregate::Max,
                Some(&error_argument),
                false,
                &derived,
                &[]
            ),
            Err(ERROR_FUNCTION_FAILED)
        );
        assert_eq!(
            eval_aggregate(
                &database,
                &query,
                &[],
                Some(&group),
                SqlAggregate::Min,
                Some(&ResolvedExpr::Literal(MsiValue::Null)),
                false,
                &derived,
                &[]
            ),
            Ok(MsiValue::Null)
        );

        assert_eq!(
            resolved_expression_type_name(
                &database,
                &tables,
                &ResolvedExpr::OuterColumn {
                    level: 1,
                    table: 0,
                    column: 0,
                    kind: SqlColumnKind::Binary,
                }
            ),
            Ok("v0".to_string())
        );
        assert_eq!(
            resolved_expression_type_name(
                &database,
                &tables,
                &ResolvedExpr::OuterColumn {
                    level: 1,
                    table: 0,
                    column: 0,
                    kind: SqlColumnKind::String { width: 32 },
                }
            ),
            Ok("s32".to_string())
        );
        assert_eq!(
            resolved_expression_type_name(
                &database,
                &tables,
                &ResolvedExpr::OuterColumn {
                    level: 1,
                    table: 0,
                    column: 0,
                    kind: SqlColumnKind::Int,
                }
            ),
            Ok("i4".to_string())
        );
        assert_eq!(
            resolved_expression_type_name(
                &database,
                &tables,
                &ResolvedExpr::Exists {
                    query: Box::new(query.clone()),
                    negated: false,
                }
            ),
            Ok("i4".to_string())
        );
        assert_eq!(
            resolved_expression_type_name(
                &database,
                &tables,
                &ResolvedExpr::Function {
                    function: SqlFunction::Length,
                    arguments: Vec::new(),
                }
            ),
            Ok("i4".to_string())
        );
        assert_eq!(
            resolved_expression_type_name(
                &database,
                &tables,
                &ResolvedExpr::Function {
                    function: SqlFunction::Upper,
                    arguments: Vec::new(),
                }
            ),
            Ok("s0".to_string())
        );

        assert_eq!(
            resolved_column_kind(
                &database,
                &tables,
                &ResolvedExpr::Unary {
                    op: SqlUnaryOp::Plus,
                    value: Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
                }
            ),
            Ok(Some(SqlColumnKind::Int))
        );
        assert_eq!(
            resolved_column_kind(
                &database,
                &tables,
                &ResolvedExpr::Exists {
                    query: Box::new(query.clone()),
                    negated: false,
                }
            ),
            Ok(Some(SqlColumnKind::Int))
        );
        assert_eq!(
            resolved_column_kind(
                &database,
                &tables,
                &ResolvedExpr::Function {
                    function: SqlFunction::Length,
                    arguments: Vec::new(),
                }
            ),
            Ok(Some(SqlColumnKind::Int))
        );
        assert_eq!(
            resolved_column_kind(
                &database,
                &tables,
                &ResolvedExpr::Function {
                    function: SqlFunction::Upper,
                    arguments: Vec::new(),
                }
            ),
            Ok(Some(SqlColumnKind::String { width: 0 }))
        );
        assert_eq!(
            msi_column_kind(&column("Data", MSITYPE_VALID | MSITYPE_STRING)),
            SqlColumnKind::Binary
        );

        let aggregate = ResolvedExpr::Aggregate {
            function: SqlAggregate::Count,
            argument: None,
            distinct: false,
        };
        assert!(contains_resolved_aggregate(&aggregate));
        assert!(contains_resolved_aggregate(&ResolvedExpr::Not(Box::new(
            aggregate.clone()
        ))));
        assert!(contains_resolved_aggregate(&ResolvedExpr::Or(
            Box::new(aggregate.clone()),
            Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
        )));
        assert!(contains_resolved_aggregate(&ResolvedExpr::Function {
            function: SqlFunction::Length,
            arguments: vec![aggregate],
        }));

        let outer = ResolvedExpr::OuterColumn {
            level: 1,
            table: 0,
            column: 1,
            kind: SqlColumnKind::Int,
        };
        let column_expr = ResolvedExpr::Column {
            table: 0,
            column: 0,
        };
        assert!(resolved_expressions_match(&column_expr, &column_expr));
        assert!(resolved_expressions_match(&outer, &outer));
        assert!(resolved_expressions_match(
            &ResolvedExpr::Literal(MsiValue::Int(1)),
            &ResolvedExpr::Literal(MsiValue::Int(1))
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::Parameter(0),
            &ResolvedExpr::Parameter(0)
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::IsNull {
                value: Box::new(column_expr.clone()),
                negated: true,
            },
            &ResolvedExpr::IsNull {
                value: Box::new(column_expr.clone()),
                negated: true,
            }
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::Compare {
                left: Box::new(column_expr.clone()),
                op: SqlCompareOp::Eq,
                right: Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            },
            &ResolvedExpr::Compare {
                left: Box::new(column_expr.clone()),
                op: SqlCompareOp::Eq,
                right: Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            }
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::And(Box::new(column_expr.clone()), Box::new(column_expr.clone())),
            &ResolvedExpr::And(Box::new(column_expr.clone()), Box::new(column_expr.clone()))
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::Not(Box::new(column_expr.clone())),
            &ResolvedExpr::Not(Box::new(column_expr.clone()))
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::Unary {
                op: SqlUnaryOp::Negate,
                value: Box::new(column_expr.clone()),
            },
            &ResolvedExpr::Unary {
                op: SqlUnaryOp::Negate,
                value: Box::new(column_expr.clone()),
            }
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::Binary {
                op: SqlBinaryOp::Add,
                left: Box::new(column_expr.clone()),
                right: Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            },
            &ResolvedExpr::Binary {
                op: SqlBinaryOp::Add,
                left: Box::new(column_expr.clone()),
                right: Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            }
        ));
        assert!(resolved_expressions_match(
            &ResolvedExpr::Function {
                function: SqlFunction::Upper,
                arguments: vec![column_expr.clone()],
            },
            &ResolvedExpr::Function {
                function: SqlFunction::Upper,
                arguments: vec![column_expr.clone()],
            }
        ));
        assert!(!resolved_expressions_match(
            &column_expr,
            &ResolvedExpr::Literal(MsiValue::Int(1))
        ));

        assert!(!grouped_expression_valid(
            &ResolvedExpr::IsNull {
                value: Box::new(column_expr.clone()),
                negated: false,
            },
            &[]
        ));
        assert!(!grouped_expression_valid(
            &ResolvedExpr::Not(Box::new(column_expr.clone())),
            &[]
        ));
        assert!(!grouped_expression_valid(
            &ResolvedExpr::Unary {
                op: SqlUnaryOp::Plus,
                value: Box::new(column_expr.clone()),
            },
            &[]
        ));
        assert!(!grouped_expression_valid(
            &ResolvedExpr::Or(
                Box::new(column_expr.clone()),
                Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            ),
            &[]
        ));
        assert!(!grouped_expression_valid(
            &ResolvedExpr::Function {
                function: SqlFunction::Upper,
                arguments: vec![column_expr.clone()],
            },
            &[]
        ));

        assert_eq!(
            join_matches(&database, &query, &[Some(0)], &[], &None, &derived, &[]),
            Ok(true)
        );

        let mut expectations: Vec<ParameterExpectation> = Vec::new();
        assert_eq!(
            resolve_expr(
                &database,
                &tables,
                &SqlExpr::Parameter(0),
                1,
                &mut expectations,
                &[],
                &[]
            )
            .unwrap_err(),
            ERROR_BAD_QUERY_SYNTAX
        );

        let base_query =
            resolve_query(&database, parse_select("SELECT A FROM T").unwrap()).unwrap();
        let mut without_base = database.clone();
        without_base.tables.remove("T");
        assert_eq!(
            execute_query(&without_base, &base_query, &[]).unwrap_err(),
            ERROR_INVALID_TABLE
        );
        let join_query = resolve_query(
            &database,
            parse_select("SELECT T.A FROM T INNER JOIN U ON T.A = U.A").unwrap(),
        )
        .unwrap();
        let mut without_join = database.clone();
        without_join.tables.remove("U");
        assert_eq!(
            execute_query(&without_join, &join_query, &[]).unwrap_err(),
            ERROR_INVALID_TABLE
        );
    }

    #[test]
    fn msi_sql_predicate_and_equation_edge_paths() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-predicate-edges");
            let (db, _path) = open_fixture(&mut fixture, "predicates.msi", &relational_compound());

            let arithmetic = open_view(
                &mut fixture,
                db,
                "SELECT Price - 1, Price * 2, Price / 2, Price % 3, -Price, +Price \
                 FROM Product ORDER BY Price",
            );
            assert_eq!(execute(&mut fixture, arithmetic), OK);
            assert_eq!(
                collect_rows(&mut fixture, arithmetic, 6),
                vec![
                    vec![
                        "4".to_string(),
                        "10".to_string(),
                        "2".to_string(),
                        "2".to_string(),
                        "-5".to_string(),
                        "5".to_string(),
                    ],
                    vec![
                        "9".to_string(),
                        "20".to_string(),
                        "5".to_string(),
                        "1".to_string(),
                        "-10".to_string(),
                        "10".to_string(),
                    ],
                    vec![
                        "19".to_string(),
                        "40".to_string(),
                        "10".to_string(),
                        "2".to_string(),
                        "-20".to_string(),
                        "20".to_string(),
                    ],
                ]
            );

            let grouped_logic = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE (Price = 10) AND \
                 (Name = 'Alpha' OR Name = 'Beta') AND NOT Name = 'Beta' ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, grouped_logic), OK);
            assert_eq!(
                collect_rows(&mut fixture, grouped_logic, 1),
                vec![vec!["Alpha".to_string()]]
            );

            let not_or = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE NOT (Price = 10 OR Price = 20) ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, not_or), OK);
            assert_eq!(
                collect_rows(&mut fixture, not_or, 1),
                vec![vec!["Gamma".to_string()]]
            );

            let like_class = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE Name LIKE '[!A]%' ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, like_class), OK);
            assert_eq!(
                collect_rows(&mut fixture, like_class, 1),
                vec![vec!["Beta".to_string()], vec!["Gamma".to_string()]]
            );

            let like_null = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title LIKE 'F%' ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, like_null), OK);
            assert_eq!(
                collect_rows(&mut fixture, like_null, 1),
                vec![vec!["1".to_string()], vec!["5".to_string()]]
            );

            let not_like = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE Name NOT LIKE 'A%' ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, not_like), OK);
            assert_eq!(
                collect_rows(&mut fixture, not_like, 1),
                vec![vec!["Beta".to_string()], vec!["Gamma".to_string()]]
            );

            let between = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Weight BETWEEN 1 AND 5 ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, between), OK);
            assert_eq!(
                collect_rows(&mut fixture, between, 1),
                vec![
                    vec!["1".to_string()],
                    vec!["3".to_string()],
                    vec!["5".to_string()]
                ]
            );

            let between_null = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title BETWEEN 'A' AND 'Z' \
                 ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, between_null), OK);
            assert_eq!(
                collect_rows(&mut fixture, between_null, 1),
                vec![
                    vec!["1".to_string()],
                    vec!["2".to_string()],
                    vec!["3".to_string()],
                    vec!["5".to_string()]
                ]
            );

            let not_between = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Weight NOT BETWEEN 1 AND 5 \
                 ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, not_between), OK);
            assert_eq!(
                collect_rows(&mut fixture, not_between, 1),
                vec![vec!["2".to_string()]]
            );

            let in_list = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE Price IN (10, 20) ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, in_list), OK);
            assert_eq!(
                collect_rows(&mut fixture, in_list, 1),
                vec![vec!["Alpha".to_string()], vec!["Beta".to_string()]]
            );

            let in_list_null = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title IN ('Fast', 'Slow') \
                 ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, in_list_null), OK);
            assert_eq!(
                collect_rows(&mut fixture, in_list_null, 1),
                vec![
                    vec!["1".to_string()],
                    vec!["2".to_string()],
                    vec!["5".to_string()]
                ]
            );

            let not_in_list = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE Price NOT IN (10) ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, not_in_list), OK);
            assert_eq!(
                collect_rows(&mut fixture, not_in_list, 1),
                vec![vec!["Beta".to_string()], vec!["Gamma".to_string()]]
            );

            let in_query = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE ProductCode IN \
                 (SELECT ProductCode FROM Feature WHERE Weight >= 5) ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, in_query), OK);
            assert_eq!(
                collect_rows(&mut fixture, in_query, 1),
                vec![vec!["Alpha".to_string()]]
            );

            let in_query_null = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title IN \
                 (SELECT Name FROM Product) ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, in_query_null), OK);
            assert!(collect_rows(&mut fixture, in_query_null, 1).is_empty());

            let non_boolean = open_view(&mut fixture, db, "SELECT Name FROM Product WHERE Price");
            assert_eq!(execute(&mut fixture, non_boolean), OK);
            assert!(collect_rows(&mut fixture, non_boolean, 1).is_empty());

            let is_null = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title IS NULL ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, is_null), OK);
            assert_eq!(
                collect_rows(&mut fixture, is_null, 1),
                vec![vec!["4".to_string()]]
            );

            let projected_comparison = open_view(
                &mut fixture,
                db,
                "SELECT Price = 10 FROM Product ORDER BY Price",
            );
            assert_eq!(execute(&mut fixture, projected_comparison), OK);
            assert_eq!(
                collect_rows(&mut fixture, projected_comparison, 1),
                vec![
                    vec![String::new()],
                    vec![String::new()],
                    vec![String::new()]
                ]
            );

            let alias_group = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode AS Code, COUNT(*) AS Cnt FROM Feature \
                 GROUP BY Code ORDER BY Code",
            );
            assert_eq!(execute(&mut fixture, alias_group), OK);
            assert_eq!(
                collect_rows(&mut fixture, alias_group, 2),
                vec![
                    vec!["P1".to_string(), "2".to_string()],
                    vec!["P2".to_string(), "2".to_string()],
                    vec!["P9".to_string(), "1".to_string()]
                ]
            );

            let ordinal_group = open_view(
                &mut fixture,
                db,
                "SELECT ProductCode, COUNT(*) FROM Feature GROUP BY `1` ORDER BY 1",
            );
            assert_eq!(execute(&mut fixture, ordinal_group), OK);
            assert_eq!(
                collect_rows(&mut fixture, ordinal_group, 2),
                vec![
                    vec!["P1".to_string(), "2".to_string()],
                    vec!["P2".to_string(), "2".to_string()],
                    vec!["P9".to_string(), "1".to_string()]
                ]
            );
        });
    }

    #[test]
    fn msi_sql_parser_and_function_error_edges() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-parser-edges");
            let (db, _path) = open_fixture(&mut fixture, "parseredges.msi", &relational_compound());

            for sql in [
                "SELECT d.Name FROM (SELECT Name FROM Product d",
                "SELECT Name FROM Product WHERE EXISTS 1",
                "SELECT Name FROM Product WHERE NOT EXISTS 1",
                "SELECT Name FROM Product WHERE NOT EXISTS (SELECT 1 FROM Feature",
                "SELECT COUNT(DISTINCT *) FROM Product",
                "SELECT UPPER() FROM Product",
                "SELECT SUBSTRING(Name, 1) FROM Product",
                "SELECT FOO(Name) FROM Product",
                "SELECT UPPER(Price) FROM Product",
                "SELECT SUBSTRING(Name, 'x', 2) FROM Product",
            ] {
                assert_eq!(
                    open_view_error(&mut fixture, db, sql),
                    u64::from(ERROR_BAD_QUERY_SYNTAX),
                    "{sql}"
                );
            }

            let not_exists = open_view(
                &mut fixture,
                db,
                "SELECT p.Name FROM Product p WHERE NOT EXISTS \
                 (SELECT 1 FROM Feature f WHERE f.ProductCode = p.ProductCode) \
                 ORDER BY p.Name",
            );
            assert_eq!(execute(&mut fixture, not_exists), OK);
            assert_eq!(
                collect_rows(&mut fixture, not_exists, 1),
                vec![vec!["Gamma".to_string()]]
            );

            let functions = open_view(
                &mut fixture,
                db,
                "SELECT UPPER(Name), LOWER(Name), LENGTH(Name), SUBSTRING(Name, 2, 3) \
                 FROM Product ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, functions), OK);
            assert_eq!(
                collect_rows(&mut fixture, functions, 4),
                vec![
                    vec![
                        "ALPHA".to_string(),
                        "alpha".to_string(),
                        "5".to_string(),
                        "lph".to_string()
                    ],
                    vec![
                        "BETA".to_string(),
                        "beta".to_string(),
                        "4".to_string(),
                        "eta".to_string()
                    ],
                    vec![
                        "GAMMA".to_string(),
                        "gamma".to_string(),
                        "5".to_string(),
                        "amm".to_string()
                    ],
                ]
            );

            let substring_clamps = open_view(
                &mut fixture,
                db,
                "SELECT SUBSTRING(Name, -3, 2), SUBSTRING(Name, 2, -1) \
                 FROM Product ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, substring_clamps), OK);
            assert_eq!(
                collect_rows(&mut fixture, substring_clamps, 2),
                vec![
                    vec!["Al".to_string(), String::new()],
                    vec!["Be".to_string(), String::new()],
                    vec!["Ga".to_string(), String::new()]
                ]
            );
        });
    }

    #[test]
    fn msi_sql_aggregate_and_join_runtime_error_edges() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-aggregate-edges");
            let (db, _path) =
                open_fixture(&mut fixture, "aggregateedges.msi", &relational_compound());

            for sql in [
                "SELECT COUNT(Weight / 0) FROM Feature",
                "SELECT SUM(Weight / 0) FROM Feature",
                "SELECT MAX(Weight / 0) FROM Feature",
                "SELECT COUNT(*) FROM Product GROUP BY Price / 0",
                "SELECT ProductCode, COUNT(*) FROM Feature GROUP BY ProductCode \
                 HAVING COUNT(*) / 0 = 0",
                "SELECT ProductCode, SUM(Weight) / 0 FROM Feature GROUP BY ProductCode",
                "SELECT COUNT(*) FROM Product WHERE Price > 100 \
                 HAVING COUNT(*) / 0 = 0",
                "SELECT COUNT(*) / 0 FROM Product WHERE Price > 100",
                "SELECT Name FROM Product ORDER BY Price / 0",
                "SELECT Name FROM Product WHERE Price = (SELECT Price FROM Product)",
                "SELECT Name FROM Product WHERE Price = 10 UNION ALL \
                 SELECT Name FROM Product WHERE Price / 0 = 1",
                "SELECT p.Name FROM Product p CROSS JOIN Feature f \
                 WHERE p.Price / 0 = 1",
                "SELECT p.Name FROM Product p RIGHT JOIN Feature f \
                 ON p.Price / 0 = f.Weight",
                "SELECT p.Name FROM Product p FULL JOIN Feature f \
                 ON p.Price / 0 = f.Weight",
            ] {
                let view = open_view(&mut fixture, db, sql);
                assert_eq!(
                    execute(&mut fixture, view),
                    u64::from(ERROR_FUNCTION_FAILED),
                    "{sql}"
                );
            }

            let empty_aggregate = open_view(
                &mut fixture,
                db,
                "SELECT COUNT(*) FROM Product WHERE Price > 100 HAVING COUNT(*) = 0",
            );
            assert_eq!(execute(&mut fixture, empty_aggregate), OK);
            assert_eq!(
                collect_rows(&mut fixture, empty_aggregate, 1),
                vec![vec!["0".to_string()]]
            );

            let sum = open_view(&mut fixture, db, "SELECT SUM(Weight) FROM Feature");
            assert_eq!(execute(&mut fixture, sum), OK);
            assert_eq!(
                collect_rows(&mut fixture, sum, 1),
                vec![vec!["17".to_string()]]
            );

            let exists_projection = open_view(
                &mut fixture,
                db,
                "SELECT EXISTS (SELECT 1 FROM Feature) FROM Product",
            );
            assert_eq!(execute(&mut fixture, exists_projection), OK);
            assert_eq!(
                collect_rows(&mut fixture, exists_projection, 1),
                vec![
                    vec!["1".to_string()],
                    vec!["1".to_string()],
                    vec!["1".to_string()]
                ]
            );

            let order_expression = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product ORDER BY Price % 7",
            );
            assert_eq!(execute(&mut fixture, order_expression), OK);
            assert_eq!(
                collect_rows(&mut fixture, order_expression, 1),
                vec![
                    vec!["Alpha".to_string()],
                    vec!["Gamma".to_string()],
                    vec!["Beta".to_string()]
                ]
            );

            let outer_select = open_view(
                &mut fixture,
                db,
                "SELECT p.Name FROM Product p WHERE EXISTS \
                 (SELECT p.Name FROM Feature f WHERE f.ProductCode = p.ProductCode \
                  AND f.Weight = 10) ORDER BY p.Name",
            );
            assert_eq!(execute(&mut fixture, outer_select), OK);
            assert_eq!(
                collect_rows(&mut fixture, outer_select, 1),
                vec![vec!["Alpha".to_string()]]
            );

            let outer_outer = open_view(
                &mut fixture,
                db,
                "SELECT p.Name FROM Product p WHERE EXISTS \
                 (SELECT 1 FROM Feature f WHERE EXISTS \
                  (SELECT 1 FROM Component c WHERE c.FeatureId = f.FeatureId \
                   AND c.Label = p.Name)) ORDER BY p.Name",
            );
            assert_eq!(execute(&mut fixture, outer_outer), OK);
            assert!(collect_rows(&mut fixture, outer_outer, 1).is_empty());

            let mut binary_fixture = x86_fixture("msi-sql-outer-binary");
            let (binary_db, _binary_path) =
                open_fixture(&mut binary_fixture, "outerbinary.msi", &fixture_compound());
            let outer_binary = open_view(
                &mut binary_fixture,
                binary_db,
                "SELECT t.Name FROM TestTable t WHERE EXISTS \
                 (SELECT t.Data FROM TestTable x)",
            );
            assert_eq!(execute(&mut binary_fixture, outer_binary), OK);
            let rows = collect_rows(&mut binary_fixture, outer_binary, 1);
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0], vec!["Alpha".to_string()]);
            assert_eq!(rows[1], vec!["Beta".to_string()]);

            let derived_binary = open_view(
                &mut binary_fixture,
                binary_db,
                "SELECT d.Data FROM (SELECT Data FROM TestTable) d",
            );
            assert_eq!(execute(&mut binary_fixture, derived_binary), OK);
        });
    }

    #[test]
    fn msi_refresh_view_recompute_error_edges() {
        with_big_stack(|| {
            let mut filtered = x86_fixture("msi-refresh-filter");
            let (db, _path) =
                open_fixture(&mut filtered, "refreshfilter.msi", &relational_compound());
            let view = open_view(
                &mut filtered,
                db,
                "SELECT FeatureId FROM Feature WHERE Weight > 5 ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut filtered, view), OK);
            let (result, record) = fetch(&mut filtered, view);
            assert_eq!(result, OK);
            assert_eq!(
                modify(&mut filtered, view, 8, record),
                u64::from(ERROR_SUCCESS)
            );
            filtered
                .runtime
                .msi_databases
                .get_mut(&db)
                .and_then(|database| database.table_mut("Feature"))
                .expect("feature table")
                .rows[1][3] = MsiValue::Int(0);
            assert_eq!(modify(&mut filtered, view, 8, record), NO_MORE_ITEMS);

            let mut failing_filter = x86_fixture("msi-refresh-filter-error");
            let (db, _path) = open_fixture(
                &mut failing_filter,
                "refreshfiltererror.msi",
                &relational_compound(),
            );
            let view = open_view(
                &mut failing_filter,
                db,
                "SELECT FeatureId FROM Feature WHERE 100 / Weight > 5 ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut failing_filter, view), OK);
            let (result, record) = fetch(&mut failing_filter, view);
            assert_eq!(result, OK);
            failing_filter
                .runtime
                .msi_databases
                .get_mut(&db)
                .and_then(|database| database.table_mut("Feature"))
                .expect("feature table")
                .rows[0][3] = MsiValue::Int(0);
            assert_eq!(
                modify(&mut failing_filter, view, 8, record),
                u64::from(ERROR_FUNCTION_FAILED)
            );

            let mut projection = x86_fixture("msi-refresh-projection-error");
            let (db, _path) = open_fixture(
                &mut projection,
                "refreshprojection.msi",
                &relational_compound(),
            );
            let view = open_view(
                &mut projection,
                db,
                "SELECT FeatureId, 100 / Weight FROM Feature ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut projection, view), OK);
            let (result, record) = fetch(&mut projection, view);
            assert_eq!(result, OK);
            projection
                .runtime
                .msi_databases
                .get_mut(&db)
                .and_then(|database| database.table_mut("Feature"))
                .expect("feature table")
                .rows[0][3] = MsiValue::Int(0);
            assert_eq!(
                modify(&mut projection, view, 8, record),
                u64::from(ERROR_FUNCTION_FAILED)
            );

            let mut derived = x86_fixture("msi-refresh-derived-error");
            let (db, _path) =
                open_fixture(&mut derived, "refreshderived.msi", &relational_compound());
            let view = open_view(
                &mut derived,
                db,
                "SELECT f.FeatureId FROM Feature f INNER JOIN \
                 (SELECT FeatureId, 100 / Weight AS X FROM Feature) d \
                 ON d.FeatureId = f.FeatureId ORDER BY f.FeatureId",
            );
            assert_eq!(execute(&mut derived, view), OK);
            let (result, record) = fetch(&mut derived, view);
            assert_eq!(result, OK);
            derived
                .runtime
                .msi_databases
                .get_mut(&db)
                .and_then(|database| database.table_mut("Feature"))
                .expect("feature table")
                .rows[0][3] = MsiValue::Int(0);
            assert_eq!(
                modify(&mut derived, view, 8, record),
                u64::from(ERROR_FUNCTION_FAILED)
            );
        });
    }

    #[test]
    fn msi_join_expression_update_target_edges() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-join-expression-modify");
            let (db, _path) =
                open_fixture(&mut fixture, "joinexpression.msi", &relational_compound());
            let view = open_view(
                &mut fixture,
                db,
                "SELECT f.FeatureId, LENGTH(f.Title) FROM Feature f \
                 INNER JOIN Product p ON p.ProductCode = f.ProductCode \
                 ORDER BY f.FeatureId",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            let (result, record) = fetch(&mut fixture, view);
            assert_eq!(result, OK);
            assert_eq!(record_integer(&mut fixture, record, 0), 1);
            assert_eq!(
                modify(&mut fixture, view, 2, record),
                u64::from(ERROR_SUCCESS)
            );
            assert_eq!(record_string(&mut fixture, record, 2), (0, "4".to_string()));
        });
    }

    #[test]
    fn msi_sql_lower_handles_non_ascii_folding_edges() {
        assert_eq!(sql_lower('A'), 'a');
        assert_eq!(sql_lower('Ä'), 'ä');
        assert_eq!(sql_lower('中'), '中');
        assert_eq!(
            sql_string_cmp("Ä", "ä"),
            std::cmp::Ordering::Equal,
            "non-ASCII folding must compare case-insensitively"
        );
        assert_eq!(
            sql_string_cmp("中", "ä"),
            std::cmp::Ordering::Greater,
            "distinct non-ASCII scalars must order deterministically"
        );
    }

    #[test]
    fn msi_sql_null_function_and_malformed_parser_edges_pin_errors() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-null-function-edges");
            let (db, _path) = open_fixture(&mut fixture, "nullfn.msi", &relational_compound());

            let view = open_view(
                &mut fixture,
                db,
                "SELECT LOWER(Title), LENGTH(Title) FROM Feature WHERE FeatureId = 4",
            );
            assert_eq!(execute(&mut fixture, view), OK);
            assert_eq!(
                collect_rows(&mut fixture, view, 2),
                vec![vec![String::new(), String::new()]],
                "LOWER/LENGTH of NULL must stay NULL"
            );

            assert_eq!(
                open_view_error(&mut fixture, db, "SELECT UPPER(Name FROM Product"),
                u64::from(ERROR_BAD_QUERY_SYNTAX),
                "a missing function closing paren is a malformed query"
            );
        });
    }

    #[test]
    fn msi_sql_predicate_and_value_evaluation_edges_pin_exact_rows() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-eval-edges");
            let (db, _path) = open_fixture(&mut fixture, "evals.msi", &relational_compound());

            let scalars = open_view(
                &mut fixture,
                db,
                "SELECT -Price, +Price, Price + 1, Price - 1, Price * 2, Price / 2, Price % 2, \
                 UPPER(Name), LOWER(Name), LENGTH(Name), SUBSTRING(Name, 2, 1) \
                 FROM Product WHERE ProductCode = 'P1'",
            );
            assert_eq!(execute(&mut fixture, scalars), OK);
            assert_eq!(
                collect_rows(&mut fixture, scalars, 11),
                vec![vec![
                    "-10".to_string(),
                    "10".to_string(),
                    "11".to_string(),
                    "9".to_string(),
                    "20".to_string(),
                    "5".to_string(),
                    "0".to_string(),
                    "ALPHA".to_string(),
                    "alpha".to_string(),
                    "5".to_string(),
                    "l".to_string(),
                ]]
            );

            let counted = open_view(&mut fixture, db, "SELECT COUNT(Price) FROM Product");
            assert_eq!(execute(&mut fixture, counted), OK);
            assert_eq!(
                collect_rows(&mut fixture, counted, 1),
                vec![vec!["3".to_string()]]
            );

            let is_null = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title IS NULL ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, is_null), OK);
            assert_eq!(
                collect_rows(&mut fixture, is_null, 1),
                vec![vec!["4".to_string()]]
            );

            let like = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title LIKE 'F%' ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, like), OK);
            assert_eq!(
                collect_rows(&mut fixture, like, 1),
                vec![vec!["1".to_string()], vec!["5".to_string()]]
            );

            let between = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Weight BETWEEN 1 AND 5 ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, between), OK);
            assert_eq!(
                collect_rows(&mut fixture, between, 1),
                vec![
                    vec!["1".to_string()],
                    vec!["3".to_string()],
                    vec!["5".to_string()]
                ]
            );

            let in_list = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Title IN ('Fast', 'Slow') ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, in_list), OK);
            assert_eq!(
                collect_rows(&mut fixture, in_list, 1),
                vec![
                    vec!["1".to_string()],
                    vec!["2".to_string()],
                    vec!["5".to_string()]
                ]
            );

            let in_query = open_view(
                &mut fixture,
                db,
                "SELECT FeatureId FROM Feature WHERE Weight IN \
                 (SELECT Weight FROM Feature WHERE Weight > 5) ORDER BY FeatureId",
            );
            assert_eq!(execute(&mut fixture, in_query), OK);
            assert_eq!(
                collect_rows(&mut fixture, in_query, 1),
                vec![vec!["2".to_string()]]
            );

            let logic = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE (Price = 10 AND Name = 'Alpha') OR Name = 'Gamma' \
                 ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, logic), OK);
            assert_eq!(
                collect_rows(&mut fixture, logic, 1),
                vec![vec!["Alpha".to_string()], vec!["Gamma".to_string()]]
            );

            let negated = open_view(
                &mut fixture,
                db,
                "SELECT Name FROM Product WHERE NOT Name = 'Zzz' ORDER BY Name",
            );
            assert_eq!(execute(&mut fixture, negated), OK);
            assert_eq!(
                collect_rows(&mut fixture, negated, 1),
                vec![
                    vec!["Alpha".to_string()],
                    vec!["Beta".to_string()],
                    vec!["Gamma".to_string()]
                ]
            );

            let not_exists = open_view(
                &mut fixture,
                db,
                "SELECT p.Name FROM Product p WHERE NOT EXISTS \
                 (SELECT 1 FROM Feature f WHERE f.ProductCode = p.ProductCode) ORDER BY p.Name",
            );
            assert_eq!(execute(&mut fixture, not_exists), OK);
            assert_eq!(
                collect_rows(&mut fixture, not_exists, 1),
                vec![vec!["Gamma".to_string()]]
            );
        });
    }

    #[test]
    fn msi_sql_outer_alias_and_group_expression_edges_pin_rows() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-outer-group-edges");
            let (db, _path) = open_fixture(&mut fixture, "outergroup.msi", &relational_compound());

            let correlated = open_view(
                &mut fixture,
                db,
                "SELECT (SELECT p.Name AS O FROM Feature f WHERE f.FeatureId = 1) AS S \
                 FROM Product p ORDER BY p.ProductCode",
            );
            assert_eq!(execute(&mut fixture, correlated), OK);
            assert_eq!(
                collect_rows(&mut fixture, correlated, 1),
                vec![
                    vec!["Alpha".to_string()],
                    vec!["Beta".to_string()],
                    vec!["Gamma".to_string()]
                ]
            );

            let grouped = open_view(
                &mut fixture,
                db,
                "SELECT (Price = 10 AND Name = 'Alpha') AS K, COUNT(*) AS C FROM Product \
                 GROUP BY (Price = 10 AND Name = 'Alpha')",
            );
            assert_eq!(execute(&mut fixture, grouped), OK);
            assert_eq!(
                collect_rows(&mut fixture, grouped, 2),
                vec![vec![String::new(), "3".to_string()]],
                "the projected AND expression groups as one NULL key"
            );
        });
    }

    #[test]
    fn msi_sql_scalar_subquery_errors_pin_function_failed_edges() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-scalar-error-edges");
            let (db, _path) =
                open_fixture(&mut fixture, "scalar-errors.msi", &relational_compound());

            // A scalar subquery with more than one row is ERROR_FUNCTION_FAILED;
            // each query pins one error-propagation edge in value/predicate
            // evaluation (invalid shape: multi-row value where one row is
            // required).
            let queries = [
                "SELECT - (SELECT Price FROM Product) FROM Product",
                "SELECT (SELECT Price FROM Product) + 1 FROM Product",
                "SELECT 1 + (SELECT Price FROM Product) FROM Product",
                "SELECT UPPER((SELECT ProductCode FROM Product)) FROM Product",
                "SELECT Name FROM Product WHERE 1 = 1 AND 1 = (SELECT Price FROM Product)",
                "SELECT Name FROM Product WHERE 1 = 0 OR 1 = (SELECT Price FROM Product)",
                "SELECT Name FROM Product WHERE NOT (1 = (SELECT Price FROM Product))",
                "SELECT Name FROM Product WHERE (SELECT Price FROM Product) IS NULL",
                "SELECT Name FROM Product WHERE (SELECT ProductCode FROM Product) LIKE 'A%'",
                "SELECT Name FROM Product WHERE Name LIKE (SELECT ProductCode FROM Product)",
                "SELECT Name FROM Product WHERE (SELECT Price FROM Product) BETWEEN 1 AND 5",
                "SELECT Name FROM Product WHERE Price BETWEEN (SELECT Price FROM Product) AND 5",
                "SELECT Name FROM Product WHERE Price BETWEEN 1 AND (SELECT Price FROM Product)",
                "SELECT Name FROM Product WHERE (SELECT Price FROM Product) IN (1, 2)",
                "SELECT Name FROM Product WHERE Price IN (1, (SELECT Price FROM Product))",
                "SELECT Name FROM Product WHERE (SELECT Price FROM Product) IN (SELECT Price FROM Product)",
            ];
            for sql in queries {
                let view = open_view(&mut fixture, db, sql);
                assert_ne!(view, 0, "view must resolve: {sql}");
                assert_eq!(execute(&mut fixture, view), FUNCTION_FAILED, "{sql}");
            }

            // NOT EXISTS in a value position takes the negated branch.
            let exists = open_view(
                &mut fixture,
                db,
                "SELECT NOT EXISTS (SELECT 1 FROM Feature) FROM Product",
            );
            assert_eq!(execute(&mut fixture, exists), OK);
            assert_eq!(
                collect_rows(&mut fixture, exists, 1),
                vec![vec!["0".to_string()]; 3]
            );
        });
    }

    #[test]
    fn msi_sql_invalid_expression_shapes_pin_bad_column_and_syntax() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("msi-sql-resolve-error-edges");
            let (db, _path) =
                open_fixture(&mut fixture, "resolve-errors.msi", &relational_compound());

            assert_eq!(
                open_view_error(
                    &mut fixture,
                    db,
                    "SELECT Name FROM Product WHERE Name LIKE (SELECT Missing FROM Product)"
                ),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
            assert_eq!(
                open_view_error(&mut fixture, db, "SELECT Name FROM Product WHERE -Name = 1"),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
            assert_eq!(
                open_view_error(&mut fixture, db, "SELECT Name + 1 FROM Product"),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
            assert_eq!(
                open_view_error(&mut fixture, db, "SELECT Price + Name FROM Product"),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
            assert_eq!(
                open_view_error(&mut fixture, db, "SELECT UPPER(Missing) FROM Product"),
                u64::from(ERROR_BAD_COLUMN)
            );
            assert_eq!(
                open_view_error(
                    &mut fixture,
                    db,
                    "SELECT SUBSTRING(Price, 2, 1) FROM Product"
                ),
                u64::from(ERROR_BAD_QUERY_SYNTAX)
            );
            assert_eq!(
                open_view_error(&mut fixture, db, "SELECT SUM(Missing) FROM Product"),
                u64::from(ERROR_BAD_COLUMN)
            );
        });
    }

    #[test]
    fn msi_sql_invalid_internal_expression_shapes_hit_defensive_edges() {
        let database = MsiDatabaseState::empty(String::new());
        let mut expectations: Vec<ParameterExpectation> = Vec::new();

        // The parser rejects zero-argument UPPER/SUBSTRING, so the defensive
        // empty-argument branch is only reachable through a malformed internal
        // AST; it must resolve instead of panicking.
        let empty_upper = SqlExpr::Function {
            function: SqlFunction::Upper,
            arguments: Vec::new(),
        };
        let resolved =
            resolve_expr(&database, &[], &empty_upper, 0, &mut expectations, &[], &[]).unwrap();
        match resolved {
            ResolvedExpr::Function { arguments, .. } => assert_eq!(arguments.len(), 0),
            other => panic!("unexpected {other:?}"),
        }

        let empty_substring = SqlExpr::Function {
            function: SqlFunction::Substring,
            arguments: Vec::new(),
        };
        let resolved = resolve_expr(
            &database,
            &[],
            &empty_substring,
            0,
            &mut expectations,
            &[],
            &[],
        )
        .unwrap();
        match resolved {
            ResolvedExpr::Function { arguments, .. } => assert_eq!(arguments.len(), 0),
            other => panic!("unexpected {other:?}"),
        }

        let left = ResolvedExpr::Or(
            Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            Box::new(ResolvedExpr::Literal(MsiValue::Int(2))),
        );
        assert_eq!(resolved_expressions_match(&left, &left.clone()), true);
        let mismatched = ResolvedExpr::Or(
            Box::new(ResolvedExpr::Literal(MsiValue::Int(1))),
            Box::new(ResolvedExpr::Literal(MsiValue::Int(3))),
        );
        assert_eq!(resolved_expressions_match(&left, &mismatched), false);
    }
}
