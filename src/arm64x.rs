//! ARM64EC/ARM64X hybrid PE metadata, code maps, auxiliary IATs and
//! ARM64X dynamic relocations.

use crate::error::{AppError, AppResult};
use crate::pe::{DataDirectory, LoadConfig, MappedImage, ParsedPe, PeSection, RelocationType};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};

pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xa641;
pub const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xa64e;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_CHPE_X86: u16 = 0x3a64;

pub const IMAGE_CHPE_RANGE_TYPE_MASK: u32 = 0x3;
pub const IMAGE_DYNAMIC_RELOCATION_ARM64X: u32 = 6;
pub const IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL: u8 = 0;
pub const IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE: u8 = 1;
pub const IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA: u8 = 2;

pub const LOAD_CONFIG64_CHPE_METADATA_POINTER: usize = 0xc8;
pub const LOAD_CONFIG64_DYNAMIC_VALUE_RELOC_TABLE: usize = 0xc0;
pub const LOAD_CONFIG64_DYNAMIC_VALUE_RELOC_TABLE_OFFSET: usize = 0xe0;
pub const LOAD_CONFIG64_DYNAMIC_VALUE_RELOC_TABLE_SECTION: usize = 0xe4;
pub const LOAD_CONFIG32_CHPE_METADATA_POINTER: usize = 0x7c;
pub const LOAD_CONFIG32_DYNAMIC_VALUE_RELOC_TABLE: usize = 0x78;
pub const LOAD_CONFIG32_DYNAMIC_VALUE_RELOC_TABLE_OFFSET: usize = 0x88;
pub const LOAD_CONFIG32_DYNAMIC_VALUE_RELOC_TABLE_SECTION: usize = 0x8c;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridView {
    Native,
    Emulation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridMachine {
    Arm64,
    Arm64Ec,
    Arm64X,
}

impl HybridMachine {
    pub fn from_machine(machine: u16) -> Option<Self> {
        match machine {
            IMAGE_FILE_MACHINE_ARM64 => Some(Self::Arm64),
            IMAGE_FILE_MACHINE_ARM64EC => Some(Self::Arm64Ec),
            IMAGE_FILE_MACHINE_ARM64X => Some(Self::Arm64X),
            _ => None,
        }
    }

    pub fn is_hybrid(self) -> bool {
        !matches!(self, Self::Arm64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChpeCodeKind {
    Arm64,
    Arm64Ec,
    Amd64,
}

/// How an ARM64EC/ARM64X image classifies one function body.
///
/// `Arm64` and `Arm64Ec` execute natively; `X64` must be translated to x64
/// guest instructions before it runs.  This is the classification the call
/// checker uses to decide whether an indirect call needs an exit thunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcFunctionKind {
    Arm64,
    Arm64Ec,
    X64,
}

impl EcFunctionKind {
    pub const fn is_native(self) -> bool {
        !matches!(self, Self::X64)
    }

    pub const fn is_x64(self) -> bool {
        matches!(self, Self::X64)
    }
}

impl From<ChpeCodeKind> for EcFunctionKind {
    fn from(kind: ChpeCodeKind) -> Self {
        match kind {
            ChpeCodeKind::Arm64 => Self::Arm64,
            ChpeCodeKind::Arm64Ec => Self::Arm64Ec,
            ChpeCodeKind::Amd64 => Self::X64,
        }
    }
}

impl ChpeCodeKind {
    pub fn from_raw(value: u32) -> AppResult<Self> {
        match value {
            0 => Ok(Self::Arm64),
            1 => Ok(Self::Arm64Ec),
            2 => Ok(Self::Amd64),
            other => Err(malformed(format!(
                "CHPE code map contains reserved range type {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChpeCodeRange {
    pub start_rva: u32,
    pub length: u32,
    pub kind: ChpeCodeKind,
}

impl ChpeCodeRange {
    pub fn end_rva(&self) -> u32 {
        self.start_rva.saturating_add(self.length)
    }

    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.start_rva && rva < self.end_rva()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChpeCodeRangeEntry {
    pub start_rva: u32,
    pub end_rva: u32,
    pub entry_point_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChpeRedirection {
    pub source_rva: u32,
    pub destination_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridAuxiliaryIat {
    pub rva: u32,
    pub entries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridExportRoute {
    pub name: Option<String>,
    pub ordinal: u32,
    pub native_rva: u32,
    pub emulation_rva: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChpeMetadata {
    pub version: u32,
    pub code_map_rva: u32,
    pub code_map_count: u32,
    pub code_ranges_to_entry_points_rva: u32,
    pub redirection_metadata_rva: u32,
    pub dispatch_call_no_redirect_rva: u32,
    pub dispatch_ret_rva: u32,
    pub dispatch_call_rva: u32,
    pub dispatch_icall_rva: u32,
    pub dispatch_icall_cfg_rva: u32,
    pub alternate_entry_point_rva: u32,
    pub auxiliary_iat_rva: u32,
    pub code_ranges_to_entry_points_count: u32,
    pub redirection_metadata_count: u32,
    pub get_x64_information_rva: u32,
    pub set_x64_information_rva: u32,
    pub extra_rfe_table_rva: u32,
    pub extra_rfe_table_size: u32,
    pub dispatch_fptr_rva: u32,
    pub auxiliary_iat_copy_rva: u32,
    pub auxiliary_delayload_iat_rva: u32,
    pub auxiliary_delayload_iat_copy_rva: u32,
    pub hybrid_image_info: u32,
    pub code_map: Vec<ChpeCodeRange>,
    pub entry_points: Vec<ChpeCodeRangeEntry>,
    pub redirections: Vec<ChpeRedirection>,
}

/// Distance from an ARM64EC function entry backwards to its entry-thunk
/// metadata word.  ARM64EC reserves these four bytes before every callable
/// function for the signature-specific entry thunk.
pub const EC_ENTRY_THUNK_METADATA_SIZE: u32 = 4;
pub const EC_ENTRY_THUNK_DELTA_MASK: u32 = !0x3;

/// Registers that have no representation in the x64 `CONTEXT` and therefore
/// must not carry state across an ARM64EC transition.
pub const EC_BLOCKED_ARM64_REGISTERS: [usize; 5] = [13, 14, 23, 24, 28];

impl ChpeMetadata {
    pub fn code_kind_at(&self, rva: u32) -> Option<ChpeCodeKind> {
        self.code_map
            .iter()
            .find(|range| range.contains(rva))
            .map(|range| range.kind)
    }

    /// Classify the code containing `rva` according to the CHPE code map.
    pub fn function_kind_at(&self, rva: u32) -> Option<EcFunctionKind> {
        self.code_kind_at(rva).map(EcFunctionKind::from)
    }

    /// Reject a code map that is unsorted or has overlapping ranges.
    ///
    /// Windows emits the map sorted by RVA; overlapping entries make the
    /// architecture of a function address ambiguous, so the checker must fail
    /// closed instead of picking one arbitrarily.
    pub fn validate_code_map(&self, size_of_image: u32) -> AppResult<()> {
        if self.code_map.is_empty() {
            return Err(malformed("ARM64EC image is missing the CHPE code map"));
        }
        let mut previous_end = 0u32;
        for range in &self.code_map {
            if range.length == 0 {
                return Err(malformed("CHPE code map entry has zero length"));
            }
            let end = range
                .start_rva
                .checked_add(range.length)
                .ok_or_else(|| malformed("CHPE code map entry overflows the image"))?;
            if end > size_of_image {
                return Err(malformed("CHPE code map entry exceeds SizeOfImage"));
            }
            if range.start_rva < previous_end {
                return Err(malformed("CHPE code map entries overlap or are unsorted"));
            }
            previous_end = end;
        }
        Ok(())
    }

    pub fn route_entry_point(&self, rva: u32) -> Option<u32> {
        if let Some(entry) = self
            .entry_points
            .iter()
            .find(|entry| rva >= entry.start_rva && rva < entry.end_rva)
        {
            return Some(entry.entry_point_rva);
        }
        self.redirections
            .iter()
            .find(|redirect| redirect.source_rva == rva)
            .map(|redirect| redirect.destination_rva)
    }

    pub fn redirect_target(&self, rva: u32) -> Option<u32> {
        self.redirections
            .iter()
            .find(|redirect| redirect.source_rva == rva)
            .map(|redirect| redirect.destination_rva)
    }

    pub fn auxiliary_iat(&self) -> Option<HybridAuxiliaryIat> {
        (self.auxiliary_iat_rva != 0).then_some(HybridAuxiliaryIat {
            rva: self.auxiliary_iat_rva,
            entries: 0,
        })
    }

    pub fn auxiliary_iat_copy(&self) -> Option<HybridAuxiliaryIat> {
        (self.auxiliary_iat_copy_rva != 0).then_some(HybridAuxiliaryIat {
            rva: self.auxiliary_iat_copy_rva,
            entries: 0,
        })
    }

    pub fn auxiliary_delayload_iat(&self) -> Option<HybridAuxiliaryIat> {
        (self.auxiliary_delayload_iat_rva != 0).then_some(HybridAuxiliaryIat {
            rva: self.auxiliary_delayload_iat_rva,
            entries: 0,
        })
    }

    pub fn auxiliary_delayload_iat_copy(&self) -> Option<HybridAuxiliaryIat> {
        (self.auxiliary_delayload_iat_copy_rva != 0).then_some(HybridAuxiliaryIat {
            rva: self.auxiliary_delayload_iat_copy_rva,
            entries: 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64XFixupKind {
    ZeroFill,
    Value,
    Delta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64XRelocation {
    pub rva: u32,
    pub size: u8,
    pub value: u64,
    pub kind: Arm64XFixupKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64XDynamicRelocationBlock {
    pub page_rva: u32,
    pub entries: Vec<Arm64XRelocation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64PdataKind {
    X64,
    Arm64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
    pub unwind_info_rva: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64UnwindInfo {
    pub function_length: u32,
    pub version: u8,
    pub exception_data_present: bool,
    pub epilog_in_header: bool,
    pub epilog_count: u32,
    pub code_words: u32,
    pub handler_rva: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64ExceptionTable {
    pub kind: Arm64PdataKind,
    pub directory: DataDirectory,
    pub functions: Vec<Arm64RuntimeFunction>,
    pub unwind_info: Vec<Arm64UnwindInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64ImageMetadata {
    pub machine: u16,
    pub chpe: Option<ChpeMetadata>,
    pub dynamic_relocations: Vec<Arm64XDynamicRelocationBlock>,
    pub extra_rfe_table: Option<DataDirectory>,
    pub exception_tables: Vec<Arm64ExceptionTable>,
}

pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        IMAGE_FILE_MACHINE_ARM64EC => "ARM64EC",
        IMAGE_FILE_MACHINE_ARM64X => "ARM64X",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        IMAGE_FILE_MACHINE_I386 => "I386",
        IMAGE_FILE_MACHINE_CHPE_X86 => "CHPE_X86",
        _ => "unknown",
    }
}

pub fn malformed(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcPeParseInvalid, message.into())
}

fn read_at<'a>(
    bytes: &'a [u8],
    sections: &[PeSection],
    rva: u32,
    size: u32,
    label: &str,
) -> AppResult<&'a [u8]> {
    let end = rva
        .checked_add(size)
        .ok_or_else(|| malformed(format!("{label} range overflow")))?;
    let section = sections
        .iter()
        .find(|section| {
            rva >= section.virtual_address
                && end
                    <= section
                        .virtual_address
                        .saturating_add(section.raw_data_size)
        })
        .ok_or_else(|| {
            malformed(format!(
                "{label} RVA 0x{rva:08x} is not backed by file data"
            ))
        })?;
    let relative = (rva - section.virtual_address) as usize;
    let start = section.raw_data_ptr as usize + relative;
    let end_offset = start
        .checked_add(size as usize)
        .ok_or_else(|| malformed(format!("{label} range overflow")))?;
    if end_offset > bytes.len() {
        return Err(malformed(format!("{label} is truncated")));
    }
    Ok(&bytes[start..end_offset])
}

fn read_u32_at(bytes: &[u8], sections: &[PeSection], rva: u32, label: &str) -> AppResult<u32> {
    let data = read_at(bytes, sections, rva, 4, label)?;
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

fn read_u64_at(bytes: &[u8], sections: &[PeSection], rva: u32, label: &str) -> AppResult<u64> {
    let data = read_at(bytes, sections, rva, 8, label)?;
    Ok(u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]))
}

fn checked_va_to_rva(va: u64, image_base: u64) -> AppResult<u32> {
    if va == 0 {
        return Err(malformed("image contains a null metadata pointer"));
    }
    let rva = if va >= image_base {
        va.checked_sub(image_base)
            .ok_or_else(|| malformed("metadata pointer is below the image base"))?
    } else {
        va
    };
    u32::try_from(rva).map_err(|_| malformed("metadata pointer does not fit in RVA space"))
}

fn meta_u32(bytes: &[u8], sections: &[PeSection], metadata_rva: u32, index: u32) -> AppResult<u32> {
    let rva = metadata_rva
        .checked_add(
            index
                .checked_mul(4)
                .ok_or_else(|| malformed("CHPE metadata offset overflow"))?,
        )
        .ok_or_else(|| malformed("CHPE metadata offset overflow"))?;
    read_u32_at(bytes, sections, rva, "CHPE metadata")
        .map_err(|_| malformed(format!("CHPE metadata is truncated at field {index}")))
}

pub fn parse_chpe_metadata(
    bytes: &[u8],
    sections: &[PeSection],
    image_base: u64,
    size_of_image: u32,
    metadata_va: u64,
) -> AppResult<ChpeMetadata> {
    let metadata_rva = checked_va_to_rva(metadata_va, image_base)?;
    let version = meta_u32(bytes, sections, metadata_rva, 0)?;
    if version == 0 || version > 2 {
        return Err(malformed(format!(
            "unsupported CHPE metadata version {version}"
        )));
    }
    let code_map_rva = meta_u32(bytes, sections, metadata_rva, 1)?;
    let code_map_count = meta_u32(bytes, sections, metadata_rva, 2)?;
    if code_map_count == 0 || code_map_rva == 0 {
        return Err(malformed("ARM64EC image is missing the CHPE code map"));
    }
    if code_map_count as u64 * 8 > bytes.len() as u64 {
        return Err(malformed("CHPE code map count exceeds the file size"));
    }
    let code_ranges_to_entry_points_rva = meta_u32(bytes, sections, metadata_rva, 3)?;
    let redirection_metadata_rva = meta_u32(bytes, sections, metadata_rva, 4)?;
    let dispatch_call_no_redirect_rva = meta_u32(bytes, sections, metadata_rva, 5)?;
    let dispatch_ret_rva = meta_u32(bytes, sections, metadata_rva, 6)?;
    let dispatch_call_rva = meta_u32(bytes, sections, metadata_rva, 7)?;
    let dispatch_icall_rva = meta_u32(bytes, sections, metadata_rva, 8)?;
    let dispatch_icall_cfg_rva = meta_u32(bytes, sections, metadata_rva, 9)?;
    let alternate_entry_point_rva = meta_u32(bytes, sections, metadata_rva, 10)?;
    let auxiliary_iat_rva = meta_u32(bytes, sections, metadata_rva, 11)?;
    let code_ranges_to_entry_points_count = meta_u32(bytes, sections, metadata_rva, 12)?;
    let redirection_metadata_count = meta_u32(bytes, sections, metadata_rva, 13)?;
    let get_x64_information_rva = meta_u32(bytes, sections, metadata_rva, 14)?;
    let set_x64_information_rva = meta_u32(bytes, sections, metadata_rva, 15)?;
    let extra_rfe_table_rva = meta_u32(bytes, sections, metadata_rva, 16)?;
    let extra_rfe_table_size = meta_u32(bytes, sections, metadata_rva, 17)?;
    let dispatch_fptr_rva = meta_u32(bytes, sections, metadata_rva, 18)?;
    let auxiliary_iat_copy_rva = meta_u32(bytes, sections, metadata_rva, 19)?;
    let (auxiliary_delayload_iat_rva, auxiliary_delayload_iat_copy_rva, hybrid_image_info) =
        if version >= 2 {
            (
                meta_u32(bytes, sections, metadata_rva, 20)?,
                meta_u32(bytes, sections, metadata_rva, 21)?,
                meta_u32(bytes, sections, metadata_rva, 22)?,
            )
        } else {
            (0, 0, 0)
        };

    if code_ranges_to_entry_points_count != 0 && code_ranges_to_entry_points_rva == 0 {
        return Err(malformed("CHPE entry-point table pointer is null"));
    }
    if redirection_metadata_count != 0 && redirection_metadata_rva == 0 {
        return Err(malformed("CHPE redirection table pointer is null"));
    }

    let mut code_map = Vec::with_capacity(code_map_count as usize);
    let mut previous_code_map_end = 0u32;
    for index in 0..code_map_count {
        let entry_rva = code_map_rva
            .checked_add(
                index
                    .checked_mul(8)
                    .ok_or_else(|| malformed("CHPE code map offset overflow"))?,
            )
            .ok_or_else(|| malformed("CHPE code map offset overflow"))?;
        let start_raw = read_u32_at(bytes, sections, entry_rva, "CHPE code map entry")
            .map_err(|_| malformed("CHPE code map is truncated"))?;
        let length = read_u32_at(bytes, sections, entry_rva + 4, "CHPE code map length")
            .map_err(|_| malformed("CHPE code map is truncated"))?;
        if length == 0 {
            return Err(malformed("CHPE code map entry has zero length"));
        }
        let kind = ChpeCodeKind::from_raw(start_raw & IMAGE_CHPE_RANGE_TYPE_MASK)?;
        let start_rva = start_raw & !IMAGE_CHPE_RANGE_TYPE_MASK;
        let end = start_rva
            .checked_add(length)
            .ok_or_else(|| malformed("CHPE code map entry overflows the image"))?;
        if end > size_of_image {
            return Err(malformed("CHPE code map entry exceeds SizeOfImage"));
        }
        if start_rva < previous_code_map_end {
            return Err(malformed("CHPE code map entries overlap or are unsorted"));
        }
        previous_code_map_end = end;
        code_map.push(ChpeCodeRange {
            start_rva,
            length,
            kind,
        });
    }

    let mut entry_points = Vec::with_capacity(code_ranges_to_entry_points_count as usize);
    for index in 0..code_ranges_to_entry_points_count {
        let entry_rva = code_ranges_to_entry_points_rva
            .checked_add(
                index
                    .checked_mul(12)
                    .ok_or_else(|| malformed("CHPE entry-point offset overflow"))?,
            )
            .ok_or_else(|| malformed("CHPE entry-point offset overflow"))?;
        let start_rva = read_u32_at(bytes, sections, entry_rva, "CHPE entry start")
            .map_err(|_| malformed("CHPE entry-point table is truncated"))?;
        let end_rva = read_u32_at(bytes, sections, entry_rva + 4, "CHPE entry end")
            .map_err(|_| malformed("CHPE entry-point table is truncated"))?;
        let entry_point_rva = read_u32_at(bytes, sections, entry_rva + 8, "CHPE entry point")
            .map_err(|_| malformed("CHPE entry-point table is truncated"))?;
        if start_rva > end_rva {
            return Err(malformed("CHPE entry-point range is inverted"));
        }
        if end_rva > size_of_image || entry_point_rva >= size_of_image {
            return Err(malformed("CHPE entry-point range exceeds SizeOfImage"));
        }
        entry_points.push(ChpeCodeRangeEntry {
            start_rva,
            end_rva,
            entry_point_rva,
        });
    }

    let mut redirections = Vec::with_capacity(redirection_metadata_count as usize);
    for index in 0..redirection_metadata_count {
        let entry_rva = redirection_metadata_rva
            .checked_add(
                index
                    .checked_mul(8)
                    .ok_or_else(|| malformed("CHPE redirection offset overflow"))?,
            )
            .ok_or_else(|| malformed("CHPE redirection offset overflow"))?;
        let source_rva = read_u32_at(bytes, sections, entry_rva, "CHPE redirection source")
            .map_err(|_| malformed("CHPE redirection metadata is truncated"))?;
        let destination_rva =
            read_u32_at(bytes, sections, entry_rva + 4, "CHPE redirection target")
                .map_err(|_| malformed("CHPE redirection metadata is truncated"))?;
        if source_rva >= size_of_image || destination_rva >= size_of_image {
            return Err(malformed("CHPE redirection target exceeds SizeOfImage"));
        }
        redirections.push(ChpeRedirection {
            source_rva,
            destination_rva,
        });
    }

    Ok(ChpeMetadata {
        version,
        code_map_rva,
        code_map_count,
        code_ranges_to_entry_points_rva,
        redirection_metadata_rva,
        dispatch_call_no_redirect_rva,
        dispatch_ret_rva,
        dispatch_call_rva,
        dispatch_icall_rva,
        dispatch_icall_cfg_rva,
        alternate_entry_point_rva,
        auxiliary_iat_rva,
        code_ranges_to_entry_points_count,
        redirection_metadata_count,
        get_x64_information_rva,
        set_x64_information_rva,
        extra_rfe_table_rva,
        extra_rfe_table_size,
        dispatch_fptr_rva,
        auxiliary_iat_copy_rva,
        auxiliary_delayload_iat_rva,
        auxiliary_delayload_iat_copy_rva,
        hybrid_image_info,
        code_map,
        entry_points,
        redirections,
    })
}

/// Read the entry-thunk delta stored in the four bytes immediately before an
/// ARM64EC function.  The low two bits are tag bits and are masked off; the
/// remaining signed delta is added to the function RVA.  `None` means the
/// function has no entry thunk (delta zero).
pub fn parse_ec_entry_thunk_rva(
    bytes: &[u8],
    sections: &[PeSection],
    function_rva: u32,
    size_of_image: u32,
) -> AppResult<Option<u32>> {
    if function_rva < EC_ENTRY_THUNK_METADATA_SIZE {
        return Err(malformed(
            "ARM64EC function is too close to the image base for entry-thunk metadata",
        ));
    }
    let metadata_rva = function_rva - EC_ENTRY_THUNK_METADATA_SIZE;
    let raw = read_u32_at(
        bytes,
        sections,
        metadata_rva,
        "ARM64EC entry thunk metadata",
    )
    .map_err(|_| malformed("ARM64EC entry thunk metadata is truncated"))?;
    let delta = (raw & EC_ENTRY_THUNK_DELTA_MASK) as i32;
    if delta == 0 {
        return Ok(None);
    }
    let target = (i64::from(function_rva) + i64::from(delta))
        .try_into()
        .map_err(|_| malformed("ARM64EC entry thunk points outside the image"))?;
    if target >= size_of_image {
        return Err(malformed("ARM64EC entry thunk points outside the image"));
    }
    Ok(Some(target))
}

/// Maximum number of bytes scanned when locating the body of an ARM64EC
/// entry thunk.  Larger code ranges fail closed instead of doing unbounded
/// work in the loader.
pub const EC_THUNK_SCAN_LIMIT: u32 = 0x10_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcThunkKind {
    /// Twelve-byte x64 stub: `mov rax, imm64; jmp rax`.
    X64EntryStub,
    /// Canonical x64 fast-forward sequence ending in `jmp rel32`.
    X64FastForward,
    /// Native body whose pre-entry metadata points at an entry thunk.
    EcEntryThunk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcThunkRoute {
    pub kind: EcThunkKind,
    /// The real native body that must receive the translated arguments.
    pub body_rva: u32,
}

fn mapped_at<'a>(mapped: &'a [u8], rva: u32, len: u32, size_of_image: u32) -> Option<&'a [u8]> {
    let end = rva.checked_add(len)?;
    if end > size_of_image || end as usize > mapped.len() {
        return None;
    }
    Some(&mapped[rva as usize..end as usize])
}

/// Detect a PE-provided thunk body at `rva` inside a mapped image.
///
/// The two x64 forms are recognized exactly (the emitted entry stub and the
/// canonical fast-forward sequence).  The ARM64EC entry-thunk form is found by
/// scanning the enclosing native code range for a function whose four bytes of
/// pre-entry metadata resolve to `rva`; that body is the real target and must
/// receive the converted arguments instead of the thunk.
pub fn detect_ec_thunk_body(
    mapped: &[u8],
    image_base: u64,
    rva: u32,
    code_start: u32,
    code_end: u32,
    size_of_image: u32,
) -> AppResult<Option<EcThunkRoute>> {
    if rva >= size_of_image {
        return Err(malformed("ARM64EC thunk target is outside SizeOfImage"));
    }
    if code_start > code_end || code_end > size_of_image {
        return Err(malformed("ARM64EC thunk scan range is invalid"));
    }
    if code_end - code_start > EC_THUNK_SCAN_LIMIT {
        return Err(malformed(
            "ARM64EC thunk scan range exceeds the supported limit",
        ));
    }
    if code_end as usize > mapped.len() {
        return Err(malformed("ARM64EC thunk scan range is not mapped"));
    }

    if let Some(bytes) = mapped_at(mapped, rva, 12, size_of_image) {
        if bytes[0] == 0x48 && bytes[1] == 0xb8 && bytes[10] == 0xff && bytes[11] == 0xe0 {
            let target = u64::from_le_bytes(bytes[2..10].try_into().expect("8 bytes"));
            let target_end = image_base
                .checked_add(u64::from(size_of_image))
                .ok_or_else(|| malformed("ARM64EC image address range overflows"))?;
            if target < image_base || target >= target_end {
                return Err(malformed(
                    "ARM64EC x64 entry stub target lies outside the image",
                ));
            }
            return Ok(Some(EcThunkRoute {
                kind: EcThunkKind::X64EntryStub,
                body_rva: (target - image_base) as u32,
            }));
        }
        const FFS_PREFIX: [u8; 9] = [0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d];
        if bytes[..9] == FFS_PREFIX
            && bytes[9] == 0xe9
            && let Some(rel) = mapped_at(mapped, rva, 14, size_of_image)
        {
            let displacement = i32::from_le_bytes(rel[10..14].try_into().expect("4 bytes"));
            let next = i64::from(rva) + 14;
            let target = next + i64::from(displacement);
            if !(0..i64::from(size_of_image)).contains(&target) {
                return Err(malformed(
                    "ARM64EC fast-forward thunk points outside the image",
                ));
            }
            return Ok(Some(EcThunkRoute {
                kind: EcThunkKind::X64FastForward,
                body_rva: target as u32,
            }));
        }
    }

    let mut candidate = code_start & !3;
    while candidate.saturating_add(4) <= code_end {
        if candidate >= EC_ENTRY_THUNK_METADATA_SIZE {
            let raw = u32::from_le_bytes(
                mapped[candidate as usize - 4..candidate as usize]
                    .try_into()
                    .expect("4 bytes"),
            );
            let delta = (raw & EC_ENTRY_THUNK_DELTA_MASK) as i32;
            if delta != 0 && i64::from(candidate) + i64::from(delta) == i64::from(rva) {
                return Ok(Some(EcThunkRoute {
                    kind: EcThunkKind::EcEntryThunk,
                    body_rva: candidate,
                }));
            }
        }
        candidate = candidate.saturating_add(4);
    }
    Ok(None)
}

pub fn parse_hybrid_aux_iat(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u32,
    pointer_bytes: usize,
    count: u32,
) -> AppResult<Vec<u64>> {
    if rva == 0 {
        return Err(malformed("hybrid auxiliary IAT pointer is null"));
    }
    paragraph_count(count, pointer_bytes, bytes.len() as u64)?;
    let mut entries = Vec::with_capacity(count as usize);
    for index in 0..count {
        let offset = rva
            .checked_add(
                index
                    .checked_mul(pointer_bytes as u32)
                    .ok_or_else(|| malformed("hybrid auxiliary IAT offset overflow"))?,
            )
            .ok_or_else(|| malformed("hybrid auxiliary IAT offset overflow"))?;
        let value = match pointer_bytes {
            4 => u64::from(
                read_u32_at(bytes, sections, offset, "hybrid auxiliary IAT")
                    .map_err(|_| malformed("hybrid auxiliary IAT is truncated"))?,
            ),
            8 => read_u64_at(bytes, sections, offset, "hybrid auxiliary IAT")
                .map_err(|_| malformed("hybrid auxiliary IAT is truncated"))?,
            _ => return Err(malformed("hybrid auxiliary IAT has invalid pointer width")),
        };
        entries.push(value);
    }
    Ok(entries)
}

fn paragraph_count(count: u32, pointer_bytes: usize, file_len: u64) -> AppResult<usize> {
    let bytes = u64::from(count)
        .checked_mul(pointer_bytes as u64)
        .ok_or_else(|| malformed("hybrid auxiliary IAT size overflow"))?;
    if bytes > file_len {
        return Err(malformed(
            "hybrid auxiliary IAT count exceeds the file size",
        ));
    }
    Ok(count as usize)
}

pub fn parse_arm64x_dynamic_relocations(
    bytes: &[u8],
    sections: &[PeSection],
    table_rva: u32,
    table_size: u32,
    size_of_image: u32,
) -> AppResult<Vec<Arm64XDynamicRelocationBlock>> {
    if table_rva == 0 {
        return Err(malformed("ARM64X dynamic relocation table pointer is null"));
    }
    if table_size < 8 {
        return Err(malformed("ARM64X dynamic relocation table is truncated"));
    }
    let header = read_at(
        bytes,
        sections,
        table_rva,
        table_size,
        "ARM64X dynamic relocation table",
    )
    .map_err(|_| malformed("ARM64X dynamic relocation table is truncated"))?;
    let version = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if version != 1 && version != 2 {
        return Err(malformed(format!(
            "unsupported ARM64X dynamic relocation table version {version}"
        )));
    }
    if size > header.len().saturating_sub(8) {
        return Err(malformed(
            "ARM64X dynamic relocation table size exceeds its directory",
        ));
    }
    let records = &header[8..8 + size];
    let mut cursor = 0usize;
    let mut blocks = Vec::new();
    while cursor < records.len() {
        if records.len() - cursor < if version == 1 { 12 } else { 20 } {
            return Err(malformed("ARM64X dynamic relocation record is truncated"));
        }
        let (symbol, fixup_size) = if version == 1 {
            let symbol = u32::from_le_bytes([
                records[cursor],
                records[cursor + 1],
                records[cursor + 2],
                records[cursor + 3],
            ]);
            let fixup = u32::from_le_bytes([
                records[cursor + 8],
                records[cursor + 9],
                records[cursor + 10],
                records[cursor + 11],
            ]) as usize;
            (symbol, fixup)
        } else {
            let header_size = u32::from_le_bytes([
                records[cursor],
                records[cursor + 1],
                records[cursor + 2],
                records[cursor + 3],
            ]) as usize;
            let fixup = u32::from_le_bytes([
                records[cursor + 4],
                records[cursor + 5],
                records[cursor + 6],
                records[cursor + 7],
            ]) as usize;
            let symbol = u32::from_le_bytes([
                records[cursor + 8],
                records[cursor + 9],
                records[cursor + 10],
                records[cursor + 11],
            ]);
            if header_size < 20 || header_size > records.len() - cursor {
                return Err(malformed(
                    "ARM64X dynamic relocation record header is malformed",
                ));
            }
            let _ = symbol;
            cursor += header_size;
            if fixup > records.len() - cursor {
                return Err(malformed(
                    "ARM64X dynamic relocation fixup exceeds the table",
                ));
            }
            if symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X {
                blocks.extend(parse_arm64x_relocation_blocks(
                    &records[cursor..cursor + fixup],
                    size_of_image,
                )?);
            }
            cursor += fixup;
            continue;
        };
        if version == 1 {
            let fixup = fixup_size;
            if fixup > records.len() - cursor - 12 {
                return Err(malformed(
                    "ARM64X dynamic relocation fixup exceeds the table",
                ));
            }
            if symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X {
                blocks.extend(parse_arm64x_relocation_blocks(
                    &records[cursor + 12..cursor + 12 + fixup],
                    size_of_image,
                )?);
            }
            cursor += 12 + fixup;
        }
        cursor = (cursor + 3) & !3;
    }
    Ok(blocks)
}

fn parse_arm64x_relocation_blocks(
    data: &[u8],
    size_of_image: u32,
) -> AppResult<Vec<Arm64XDynamicRelocationBlock>> {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        if data.len() - cursor < 8 {
            if data[cursor..].iter().all(|byte| *byte == 0) {
                break;
            }
            return Err(malformed("ARM64X relocation block is truncated"));
        }
        let page_rva = u32::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        let block_size = u32::from_le_bytes([
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]) as usize;
        if page_rva == 0 && block_size == 0 {
            break;
        }
        if block_size < 8 || block_size > data.len() - cursor {
            return Err(malformed("ARM64X relocation block exceeds its bounds"));
        }
        if block_size % 4 != 0 {
            return Err(malformed(
                "ARM64X relocation block size is not 4-byte aligned",
            ));
        }
        if page_rva & 0xfff != 0 {
            return Err(malformed("ARM64X relocation page RVA is not page aligned"));
        }
        let block = &data[cursor..cursor + block_size];
        let words = (block_size - 8) / 2;
        let mut index = 0usize;
        let mut entries = Vec::new();
        while index < words {
            let raw = u16::from_le_bytes([block[8 + index * 2], block[9 + index * 2]]);
            if raw == 0 {
                break;
            }
            let fixup = ((raw >> 12) & 0x3) as u8;
            let arg = (raw >> 14) & 0x3;
            let rva = page_rva | u32::from(raw & 0x0fff);
            match fixup {
                IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL => {
                    let size = 1u8 << arg;
                    if rva % u32::from(size) != 0 {
                        return Err(malformed("unaligned ARM64X zero-fill relocation"));
                    }
                    entries.push(Arm64XRelocation {
                        rva,
                        size,
                        value: 0,
                        kind: Arm64XFixupKind::ZeroFill,
                    });
                    index += 1;
                }
                IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE => {
                    if arg == 0 {
                        return Err(malformed("ARM64X value relocation has size zero"));
                    }
                    let size = 1u8 << arg;
                    let words_needed = 1 + usize::from(size) / 2;
                    if index + words_needed > words {
                        return Err(malformed("ARM64X value relocation is truncated"));
                    }
                    if rva % u32::from(size) != 0 {
                        return Err(malformed("unaligned ARM64X value relocation"));
                    }
                    let payload = &block[8 + (index + 1) * 2..8 + (index + words_needed) * 2];
                    let value = match size {
                        2 => u64::from(u16::from_le_bytes([payload[0], payload[1]])),
                        4 => u64::from(u32::from_le_bytes([
                            payload[0], payload[1], payload[2], payload[3],
                        ])),
                        8 => u64::from_le_bytes([
                            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                            payload[6], payload[7],
                        ]),
                        _ => return Err(malformed("ARM64X value relocation has invalid size")),
                    };
                    entries.push(Arm64XRelocation {
                        rva,
                        size,
                        value,
                        kind: Arm64XFixupKind::Value,
                    });
                    index += words_needed;
                }
                IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA => {
                    if index + 2 > words {
                        return Err(malformed("ARM64X delta relocation is truncated"));
                    }
                    let raw_delta = u16::from_le_bytes([
                        block[8 + (index + 1) * 2],
                        block[9 + (index + 1) * 2],
                    ]);
                    let negative = arg & 1 != 0;
                    let scale = if arg & 2 != 0 { 8 } else { 4 };
                    let mut delta = i64::from(raw_delta) * scale;
                    if negative {
                        delta = -delta;
                    }
                    if rva % 4 != 0 {
                        return Err(malformed("unaligned ARM64X delta relocation"));
                    }
                    entries.push(Arm64XRelocation {
                        rva,
                        size: 4,
                        value: delta as u64,
                        kind: Arm64XFixupKind::Delta,
                    });
                    index += 2;
                }
                _ => return Err(malformed("invalid ARM64X relocation type")),
            }
            if rva >= size_of_image || rva.saturating_add(4) > size_of_image {
                return Err(malformed("ARM64X relocation target exceeds SizeOfImage"));
            }
        }
        blocks.push(Arm64XDynamicRelocationBlock { page_rva, entries });
        cursor += block_size;
        cursor = (cursor + 3) & !3;
    }
    Ok(blocks)
}

pub fn parse_arm64_exception_table(
    bytes: &[u8],
    sections: &[PeSection],
    directory: DataDirectory,
    kind: Arm64PdataKind,
) -> AppResult<Option<Arm64ExceptionTable>> {
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(None);
    }
    let entry_size: usize = match kind {
        Arm64PdataKind::X64 => 12,
        Arm64PdataKind::Arm64 => 8,
    };
    if directory.size as usize % entry_size != 0 {
        return Err(malformed(
            "exception directory is not a whole number of entries",
        ));
    }
    let data = read_at(
        bytes,
        sections,
        directory.virtual_address,
        directory.size,
        "exception directory",
    )
    .map_err(|_| malformed("exception directory is truncated"))?;
    let count = data.len() / entry_size;
    let mut functions = Vec::with_capacity(count);
    let mut unwind_info = Vec::new();
    for index in 0..count {
        let offset = index * entry_size;
        let begin_address = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        match kind {
            Arm64PdataKind::X64 => {
                let end_address = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                let unwind_data = u32::from_le_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                ]);
                if end_address < begin_address {
                    return Err(malformed("x64 runtime function has an inverted range"));
                }
                functions.push(Arm64RuntimeFunction {
                    begin_address,
                    end_address,
                    unwind_data,
                    unwind_info_rva: Some(unwind_data),
                });
            }
            Arm64PdataKind::Arm64 => {
                let unwind_data = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                let flag = unwind_data & 0x3;
                let (function_length, unwind_info_rva) = if flag == 0 {
                    let info_rva = unwind_data;
                    let info = parse_arm64_unwind_info(bytes, sections, info_rva)?;
                    let function_length = info.function_length;
                    unwind_info.push(info);
                    (function_length, Some(info_rva))
                } else {
                    let function_length = (unwind_data >> 2) & 0x7ff;
                    if function_length == 0 {
                        return Err(malformed("packed ARM64 runtime function has zero length"));
                    }
                    (function_length, None)
                };
                functions.push(Arm64RuntimeFunction {
                    begin_address,
                    end_address: begin_address.saturating_add(function_length),
                    unwind_data,
                    unwind_info_rva,
                });
            }
        }
    }
    Ok(Some(Arm64ExceptionTable {
        kind,
        directory,
        functions,
        unwind_info,
    }))
}

pub fn parse_arm64_unwind_info(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u32,
) -> AppResult<Arm64UnwindInfo> {
    let header = read_u32_at(bytes, sections, rva, "ARM64 unwind header")
        .map_err(|_| malformed("ARM64 unwind info is truncated"))?;
    let function_length = header & 0x3ffff;
    let version = ((header >> 18) & 0x3) as u8;
    let exception_data_present = (header >> 20) & 1 != 0;
    let epilog_in_header = (header >> 21) & 1 != 0;
    let epilog_count = (header >> 22) & 0x1f;
    let code_words = (header >> 27) & 0x1f;
    if function_length == 0 {
        return Err(malformed("ARM64 unwind info has zero function length"));
    }
    let mut body_words = if epilog_in_header { 1 } else { epilog_count };
    body_words = body_words
        .checked_add(code_words)
        .ok_or_else(|| malformed("ARM64 unwind code word count overflows"))?;
    let body_size = body_words
        .checked_mul(4)
        .ok_or_else(|| malformed("ARM64 unwind code size overflows"))?;
    let end = rva
        .checked_add(4)
        .and_then(|start| start.checked_add(body_size))
        .ok_or_else(|| malformed("ARM64 unwind info range overflows"))?;
    if end < rva {
        return Err(malformed("ARM64 unwind info range overflows"));
    }
    let _ = read_at(
        bytes,
        sections,
        rva + 4,
        body_size,
        "ARM64 unwind info body",
    )
    .map_err(|_| malformed("ARM64 unwind info is truncated"))?;
    let handler_rva = if exception_data_present {
        let handler_offset = rva
            .checked_add(4 + body_size)
            .ok_or_else(|| malformed("ARM64 unwind handler offset overflows"))?;
        Some(
            read_u32_at(bytes, sections, handler_offset, "ARM64 unwind handler")
                .map_err(|_| malformed("ARM64 unwind exception data is truncated"))?,
        )
    } else {
        None
    };
    Ok(Arm64UnwindInfo {
        function_length,
        version,
        exception_data_present,
        epilog_in_header,
        epilog_count,
        code_words,
        handler_rva,
    })
}

pub fn parse_image_metadata(
    bytes: &[u8],
    image: &ParsedPe,
    load_config: Option<&LoadConfig>,
) -> AppResult<Option<Arm64ImageMetadata>> {
    let Some(machine) = HybridMachine::from_machine(image.machine) else {
        return Ok(None);
    };
    let pointer_bytes = image.pointer_bytes();
    let image_base = image.image_base;
    let chpe = match load_config.and_then(|config| {
        let pointer = if pointer_bytes == 8 {
            config.chpe_metadata_pointer
        } else {
            config.chpe_metadata_pointer
        };
        (pointer != 0).then_some(pointer)
    }) {
        Some(pointer) => Some(parse_chpe_metadata(
            bytes,
            &image.sections,
            image_base,
            image.size_of_image,
            pointer,
        )?),
        None if machine.is_hybrid() => {
            return Err(malformed(format!(
                "{} image is missing CHPE metadata",
                machine_name(image.machine)
            )));
        }
        None => None,
    };

    let mut dynamic_relocations = Vec::new();
    if image.machine == IMAGE_FILE_MACHINE_ARM64X {
        if let Some(config) = load_config {
            let table = if config.dynamic_value_reloc_table_section != 0 {
                let index = usize::from(config.dynamic_value_reloc_table_section - 1);
                let section = image.sections.get(index).ok_or_else(|| {
                    malformed("ARM64X dynamic relocation section index is out of range")
                })?;
                Some((
                    section
                        .virtual_address
                        .checked_add(config.dynamic_value_reloc_table_offset)
                        .ok_or_else(|| malformed("ARM64X dynamic relocation RVA overflows"))?,
                    section
                        .raw_data_size
                        .saturating_sub(config.dynamic_value_reloc_table_offset),
                ))
            } else if config.dynamic_value_reloc_table != 0 {
                Some((
                    checked_va_to_rva(config.dynamic_value_reloc_table, image_base)?,
                    image.size_of_image,
                ))
            } else {
                None
            };
            if let Some((rva, size)) = table {
                dynamic_relocations = parse_arm64x_dynamic_relocations(
                    bytes,
                    &image.sections,
                    rva,
                    size,
                    image.size_of_image,
                )?;
            }
        }
    }

    let exception_directory = image.directory(crate::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    let mut exception_tables = Vec::new();
    let exception_kind = if image.machine == IMAGE_FILE_MACHINE_ARM64EC {
        Arm64PdataKind::X64
    } else {
        Arm64PdataKind::Arm64
    };
    if let Some(table) =
        parse_arm64_exception_table(bytes, &image.sections, exception_directory, exception_kind)?
    {
        exception_tables.push(table);
    }
    if image.machine == IMAGE_FILE_MACHINE_ARM64X
        && let Some(chpe) = chpe.as_ref()
        && chpe.extra_rfe_table_rva != 0
        && chpe.extra_rfe_table_size != 0
    {
        let extra = DataDirectory {
            virtual_address: chpe.extra_rfe_table_rva,
            size: chpe.extra_rfe_table_size,
        };
        if let Some(table) =
            parse_arm64_exception_table(bytes, &image.sections, extra, Arm64PdataKind::Arm64)?
        {
            exception_tables.push(table);
        }
    }

    let extra_rfe_table = chpe.as_ref().and_then(|chpe| {
        (chpe.extra_rfe_table_rva != 0 && chpe.extra_rfe_table_size != 0).then_some(DataDirectory {
            virtual_address: chpe.extra_rfe_table_rva,
            size: chpe.extra_rfe_table_size,
        })
    });
    Ok(Some(Arm64ImageMetadata {
        machine: image.machine,
        chpe,
        dynamic_relocations,
        extra_rfe_table,
        exception_tables,
    }))
}

pub fn apply_arm64x_relocations(image: &ParsedPe, mapped: &mut MappedImage) -> AppResult<()> {
    let Some(metadata) = image.arm64.as_ref() else {
        return Ok(());
    };
    for block in &metadata.dynamic_relocations {
        for entry in &block.entries {
            let offset = entry.rva as usize;
            let end = offset
                .checked_add(entry.size as usize)
                .ok_or_else(|| malformed("ARM64X relocation target overflows"))?;
            if end > mapped.memory.len() {
                return Err(malformed(
                    "ARM64X relocation target exceeds the mapped image",
                ));
            }
            match entry.kind {
                Arm64XFixupKind::ZeroFill => {
                    mapped.memory[offset..end].fill(0);
                }
                Arm64XFixupKind::Value => {
                    let bytes = entry.value.to_le_bytes();
                    mapped.memory[offset..end].copy_from_slice(&bytes[..entry.size as usize]);
                }
                Arm64XFixupKind::Delta => {
                    let current = u32::from_le_bytes([
                        mapped.memory[offset],
                        mapped.memory[offset + 1],
                        mapped.memory[offset + 2],
                        mapped.memory[offset + 3],
                    ]);
                    let updated = (i64::from(current) + entry.value as i64) as u32;
                    mapped.memory[offset..offset + 4].copy_from_slice(&updated.to_le_bytes());
                }
            }
        }
    }
    Ok(())
}

pub fn route_entry_point(image: &ParsedPe, view: HybridView) -> AppResult<u32> {
    let native_entry = image.address_of_entry_point;
    let Some(metadata) = image.arm64.as_ref() else {
        return Ok(native_entry);
    };
    match view {
        HybridView::Native => {
            if let Some(chpe) = metadata.chpe.as_ref() {
                if let Some(target) = chpe.route_entry_point(native_entry) {
                    return Ok(target);
                }
            }
            Ok(native_entry)
        }
        HybridView::Emulation => {
            let chpe = metadata
                .chpe
                .as_ref()
                .ok_or_else(|| malformed("hybrid image is missing CHPE metadata"))?;
            if chpe.alternate_entry_point_rva != 0 {
                Ok(chpe.alternate_entry_point_rva)
            } else {
                Ok(native_entry)
            }
        }
    }
}

pub fn route_export(
    image: &ParsedPe,
    name: Option<&str>,
    ordinal: u32,
    view: HybridView,
) -> AppResult<Option<u32>> {
    let Some(export) = image.exports.iter().find(|export| {
        export.ordinal == ordinal
            && name.is_none_or(|expected| export.name.as_deref() == Some(expected))
    }) else {
        return Ok(None);
    };
    let target = match &export.target {
        crate::pe::ExportTarget::Rva(rva) => *rva,
        crate::pe::ExportTarget::Forwarder(_) => {
            return Err(malformed(
                "forwarded hybrid exports require provider resolution",
            ));
        }
    };
    let Some(metadata) = image.arm64.as_ref() else {
        return Ok(Some(target));
    };
    let Some(chpe) = metadata.chpe.as_ref() else {
        return Ok(Some(target));
    };
    Ok(Some(match view {
        HybridView::Native => chpe.route_entry_point(target).unwrap_or(target),
        HybridView::Emulation => chpe
            .redirect_target(target)
            .or_else(|| {
                chpe.redirections
                    .iter()
                    .find(|redirect| redirect.destination_rva == target)
                    .map(|redirect| redirect.source_rva)
            })
            .unwrap_or(target),
    }))
}

pub fn validate_hybrid_image(image: &ParsedPe) -> AppResult<()> {
    let Some(machine) = HybridMachine::from_machine(image.machine) else {
        return Err(malformed(format!(
            "unsupported machine 0x{:04x}",
            image.machine
        )));
    };
    if machine.is_hybrid()
        && image
            .arm64
            .as_ref()
            .is_none_or(|metadata| metadata.chpe.is_none())
    {
        return Err(malformed(format!(
            "{} image is missing CHPE metadata",
            machine_name(image.machine)
        )));
    }
    Ok(())
}

pub fn relocation_kind_from_base_type(kind: u16) -> Option<RelocationType> {
    match kind {
        0 => Some(RelocationType::Absolute),
        3 => Some(RelocationType::HighLow),
        10 => Some(RelocationType::Dir64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{ExportSymbol, ExportTarget, PeSection};

    fn section(rva: u32, len: u32) -> PeSection {
        PeSection {
            name: ".rdata".to_string(),
            virtual_address: rva,
            virtual_size: len,
            raw_data_ptr: rva,
            raw_data_size: len,
            characteristics: 0x4000_0040,
        }
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn image_with_metadata(machine: u16, bytes: &[u8]) -> ParsedPe {
        let mut image = crate::pe::pe_stub_for_tests();
        image.machine = machine;
        image.sections = vec![section(0x1000, 0x1000)];
        image.size_of_image = 0x2000;
        image.load_config = Some(LoadConfig {
            chpe_metadata_pointer: 0x1000,
            ..LoadConfig::default()
        });
        image.arm64 = parse_image_metadata(bytes, &image, image.load_config.as_ref())
            .expect("metadata parse");
        image
    }

    fn valid_metadata() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x1000, 1);
        put_u32(&mut bytes, 0x1004, 0x1100);
        put_u32(&mut bytes, 0x1008, 2);
        put_u32(&mut bytes, 0x100c, 0x1140);
        put_u32(&mut bytes, 0x1010, 0x1160);
        put_u32(&mut bytes, 0x1028, 0x1180);
        put_u32(&mut bytes, 0x1030, 1);
        put_u32(&mut bytes, 0x1034, 1);
        put_u32(&mut bytes, 0x1038, 0);
        put_u32(&mut bytes, 0x103c, 0);
        put_u32(&mut bytes, 0x1040, 0);
        put_u32(&mut bytes, 0x1044, 0);
        put_u32(&mut bytes, 0x1100, 0x1000);
        put_u32(&mut bytes, 0x1104, 0x800);
        put_u32(&mut bytes, 0x1108, 0x1800);
        put_u32(&mut bytes, 0x110c, 0x400);
        put_u32(&mut bytes, 0x1140, 0x1000);
        put_u32(&mut bytes, 0x1144, 0x1800);
        put_u32(&mut bytes, 0x1148, 0x1000);
        put_u32(&mut bytes, 0x1160, 0x1800);
        put_u32(&mut bytes, 0x1164, 0x1000);
        bytes
    }

    #[test]
    fn arm64x_truncated_chpe_metadata_is_rejected() {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x1000, 1);
        let error = parse_chpe_metadata(
            &bytes,
            &[section(0x1000, 4)],
            0x1_8000_0000,
            0x2000,
            0x1_8000_1000,
        )
        .expect_err("truncated metadata must be rejected");
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(error.message, "CHPE metadata is truncated at field 1");
    }

    #[test]
    fn arm64ec_missing_chpe_code_map_is_rejected_exactly() {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x1000, 1);
        put_u32(&mut bytes, 0x1004, 0x1100);
        put_u32(&mut bytes, 0x1008, 0);
        let error = parse_chpe_metadata(
            &bytes,
            &[section(0x1000, 0x1000)],
            0x1_8000_0000,
            0x2000,
            0x1_8000_1000,
        )
        .expect_err("missing code map must be rejected");
        assert_eq!(error.message, "ARM64EC image is missing the CHPE code map");
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
    }

    #[test]
    fn chpe_unsupported_version_is_rejected_exactly() {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x1000, 3);
        let error = parse_chpe_metadata(&bytes, &[section(0x1000, 0x1000)], 0, 0x2000, 0x1000)
            .expect_err("unsupported metadata version must be rejected");
        assert_eq!(error.message, "unsupported CHPE metadata version 3");
    }

    #[test]
    fn chpe_reserved_code_range_type_is_rejected() {
        let mut bytes = valid_metadata();
        put_u32(&mut bytes, 0x1100, 3);
        let error = parse_chpe_metadata(&bytes, &[section(0x1000, 0x1000)], 0, 0x2000, 0x1000)
            .expect_err("reserved code range type must be rejected");
        assert_eq!(
            error.message,
            "CHPE code map contains reserved range type 3"
        );
    }

    #[test]
    fn chpe_code_map_exceeding_image_is_rejected() {
        let mut bytes = valid_metadata();
        put_u32(&mut bytes, 0x1104, 0x10000);
        let error = parse_chpe_metadata(&bytes, &[section(0x1000, 0x1000)], 0, 0x2000, 0x1000)
            .expect_err("out-of-image code range must be rejected");
        assert_eq!(error.message, "CHPE code map entry exceeds SizeOfImage");
    }

    #[test]
    fn arm64x_invalid_dynamic_relocation_type_is_rejected() {
        let mut data = vec![0u8; 0x1100];
        put_u32(&mut data, 0x1000, 1);
        put_u32(&mut data, 0x1004, 24);
        put_u32(&mut data, 0x1008, 6);
        put_u32(&mut data, 0x1010, 12);
        put_u32(&mut data, 0x1014, 0x1000);
        put_u32(&mut data, 0x1018, 12);
        data[0x101c..0x101e].copy_from_slice(&0x7000u16.to_le_bytes());
        let error = parse_arm64x_dynamic_relocations(
            &data,
            &[section(0x1000, 0x100)],
            0x1000,
            0x20,
            0x2000,
        )
        .expect_err("invalid relocation type must be rejected");
        assert_eq!(error.message, "invalid ARM64X relocation type");
    }

    #[test]
    fn arm64x_dynamic_relocation_parser_boundary_is_pinned() {
        let mut data = vec![0u8; 0x2000];
        put_u32(&mut data, 0x1000, 1);
        put_u32(&mut data, 0x1004, 32);
        put_u32(&mut data, 0x1008, 6);
        put_u32(&mut data, 0x1010, 20);
        put_u32(&mut data, 0x1014, 0x1000);
        put_u32(&mut data, 0x1018, 20);
        data[0x101c..0x101e].copy_from_slice(&0x9000u16.to_le_bytes());
        data[0x101e..0x1022].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        data[0x1022..0x1024].copy_from_slice(&0x2004u16.to_le_bytes());
        data[0x1024..0x1026].copy_from_slice(&2u16.to_le_bytes());
        let blocks =
            parse_arm64x_dynamic_relocations(&data, &[section(0x1000, 0x1000)], 0x1000, 40, 0x2000)
                .expect("parse ARM64X dynamic relocations");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].entries.len(), 2);
        assert_eq!(blocks[0].entries[0].value, 0x1234_5678);
        assert_eq!(blocks[0].entries[1].value, 8);
    }

    #[test]
    fn arm64x_unaligned_dynamic_relocation_is_rejected() {
        let mut data = vec![0u8; 0x1100];
        put_u32(&mut data, 0x1000, 1);
        put_u32(&mut data, 0x1004, 24);
        put_u32(&mut data, 0x1008, 6);
        put_u32(&mut data, 0x1010, 12);
        put_u32(&mut data, 0x1014, 0x1000);
        put_u32(&mut data, 0x1018, 12);
        data[0x101c..0x101e].copy_from_slice(&0x5001u16.to_le_bytes());
        let error = parse_arm64x_dynamic_relocations(
            &data,
            &[section(0x1000, 0x100)],
            0x1000,
            0x20,
            0x2000,
        )
        .expect_err("unaligned value relocation must be rejected");
        assert_eq!(error.message, "unaligned ARM64X value relocation");
    }

    #[test]
    fn arm64_exception_directory_truncation_is_rejected() {
        let bytes = vec![0u8; 0x10];
        let error = parse_arm64_exception_table(
            &bytes,
            &[section(0x1000, 0x10)],
            DataDirectory {
                virtual_address: 0x1000,
                size: 12,
            },
            Arm64PdataKind::Arm64,
        )
        .expect_err("non-multiple exception size must be rejected");
        assert_eq!(
            error.message,
            "exception directory is not a whole number of entries"
        );
    }

    #[test]
    fn arm64_unwind_exception_handler_boundary_is_pinned() {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x1000, 0x2000);
        put_u32(&mut bytes, 0x1004, 0x1100);
        put_u32(&mut bytes, 0x1100, (1 << 18) | (1 << 20) | 0x40);
        put_u32(&mut bytes, 0x1104, 0x1200);
        let table = parse_arm64_exception_table(
            &bytes,
            &[section(0x1000, 0x1000)],
            DataDirectory {
                virtual_address: 0x1000,
                size: 8,
            },
            Arm64PdataKind::Arm64,
        )
        .expect("parse ARM64 exception table")
        .expect("table present");
        assert_eq!(table.functions.len(), 1);
        assert_eq!(table.functions[0].end_address, 0x2040);
        assert_eq!(table.unwind_info[0].handler_rva, Some(0x1200));
        assert_eq!(table.unwind_info[0].function_length, 0x40);
    }

    #[test]
    fn arm64_unwind_truncation_is_rejected() {
        let bytes = vec![0u8; 0x10];
        let error = parse_arm64_unwind_info(&bytes, &[section(0x1000, 0x10)], 0x1000)
            .expect_err("truncated unwind must be rejected");
        assert_eq!(error.message, "ARM64 unwind info is truncated");
    }

    #[test]
    fn missing_chpe_metadata_pointer_for_hybrid_image_is_rejected() {
        let mut image = crate::pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64EC;
        let error = parse_image_metadata(&[], &image, None)
            .expect_err("ARM64EC without metadata must be rejected");
        assert_eq!(error.message, "ARM64EC image is missing CHPE metadata");
    }

    #[test]
    fn route_entry_point_redirection_boundary_is_pinned() {
        let bytes = valid_metadata();
        let image = image_with_metadata(IMAGE_FILE_MACHINE_ARM64EC, &bytes);
        assert_eq!(
            route_entry_point(&image, HybridView::Native).unwrap(),
            0x1000
        );
        assert_eq!(
            route_entry_point(&image, HybridView::Emulation).unwrap(),
            0x1180
        );
    }

    #[test]
    fn route_export_native_emulation_boundary_is_pinned() {
        let bytes = valid_metadata();
        let mut image = image_with_metadata(IMAGE_FILE_MACHINE_ARM64EC, &bytes);
        image.exports = vec![ExportSymbol {
            ordinal: 1,
            name: Some("Run".to_string()),
            target: ExportTarget::Rva(0x1000),
        }];
        assert_eq!(
            route_export(&image, Some("Run"), 1, HybridView::Native).unwrap(),
            Some(0x1000)
        );
        assert_eq!(
            route_export(&image, Some("Run"), 1, HybridView::Emulation).unwrap(),
            Some(0x1800)
        );
    }

    #[test]
    fn arm64x_dynamic_value_and_delta_boundary_applies() {
        let mut image = crate::pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64X;
        image.arm64 = Some(Arm64ImageMetadata {
            machine: IMAGE_FILE_MACHINE_ARM64X,
            chpe: None,
            dynamic_relocations: vec![Arm64XDynamicRelocationBlock {
                page_rva: 0,
                entries: vec![
                    Arm64XRelocation {
                        rva: 0,
                        size: 4,
                        value: 0x1234,
                        kind: Arm64XFixupKind::Value,
                    },
                    Arm64XRelocation {
                        rva: 4,
                        size: 4,
                        value: 8,
                        kind: Arm64XFixupKind::Delta,
                    },
                    Arm64XRelocation {
                        rva: 8,
                        size: 2,
                        value: 0,
                        kind: Arm64XFixupKind::ZeroFill,
                    },
                ],
            }],
            extra_rfe_table: None,
            exception_tables: Vec::new(),
        });
        let mut mapped = MappedImage {
            preferred_base: 0,
            selected_base: 0,
            memory: vec![0xff; 16],
            sections: Vec::new(),
        };
        apply_arm64x_relocations(&image, &mut mapped).unwrap();
        assert_eq!(&mapped.memory[0..4], &0x1234u32.to_le_bytes());
        assert_eq!(&mapped.memory[4..8], &7u32.to_le_bytes());
        assert_eq!(&mapped.memory[8..10], &[0, 0]);
    }

    #[test]
    fn arm64x_relocation_beyond_image_is_rejected() {
        let mut image = crate::pe::pe_stub_for_tests();
        image.arm64 = Some(Arm64ImageMetadata {
            machine: IMAGE_FILE_MACHINE_ARM64X,
            chpe: None,
            dynamic_relocations: vec![Arm64XDynamicRelocationBlock {
                page_rva: 0,
                entries: vec![Arm64XRelocation {
                    rva: 0x20,
                    size: 8,
                    value: 0,
                    kind: Arm64XFixupKind::Value,
                }],
            }],
            extra_rfe_table: None,
            exception_tables: Vec::new(),
        });
        let mut mapped = MappedImage {
            preferred_base: 0,
            selected_base: 0,
            memory: vec![0; 16],
            sections: Vec::new(),
        };
        let error = apply_arm64x_relocations(&image, &mut mapped)
            .expect_err("out-of-image dynamic relocation must be rejected");
        assert_eq!(
            error.message,
            "ARM64X relocation target exceeds the mapped image"
        );
    }
    #[test]
    fn arm64x_chpe_code_map_overlap_is_rejected_exactly() {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x1000, 1);
        put_u32(&mut bytes, 0x1004, 0x1100);
        put_u32(&mut bytes, 0x1008, 2);
        put_u32(&mut bytes, 0x1100, 0x1000 | 1);
        put_u32(&mut bytes, 0x1104, 0x400);
        put_u32(&mut bytes, 0x1108, 0x1200 | 2);
        put_u32(&mut bytes, 0x110c, 0x400);
        let error = parse_chpe_metadata(&bytes, &[section(0x1000, 0x1000)], 0, 0x2000, 0x1000)
            .expect_err("overlapping code map must be rejected");
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(
            error.message,
            "CHPE code map entries overlap or are unsorted"
        );
    }

    #[test]
    fn arm64x_ec_entry_thunk_metadata_masks_tags_and_rejects_oob_exactly() {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x0ffc, 0x200 | 3);
        let target = parse_ec_entry_thunk_rva(&bytes, &[section(0x0f00, 0x200)], 0x1000, 0x2000)
            .expect("entry thunk")
            .expect("tagged delta resolves");
        assert_eq!(target, 0x1200);

        put_u32(&mut bytes, 0x0ffc, 0x2000 | 1);
        let error = parse_ec_entry_thunk_rva(&bytes, &[section(0x0f00, 0x200)], 0x1000, 0x2000)
            .expect_err("out-of-image entry thunk must fail");
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(
            error.message,
            "ARM64EC entry thunk points outside the image"
        );
    }

    #[test]
    fn arm64x_ec_thunk_body_detection_boundary_routes_the_real_body_exactly() {
        let image_base = 0x1_8000_0000u64;
        let mut mapped = vec![0u8; 0x3000];
        // Body at 0x1000 has metadata pointing at entry thunk 0x1100.
        put_u32(&mut mapped, 0x0ffc, 0x100 | 1);
        let route = detect_ec_thunk_body(&mapped, image_base, 0x1100, 0x1000, 0x1200, 0x3000)
            .expect("detect EC entry thunk")
            .expect("metadata route");
        assert_eq!(
            route,
            EcThunkRoute {
                kind: EcThunkKind::EcEntryThunk,
                body_rva: 0x1000
            }
        );

        // Twelve-byte x64 entry stub at 0x1200 targeting the body.
        mapped[0x1200..0x1202].copy_from_slice(&[0x48, 0xb8]);
        mapped[0x1202..0x120a].copy_from_slice(&(image_base + 0x1000).to_le_bytes());
        mapped[0x120a..0x120c].copy_from_slice(&[0xff, 0xe0]);
        let route = detect_ec_thunk_body(&mapped, image_base, 0x1200, 0x1200, 0x1300, 0x3000)
            .expect("detect x64 entry stub")
            .expect("stub route");
        assert_eq!(
            route,
            EcThunkRoute {
                kind: EcThunkKind::X64EntryStub,
                body_rva: 0x1000
            }
        );

        // Canonical x64 fast-forward sequence at 0x1300 tail-jumping to 0x1000.
        let prefix = [0x48u8, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9];
        mapped[0x1300..0x130a].copy_from_slice(&prefix);
        let next = 0x1300i64 + 14;
        let displacement = 0x1000i64 - next;
        mapped[0x130a..0x130e].copy_from_slice(&(displacement as i32).to_le_bytes());
        let route = detect_ec_thunk_body(&mapped, image_base, 0x1300, 0x1300, 0x1400, 0x3000)
            .expect("detect fast-forward thunk")
            .expect("fast-forward route");
        assert_eq!(
            route,
            EcThunkRoute {
                kind: EcThunkKind::X64FastForward,
                body_rva: 0x1000
            }
        );

        put_u32(&mut mapped, 0x1800, 0xd65f_03c0);
        assert_eq!(
            detect_ec_thunk_body(&mapped, image_base, 0x1800, 0x1800, 0x1900, 0x3000)
                .expect("ordinary body is not a thunk"),
            None
        );
    }

    #[test]
    fn arm64x_ec_thunk_detection_rejects_malformed_metadata_exactly() {
        let image_base = 0x1_8000_0000u64;
        let mut mapped = vec![0u8; 0x2000];
        mapped[0x1200..0x1202].copy_from_slice(&[0x48, 0xb8]);
        mapped[0x1202..0x120a].copy_from_slice(&(image_base + 0x3000).to_le_bytes());
        mapped[0x120a..0x120c].copy_from_slice(&[0xff, 0xe0]);
        let outside = detect_ec_thunk_body(&mapped, image_base, 0x1200, 0x1200, 0x1300, 0x2000)
            .expect_err("out-of-image stub target must be rejected");
        assert_eq!(outside.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(
            outside.message,
            "ARM64EC x64 entry stub target lies outside the image"
        );

        let oversized = detect_ec_thunk_body(
            &[],
            image_base,
            0,
            0,
            EC_THUNK_SCAN_LIMIT + 1,
            EC_THUNK_SCAN_LIMIT + 1,
        )
        .expect_err("oversized scan range must fail closed");
        assert_eq!(
            oversized.message,
            "ARM64EC thunk scan range exceeds the supported limit"
        );

        let outside_target = detect_ec_thunk_body(&mapped, image_base, 0x2000, 0, 0x1000, 0x2000)
            .expect_err("target outside SizeOfImage must be rejected");
        assert_eq!(
            outside_target.message,
            "ARM64EC thunk target is outside SizeOfImage"
        );

        let unmapped = detect_ec_thunk_body(&[0u8; 0x100], image_base, 0, 0, 0x1000, 0x1000)
            .expect_err("unmapped scan range must be rejected");
        assert_eq!(unmapped.message, "ARM64EC thunk scan range is not mapped");
    }

    #[test]
    fn arm64x_ec_function_classification_boundary_is_pinned() {
        let mut bytes = vec![0u8; 0x2000];
        put_u32(&mut bytes, 0x1000, 1);
        put_u32(&mut bytes, 0x1004, 0x1100);
        put_u32(&mut bytes, 0x1008, 2);
        put_u32(&mut bytes, 0x1100, 0x1000 | 1);
        put_u32(&mut bytes, 0x1104, 0x400);
        put_u32(&mut bytes, 0x1108, 0x1400 | 2);
        put_u32(&mut bytes, 0x110c, 0x400);
        let chpe = parse_chpe_metadata(&bytes, &[section(0x1000, 0x1000)], 0, 0x2000, 0x1000)
            .expect("parse code map");
        assert_eq!(chpe.function_kind_at(0x1000), Some(EcFunctionKind::Arm64Ec));
        assert_eq!(chpe.function_kind_at(0x13ff), Some(EcFunctionKind::Arm64Ec));
        assert_eq!(chpe.function_kind_at(0x1400), Some(EcFunctionKind::X64));
        assert_eq!(chpe.function_kind_at(0x17ff), Some(EcFunctionKind::X64));
        assert_eq!(chpe.function_kind_at(0x1800), None);
    }
}
