//! Native ARM64 execution, the Windows AArch64 ABI bridge, TEB/PEB state,
//! import callbacks and the in-process ARM64 image runner.

use crate::arm64x::{
    self, Arm64ImageMetadata, ChpeCodeKind, HybridView, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X,
};
use crate::cpu::{CpuState, MemoryImage};
use crate::error::{AppError, AppResult};
use crate::pe::{self, ImportSymbol, MappedImage, ParsedPe, SectionMapping};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::ptr;

pub const ARM64_REGISTER_COUNT: usize = 31;
pub const ARM64_STACK_ALIGNMENT: u64 = 16;
pub const TEB_CTX_SLOT: usize = 0x100;
pub const TEB_HOST_SP_SLOT: usize = 0x108;
pub const TEB_GUEST_X17_SLOT: usize = 0x110;
pub const TEB_HOST_X18_SLOT: usize = 0x118;
pub const DEFAULT_STACK_SIZE: usize = 0x80_0000;
pub const DEFAULT_TEB_SIZE: usize = 0x1000;

/// Extra executable pages reserved directly after an ARM64EC image for
/// generated transition thunks.  Keeping them adjacent guarantees that a
/// 26-bit `BL` from any code page can reach the thunk.
pub const ARM64EC_THUNK_ARENA_SIZE: usize = 0x10000;

pub const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;

pub const MISSING_CROSS_ISA_PIECE: &str =
    "x64 guest instruction execution under the ARM64EC ABI (the x64<->ARM64EC thunk bridge)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64Register {
    X(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64Isa {
    Arm64,
    X64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossIsaError {
    pub from: Arm64Isa,
    pub to: Arm64Isa,
    pub status: u32,
    pub missing_piece: &'static str,
}

impl CrossIsaError {
    pub const fn new(from: Arm64Isa, to: Arm64Isa) -> Self {
        Self {
            from,
            to,
            status: STATUS_NOT_SUPPORTED,
            missing_piece: MISSING_CROSS_ISA_PIECE,
        }
    }

    pub fn message(&self) -> String {
        format!(
            "ARM64EC cross-ISA transition {:?}->{:?} is fail-closed: missing {} (status 0x{:08x})",
            self.from, self.to, self.missing_piece, self.status
        )
    }

    pub fn to_app_error(&self) -> AppError {
        AppError::new(ReasonCode::RcUnimplInsn, self.message())
            .with_hint(format!("ntstatus=0x{:08x}", self.status))
            .with_hint(format!("missing_piece={}", self.missing_piece))
    }
}

impl std::fmt::Display for CrossIsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for CrossIsaError {}

// ── ARM64EC ↔ x64 transition machinery ──────────────────────────────────
//
// Windows ARM64EC keeps an x64 `CONTEXT` as the canonical register state.
// The mapping below is the one published in `<winnt.h>` (`ARM64EC_NT_CONTEXT`):
// x0=rcx, x1=rdx, x2=r8, x3=r9, x4=r10, x5=r11, x8=rax, x19=r12,
// x20=r13, x21=r14, x22=r15, x25=rsi, x26=rdi, x27=rbx, fp=x29=rbp,
// sp=rsp, pc=rip, lr=x30.  x13, x14, x23, x24 and x28 are blocked.

pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xc000_007b;
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
pub const STATUS_BAD_FUNCTION_TABLE: u32 = 0xc000_00ff;

/// Sentinel written by a failed native call-checker dispatch.
pub const EC_CHECK_FAILED: u64 = u64::MAX;

/// Size of the frame a generated ARM64EC exit thunk hands to the host.
pub const EC_EXIT_FRAME_SIZE: usize = 304;
/// Size of the frame a generated ARM64EC call-checker thunk hands to the host.
pub const EC_CHECK_FRAME_SIZE: usize = 272;

/// x64 GPR index (`Register::index`) → ARM64EC X register.  `Rsp` is `None`
/// because it maps to the architectural stack pointer.
pub const X64_GPR_TO_ARM64: [Option<usize>; 16] = [
    Some(8),  // rax -> x8
    Some(0),  // rcx -> x0
    Some(1),  // rdx -> x1
    Some(27), // rbx -> x27
    None,     // rsp -> sp
    Some(29), // rbp -> fp
    Some(25), // rsi -> x25
    Some(26), // rdi -> x26
    Some(2),  // r8  -> x2
    Some(3),  // r9  -> x3
    Some(4),  // r10 -> x4
    Some(5),  // r11 -> x5
    Some(19), // r12 -> x19
    Some(20), // r13 -> x20
    Some(21), // r14 -> x21
    Some(22), // r15 -> x22
];

/// ARM64EC X register → x64 GPR index (`Register::index`).
pub const ARM64_GPR_TO_X64: [Option<usize>; ARM64_REGISTER_COUNT] = {
    let mut map = [None; ARM64_REGISTER_COUNT];
    map[0] = Some(1);
    map[1] = Some(2);
    map[2] = Some(8);
    map[3] = Some(9);
    map[4] = Some(10);
    map[5] = Some(11);
    map[8] = Some(0);
    map[19] = Some(12);
    map[20] = Some(13);
    map[21] = Some(14);
    map[22] = Some(15);
    map[25] = Some(6);
    map[26] = Some(7);
    map[27] = Some(3);
    map[29] = Some(5);
    map
};

/// x64 non-volatile GPRs paired with their ARM64EC registers.
pub const EC_NONVOLATILE_GPR_PAIRS: [(usize, usize); 8] = [
    (3, 27),  // rbx / x27
    (5, 29),  // rbp / fp
    (6, 25),  // rsi / x25
    (7, 26),  // rdi / x26
    (12, 19), // r12 / x19
    (13, 20), // r13 / x20
    (14, 21), // r14 / x21
    (15, 22), // r15 / x22
];

/// x64 non-volatile XMM registers (`xmm6`-`xmm15`); the full 128 bits are
/// preserved, unlike ARM64 classic where only `d8`-`d15` are callee-saved.
pub const EC_NONVOLATILE_VECTOR_INDICES: [usize; 10] = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcParamKind {
    Integer,
    Float,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcReturnKind {
    Void,
    Integer,
    Float,
    /// Return type is unknown (no PE signature metadata).  Populate both the
    /// integer and vector return registers so either caller convention works.
    Auto,
}

/// How parameter positions are translated when no signature metadata exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcAbiMode {
    /// Use the per-position `EcSignature::params` list.
    Positional,
    /// No type metadata: translate each register class independently.  This
    /// is exact for ordinary calls with at most four integer and four vector
    /// arguments, which covers the overwhelmingly common Windows signatures.
    ClassParallel,
}

/// Signature-specific description of a transition thunk.
///
/// The Windows ARM64EC ABI cannot translate calling conventions with one
/// universal rule: the location of a parameter depends on the types of all
/// preceding parameters.  Entry/exit thunks are therefore per-signature.  This
/// type carries the information the generic host thunk needs to perform the
/// same permutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcSignature {
    pub params: Vec<EcParamKind>,
    pub returns: EcReturnKind,
    pub variadic: bool,
    pub mode: EcAbiMode,
}

impl EcSignature {
    pub fn new(params: impl Into<Vec<EcParamKind>>, returns: EcReturnKind) -> Self {
        Self {
            params: params.into(),
            returns,
            variadic: false,
            mode: EcAbiMode::Positional,
        }
    }

    pub fn integer_arguments(count: usize) -> Self {
        Self {
            params: vec![EcParamKind::Integer; count],
            returns: EcReturnKind::Integer,
            variadic: false,
            mode: EcAbiMode::Positional,
        }
    }

    pub fn all_integer() -> Self {
        Self::integer_arguments(8)
    }

    /// Default translation used when no signature metadata is available.
    pub fn class_parallel() -> Self {
        Self {
            params: Vec::new(),
            returns: EcReturnKind::Auto,
            variadic: false,
            mode: EcAbiMode::ClassParallel,
        }
    }

    fn layouts(&self) -> AppResult<Vec<EcArgLayout>> {
        if self.variadic {
            return Err(EcTransitionError::unsupported(
                "variadic ARM64EC call signatures require `x4`/`x5` stack metadata",
            )
            .to_app_error());
        }
        let mut x64_gprs = [1usize, 2, 8, 9] // rcx, rdx, r8, r9
            .into_iter();
        let mut ec_gprs = (0usize..8).into_iter();
        let mut x64_vectors = (0usize..4).into_iter();
        let mut ec_vectors = (0usize..8).into_iter();
        let mut stack_index = 0u64;
        let mut layouts = Vec::with_capacity(self.params.len());
        for kind in &self.params {
            let (x64, ec) = match kind {
                EcParamKind::Integer => {
                    let x64 = match x64_gprs.next() {
                        Some(register) => EcArgLocation::Gpr(register),
                        None => {
                            let offset = stack_index * 8;
                            stack_index += 1;
                            EcArgLocation::Stack(offset)
                        }
                    };
                    let ec = match ec_gprs.next() {
                        Some(register) => EcArgLocation::Gpr(register),
                        None => {
                            // EC stack slots are laid out independently; keep
                            // the same ordinal so both ABIs agree per arg.
                            let offset = layouts
                                .iter()
                                .filter(|layout: &&EcArgLayout| {
                                    matches!(layout.ec, EcArgLocation::Stack(_))
                                })
                                .count() as u64
                                * 8;
                            EcArgLocation::Stack(offset)
                        }
                    };
                    (x64, ec)
                }
                EcParamKind::Float => {
                    let x64 = match x64_vectors.next() {
                        Some(register) => EcArgLocation::Vector(register),
                        None => {
                            let offset = stack_index * 8;
                            stack_index += 1;
                            EcArgLocation::Stack(offset)
                        }
                    };
                    let ec = match ec_vectors.next() {
                        Some(register) => EcArgLocation::Vector(register),
                        None => {
                            let offset = layouts
                                .iter()
                                .filter(|layout: &&EcArgLayout| {
                                    matches!(layout.ec, EcArgLocation::Stack(_))
                                })
                                .count() as u64
                                * 8;
                            EcArgLocation::Stack(offset)
                        }
                    };
                    (x64, ec)
                }
            };
            layouts.push(EcArgLayout {
                kind: *kind,
                x64,
                ec,
            });
        }
        Ok(layouts)
    }

    pub fn x64_stack_arg_bytes(&self) -> AppResult<u64> {
        Ok(self
            .layouts()?
            .iter()
            .filter(|layout| matches!(layout.x64, EcArgLocation::Stack(_)))
            .count() as u64
            * 8)
    }

    pub fn ec_stack_arg_bytes(&self) -> AppResult<u64> {
        Ok(self
            .layouts()?
            .iter()
            .filter(|layout| matches!(layout.ec, EcArgLocation::Stack(_)))
            .count() as u64
            * 8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcArgLocation {
    /// For x64 layouts this is `Register::index`; for EC layouts it is `xN`.
    Gpr(usize),
    Vector(usize),
    /// Byte offset inside the stack argument area.
    Stack(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcArgLayout {
    pub kind: EcParamKind,
    pub x64: EcArgLocation,
    pub ec: EcArgLocation,
}

/// Raw canonical register state used at an x64 ↔ ARM64EC boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X64AbiState {
    pub gpr: [u64; 16],
    pub xmm: [u128; 16],
    pub rip: u64,
    pub teb: u64,
}

impl Default for X64AbiState {
    fn default() -> Self {
        Self {
            gpr: [0; 16],
            xmm: [0; 16],
            rip: 0,
            teb: 0,
        }
    }
}

impl X64AbiState {
    pub fn from_cpu_state(state: &CpuState) -> Self {
        let mut abi = Self {
            gpr: state.gpr,
            rip: state.rip,
            teb: state.segment_bases.gs,
            ..Self::default()
        };
        for index in 0..16 {
            abi.xmm[index] =
                u128::from(state.xmm[index].low) | (u128::from(state.xmm[index].high) << 64);
        }
        abi
    }

    pub fn write_to_cpu_state(&self, state: &mut CpuState) {
        state.gpr = self.gpr;
        state.rip = self.rip;
        state.segment_bases.gs = self.teb;
        for index in 0..16 {
            state.xmm[index] = crate::cpu::XmmValue {
                low: self.xmm[index] as u64,
                high: (self.xmm[index] >> 64) as u64,
            };
            state.ymm_upper[index] = crate::cpu::XmmValue::default();
        }
    }
}

/// Raw ARM64EC register state at a boundary.  `q` holds full 128-bit vector
/// registers because x64 XMM registers are 128-bit callee-save values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcAbiState {
    pub x: [u64; ARM64_REGISTER_COUNT],
    pub q: [u128; 32],
    pub sp: u64,
    pub pc: u64,
    pub teb: u64,
    pub lr: u64,
}

impl Default for EcAbiState {
    fn default() -> Self {
        Self {
            x: [0; ARM64_REGISTER_COUNT],
            q: [0; 32],
            sp: 0,
            pc: 0,
            teb: 0,
            lr: 0,
        }
    }
}

impl EcAbiState {
    pub fn from_context(context: &Arm64Context) -> Self {
        Self {
            x: context.x,
            q: context.d,
            sp: context.sp,
            pc: context.pc,
            teb: context.x[18],
            lr: context.x[30],
        }
    }

    pub fn write_to_context(&self, context: &mut Arm64Context) {
        context.x = self.x;
        context.d = self.q;
        context.sp = self.sp;
        context.pc = self.pc;
        context.x[18] = self.teb;
        context.x[30] = self.lr;
    }

    pub fn set_teb(&mut self, teb: u64) {
        self.teb = teb;
        self.x[18] = teb;
    }
}

/// Parameters after an x64 → ARM64EC translation, in ARM64EC form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcCallArguments {
    pub gpr: [u64; 8],
    pub vec: [u128; 8],
    pub stack: Vec<u64>,
    pub returns: EcReturnKind,
}

impl Default for EcCallArguments {
    fn default() -> Self {
        Self {
            gpr: [0; 8],
            vec: [0; 8],
            stack: Vec::new(),
            returns: EcReturnKind::Integer,
        }
    }
}

/// Parameters after an ARM64EC → x64 translation, in x64 form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X64CallArguments {
    pub gpr: [u64; 16],
    pub vec: [u128; 16],
    pub stack: Vec<u64>,
    pub returns: EcReturnKind,
}

impl Default for X64CallArguments {
    fn default() -> Self {
        Self {
            gpr: [0; 16],
            vec: [0; 16],
            stack: Vec::new(),
            returns: EcReturnKind::Integer,
        }
    }
}

/// Byte-addressed stack view used while translating arguments.
pub trait EcStackAccess {
    fn read_u64(&self, address: u64) -> AppResult<u64>;
    fn write_u64(&mut self, address: u64, value: u64) -> AppResult<()>;
}

impl EcStackAccess for MemoryImage {
    fn read_u64(&self, address: u64) -> AppResult<u64> {
        self.read_u64(address).map_err(|_| {
            EcTransitionError::fault(format!(
                "ARM64EC transition stack read at 0x{address:016x} is unmapped"
            ))
            .to_app_error()
        })
    }

    fn write_u64(&mut self, address: u64, value: u64) -> AppResult<()> {
        MemoryImage::write_u64(self, address, value);
        Ok(())
    }
}

/// Borrowed byte buffer with an explicit guest base address.
pub struct BufferStack<'a> {
    pub base: u64,
    pub bytes: &'a mut [u8],
}

impl EcStackAccess for BufferStack<'_> {
    fn read_u64(&self, address: u64) -> AppResult<u64> {
        let offset = address.wrapping_sub(self.base) as usize;
        let end = offset.checked_add(8).ok_or_else(|| {
            EcTransitionError::fault("ARM64EC transition stack read overflows").to_app_error()
        })?;
        if end > self.bytes.len() {
            return Err(EcTransitionError::fault(format!(
                "ARM64EC transition stack read at 0x{address:016x} is outside the stack"
            ))
            .to_app_error());
        }
        Ok(u64::from_le_bytes(
            self.bytes[offset..end].try_into().expect("8 bytes"),
        ))
    }

    fn write_u64(&mut self, address: u64, value: u64) -> AppResult<()> {
        let offset = address.wrapping_sub(self.base) as usize;
        let end = offset.checked_add(8).ok_or_else(|| {
            EcTransitionError::fault("ARM64EC transition stack write overflows").to_app_error()
        })?;
        if end > self.bytes.len() {
            return Err(EcTransitionError::fault(format!(
                "ARM64EC transition stack write at 0x{address:016x} is outside the stack"
            ))
            .to_app_error());
        }
        self.bytes[offset..end].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcTransitionError {
    pub status: u32,
    pub detail: String,
}

impl EcTransitionError {
    pub fn new(status: u32, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }

    pub fn fault(detail: impl Into<String>) -> Self {
        Self::new(STATUS_ACCESS_VIOLATION, detail)
    }

    pub fn malformed(detail: impl Into<String>) -> Self {
        Self::new(STATUS_INVALID_IMAGE_FORMAT, detail)
    }

    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::new(STATUS_NOT_SUPPORTED, detail)
    }

    pub fn misaligned(sp: u64, alignment: u64) -> Self {
        Self::new(
            STATUS_ACCESS_VIOLATION,
            format!("ARM64EC stack pointer 0x{sp:016x} is not {alignment}-byte aligned"),
        )
    }

    /// Convert a host-side execution error into the exact Windows status the
    /// boundary must surface.  Explicit `ntstatus=` hints always win; the
    /// fallbacks pin the common guest-memory faults so an access violation in
    /// the other ISA can never be reported as a generic unsupported error.
    pub fn from_app_error(error: &AppError) -> Self {
        let hinted = error
            .reproduction_hints
            .iter()
            .find_map(|hint| hint.strip_prefix("ntstatus=0x"))
            .and_then(|raw| u32::from_str_radix(raw, 16).ok());
        let status = hinted.unwrap_or_else(|| match error.code {
            ReasonCode::RcPeParseInvalid => STATUS_INVALID_IMAGE_FORMAT,
            ReasonCode::RcUnimplInsn
                if error.message.contains("unmapped guest memory")
                    || error.message.contains("access violation") =>
            {
                STATUS_ACCESS_VIOLATION
            }
            ReasonCode::RcInvalidParameter
                if error.message.contains("stack pointer")
                    || error.message.contains("transition stack") =>
            {
                STATUS_ACCESS_VIOLATION
            }
            _ => STATUS_NOT_SUPPORTED,
        });
        Self::new(status, error.message.clone())
    }

    pub fn to_app_error(&self) -> AppError {
        let code = match self.status {
            STATUS_INVALID_IMAGE_FORMAT => ReasonCode::RcPeParseInvalid,
            STATUS_NOT_SUPPORTED => ReasonCode::RcUnimplInsn,
            _ => ReasonCode::RcInvalidParameter,
        };
        AppError::new(code, self.detail.clone())
            .with_hint(format!("ntstatus=0x{:08x}", self.status))
    }
}

impl std::fmt::Display for EcTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (status 0x{:08x})", self.detail, self.status)
    }
}

impl std::error::Error for EcTransitionError {}

fn transition_stack_read(stack: &dyn EcStackAccess, address: u64) -> AppResult<u64> {
    stack.read_u64(address).map_err(|error| {
        EcTransitionError::fault(format!(
            "ARM64EC transition stack read at 0x{address:016x} failed: {}",
            error.message
        ))
        .to_app_error()
    })
}

/// Translate x64 argument registers/stack into ARM64EC form according to
/// `signature`.  Stack arguments are read from `[rsp+0x28 + offset]`
/// (return address + 32-byte shadow space) and returned in EC order.
pub fn x64_to_ec_arguments(
    signature: &EcSignature,
    state: &X64AbiState,
    stack: &dyn EcStackAccess,
) -> AppResult<EcCallArguments> {
    if signature.mode == EcAbiMode::ClassParallel {
        let mut args = EcCallArguments {
            returns: signature.returns,
            ..EcCallArguments::default()
        };
        for (destination, source) in [(0usize, 1usize), (1, 2), (2, 8), (3, 9)] {
            args.gpr[destination] = state.gpr[source];
        }
        args.vec[..4].copy_from_slice(&state.xmm[..4]);
        let mut slot = 0u64;
        loop {
            let address = state.gpr[crate::cpu::Register::Rsp.index()]
                .wrapping_add(0x28)
                .wrapping_add(slot * 8);
            let value = match transition_stack_read(stack, address) {
                Ok(value) => value,
                Err(_) => break,
            };
            let index = 4 + slot as usize;
            if index < 8 {
                args.gpr[index] = value;
                args.vec[index] = value as u128;
            } else {
                args.stack.push(value);
            }
            slot += 1;
            if slot > 8 {
                break;
            }
        }
        return Ok(args);
    }
    let layouts = signature.layouts()?;
    let mut args = EcCallArguments {
        returns: signature.returns,
        ..EcCallArguments::default()
    };
    for (index, layout) in layouts.iter().enumerate() {
        let value = match layout.x64 {
            EcArgLocation::Gpr(register) => state.gpr[register],
            EcArgLocation::Vector(register) => state.xmm[register] as u64,
            EcArgLocation::Stack(offset) => {
                transition_stack_read(stack, state.gpr[4].wrapping_add(0x28).wrapping_add(offset))?
            }
        };
        match layout.ec {
            EcArgLocation::Gpr(register) => args.gpr[register] = value,
            EcArgLocation::Vector(register) => {
                args.vec[register] = value as u128;
            }
            EcArgLocation::Stack(_) => args.stack.push(value),
        }
        let _ = index;
    }
    Ok(args)
}

/// Translate ARM64EC argument registers/stack into x64 form according to
/// `signature`.  Stack values are returned in x64 argument order; the caller
/// writes them starting at `rsp+0x28`.
pub fn ec_to_x64_arguments(
    signature: &EcSignature,
    state: &EcAbiState,
    stack: &dyn EcStackAccess,
) -> AppResult<X64CallArguments> {
    if signature.mode == EcAbiMode::ClassParallel {
        let mut args = X64CallArguments {
            returns: signature.returns,
            ..X64CallArguments::default()
        };
        for (destination, source) in [(1usize, 0usize), (2, 1), (8, 2), (9, 3)] {
            args.gpr[destination] = state.x[source];
        }
        args.vec[..4].copy_from_slice(&state.q[..4]);
        for slot in 0..8u64 {
            match transition_stack_read(stack, state.sp.wrapping_add(slot * 8)) {
                Ok(value) => args.stack.push(value),
                Err(_) => break,
            }
        }
        return Ok(args);
    }
    let layouts = signature.layouts()?;
    let mut args = X64CallArguments {
        returns: signature.returns,
        ..X64CallArguments::default()
    };
    for layout in &layouts {
        let value = match layout.ec {
            EcArgLocation::Gpr(register) => state.x[register],
            EcArgLocation::Vector(register) => state.q[register] as u64,
            EcArgLocation::Stack(offset) => {
                transition_stack_read(stack, state.sp.wrapping_add(offset))?
            }
        };
        match layout.x64 {
            EcArgLocation::Gpr(register) => args.gpr[register] = value,
            EcArgLocation::Vector(register) => {
                args.vec[register] = value as u128;
            }
            EcArgLocation::Stack(_) => args.stack.push(value),
        }
    }
    Ok(args)
}

/// Write translated x64 stack arguments into `stack`, starting after the
/// return address and the 32-byte shadow home area.
pub fn write_x64_stack_arguments(
    args: &X64CallArguments,
    stack: &mut dyn EcStackAccess,
    rsp: u64,
) -> AppResult<()> {
    for (index, value) in args.stack.iter().copied().enumerate() {
        let address = rsp.wrapping_add(0x28).wrapping_add(index as u64 * 8);
        stack.write_u64(address, value)?;
    }
    Ok(())
}

/// Write translated ARM64EC stack arguments into `stack` at `sp`.
pub fn write_ec_stack_arguments(
    args: &EcCallArguments,
    stack: &mut dyn EcStackAccess,
    sp: u64,
) -> AppResult<()> {
    for (index, value) in args.stack.iter().copied().enumerate() {
        stack.write_u64(sp.wrapping_add(index as u64 * 8), value)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X64Return {
    pub rax: u64,
    pub rdx: u64,
    pub xmm0: u128,
    pub xmm1: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcReturn {
    pub x0: u64,
    pub x1: u64,
    pub d0: u128,
    pub d1: u128,
}

/// Convert the return value of an ARM64EC callee to x64 return registers.
pub fn ec_result_to_x64(signature: &EcSignature, result: &EcAbiState) -> X64Return {
    match signature.returns {
        EcReturnKind::Void => X64Return {
            rax: 0,
            rdx: 0,
            xmm0: 0,
            xmm1: 0,
        },
        EcReturnKind::Integer => X64Return {
            rax: result.x[0],
            rdx: result.x[1],
            xmm0: 0,
            xmm1: 0,
        },
        EcReturnKind::Float => X64Return {
            rax: 0,
            rdx: 0,
            xmm0: result.q[0],
            xmm1: result.q[1],
        },
        EcReturnKind::Auto => X64Return {
            rax: result.x[0],
            rdx: result.x[1],
            xmm0: result.q[0],
            xmm1: result.q[1],
        },
    }
}

/// Convert the return value of an x64 callee to ARM64EC return registers.
pub fn x64_result_to_ec(signature: &EcSignature, result: &X64AbiState) -> EcReturn {
    match signature.returns {
        EcReturnKind::Void => EcReturn {
            x0: 0,
            x1: 0,
            d0: 0,
            d1: 0,
        },
        EcReturnKind::Integer => EcReturn {
            x0: result.gpr[crate::cpu::Register::Rax.index()],
            x1: result.gpr[crate::cpu::Register::Rdx.index()],
            d0: 0,
            d1: 0,
        },
        EcReturnKind::Float => EcReturn {
            x0: 0,
            x1: 0,
            d0: result.xmm[0],
            d1: result.xmm[1],
        },
        EcReturnKind::Auto => EcReturn {
            x0: result.gpr[crate::cpu::Register::Rax.index()],
            x1: result.gpr[crate::cpu::Register::Rdx.index()],
            d0: result.xmm[0],
            d1: result.xmm[1],
        },
    }
}

/// Copy the ARM64EC non-volatile registers into the corresponding x64
/// callee-save registers.  This is used when entering x64 from EC so the x64
/// function observes a consistent non-volatile state.
pub fn copy_ec_nonvolatile_to_x64(ec: &EcAbiState, x64: &mut X64AbiState) {
    for (x64_index, arm64_index) in EC_NONVOLATILE_GPR_PAIRS {
        x64.gpr[x64_index] = ec.x[arm64_index];
    }
    for index in EC_NONVOLATILE_VECTOR_INDICES {
        x64.xmm[index] = ec.q[index];
    }
}

/// Copy x64 callee-save registers into the corresponding ARM64EC registers.
pub fn copy_x64_nonvolatile_to_ec(x64: &X64AbiState, ec: &mut EcAbiState) {
    for (x64_index, arm64_index) in EC_NONVOLATILE_GPR_PAIRS {
        ec.x[arm64_index] = x64.gpr[x64_index];
    }
    for index in EC_NONVOLATILE_VECTOR_INDICES {
        ec.q[index] = x64.xmm[index];
    }
}

/// A single cross-ISA unwind record.  It snapshots the caller's canonical
/// state so an exception raised in the other ISA can be propagated back
/// without silently corrupting non-volatile registers or the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcUnwindRecord {
    pub from: Arm64Isa,
    pub to: Arm64Isa,
    pub caller_pc: u64,
    pub caller_sp: u64,
    pub caller_teb: u64,
    pub caller_gpr: [u64; 16],
    pub caller_vec: [u128; 16],
    pub status: u32,
}

impl EcUnwindRecord {
    pub fn from_x64(state: &X64AbiState) -> Self {
        Self {
            from: Arm64Isa::X64,
            to: Arm64Isa::Arm64,
            caller_pc: state.rip,
            caller_sp: state.gpr[crate::cpu::Register::Rsp.index()],
            caller_teb: state.teb,
            caller_gpr: state.gpr,
            caller_vec: state.xmm,
            status: 0,
        }
    }

    pub fn from_ec(state: &EcAbiState) -> Self {
        let mut gpr = [0u64; 16];
        let mut vec = [0u128; 16];
        for (x64_index, arm64_index) in EC_NONVOLATILE_GPR_PAIRS {
            gpr[x64_index] = state.x[arm64_index];
        }
        for index in EC_NONVOLATILE_VECTOR_INDICES {
            vec[index] = state.q[index];
        }
        Self {
            from: Arm64Isa::Arm64,
            to: Arm64Isa::X64,
            caller_pc: state.pc,
            caller_sp: state.sp,
            caller_teb: state.teb,
            caller_gpr: gpr,
            caller_vec: vec,
            status: 0,
        }
    }

    pub fn restore_x64(&self, state: &mut X64AbiState) {
        state.rip = self.caller_pc;
        state.gpr[crate::cpu::Register::Rsp.index()] = self.caller_sp;
        state.teb = self.caller_teb;
        for (x64_index, _) in EC_NONVOLATILE_GPR_PAIRS {
            state.gpr[x64_index] = self.caller_gpr[x64_index];
        }
        for index in EC_NONVOLATILE_VECTOR_INDICES {
            state.xmm[index] = self.caller_vec[index];
        }
    }

    pub fn restore_ec(&self, state: &mut EcAbiState) {
        state.pc = self.caller_pc;
        state.sp = self.caller_sp;
        state.set_teb(self.caller_teb);
        for (x64_index, arm64_index) in EC_NONVOLATILE_GPR_PAIRS {
            state.x[arm64_index] = self.caller_gpr[x64_index];
        }
        for index in EC_NONVOLATILE_VECTOR_INDICES {
            state.q[index] = self.caller_vec[index];
        }
    }
}

/// LIFO chain of transition records.  `unwind` returns records from the
/// innermost transition outwards and attaches the originating status so the
/// caller can re-raise the exact Windows exception.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EcUnwindChain {
    frames: Vec<EcUnwindRecord>,
}

impl EcUnwindChain {
    pub fn push(&mut self, record: EcUnwindRecord) {
        self.frames.push(record);
    }

    pub fn pop(&mut self) -> Option<EcUnwindRecord> {
        self.frames.pop()
    }

    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    pub fn unwind(&mut self, status: u32) -> Vec<EcUnwindRecord> {
        let mut records = Vec::with_capacity(self.frames.len());
        while let Some(mut record) = self.frames.pop() {
            record.status = status;
            records.push(record);
        }
        records
    }
}

thread_local! {
    static EC_TRANSITION_UNWIND: RefCell<EcUnwindChain> =
        RefCell::new(EcUnwindChain::default());
    static EC_LAST_UNWIND: RefCell<Vec<EcUnwindRecord>> = const { RefCell::new(Vec::new()) };
}

fn push_transition_unwind(record: EcUnwindRecord) {
    EC_TRANSITION_UNWIND.with(|chain| chain.borrow_mut().push(record));
}

fn pop_transition_unwind() {
    EC_TRANSITION_UNWIND.with(|chain| {
        chain.borrow_mut().pop();
    });
}

fn unwind_transition(status: u32) {
    let records = EC_TRANSITION_UNWIND.with(|chain| chain.borrow_mut().unwind(status));
    EC_LAST_UNWIND.with(|slot| *slot.borrow_mut() = records);
}

/// Take the records produced by the most recent cross-ISA unwind.  Each record
/// carries the originating NTSTATUS and the caller's non-volatile register
/// snapshot, so diagnostics can prove no silent corruption occurred.
pub fn take_last_unwind_records() -> Vec<EcUnwindRecord> {
    EC_LAST_UNWIND.with(|slot| std::mem::take(&mut *slot.borrow_mut()))
}

/// Result returned by the ARM64EC call checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct EcCheckResult {
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
}

/// Architecture classification and routing for ARM64EC indirect calls.
///
/// The checker is deliberately fail-closed: a target that is not described by
/// the image's CHPE code map cannot be assumed to be native.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcCallChecker {
    pub image_base: u64,
    pub image_size: u32,
    pub ranges: Vec<arm64x::ChpeCodeRange>,
    pub default_native: bool,
}

impl EcCallChecker {
    pub fn for_image(image: &ParsedPe) -> AppResult<Self> {
        let image_base = image.image_base;
        let image_size = image.size_of_image;
        if let Some(chpe) = image.chpe_metadata() {
            if chpe.code_map.is_empty() {
                return Err(EcTransitionError::malformed(
                    "ARM64EC image is missing the CHPE code map",
                )
                .to_app_error());
            }
            chpe.validate_code_map(image_size)?;
            return Ok(Self {
                image_base,
                image_size,
                ranges: chpe.code_map.clone(),
                default_native: false,
            });
        }
        if image.is_arm64ec() || image.is_arm64x() {
            return Err(EcTransitionError::malformed(format!(
                "{} image is missing CHPE metadata",
                arm64x::machine_name(image.machine)
            ))
            .to_app_error());
        }
        Ok(Self {
            image_base,
            image_size,
            ranges: Vec::new(),
            default_native: image.is_arm64(),
        })
    }

    /// Like [`Self::for_image`] but addresses are host addresses produced by
    /// loading the image at `loaded_base`.
    pub fn for_loaded_image(image: &ParsedPe, loaded_base: u64) -> AppResult<Self> {
        let mut checker = Self::for_image(image)?;
        checker.image_base = loaded_base;
        Ok(checker)
    }

    pub fn classify(&self, address: u64) -> Option<arm64x::EcFunctionKind> {
        let rva = address.checked_sub(self.image_base)?;
        if rva >= u64::from(self.image_size) {
            return None;
        }
        let rva = rva as u32;
        if let Some(range) = self.ranges.iter().find(|range| range.contains(rva)) {
            return Some(range.kind.into());
        }
        if self.default_native {
            return Some(arm64x::EcFunctionKind::Arm64);
        }
        None
    }

    /// Implement the register contract of `__os_arm64x_check_icall`:
    /// on entry `target` is in x11 and the signature-specific exit thunk in
    /// x10.  Native targets are returned unchanged in x11; x64 targets route
    /// through the exit thunk while x9 carries the real x64 address.
    pub fn check(&self, target: u64, exit_thunk: u64) -> AppResult<EcCheckResult> {
        match self.classify(target) {
            Some(kind) if kind.is_x64() => Ok(EcCheckResult {
                x9: target,
                x10: exit_thunk,
                x11: exit_thunk,
            }),
            Some(_) => Ok(EcCheckResult {
                x9: target,
                x10: exit_thunk,
                x11: target,
            }),
            None => Err(EcTransitionError::unsupported(format!(
                "ARM64EC call checker cannot classify target 0x{target:016x}"
            ))
            .to_app_error()),
        }
    }
}

/// Encode a function kind as the 32-bit CHPE range type (for tests and for
/// synthesized code maps).
pub fn ec_function_kind_raw(kind: arm64x::EcFunctionKind) -> u32 {
    match kind {
        arm64x::EcFunctionKind::Arm64 => 0,
        arm64x::EcFunctionKind::Arm64Ec => 1,
        arm64x::EcFunctionKind::X64 => 2,
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64Context {
    pub x: [u64; ARM64_REGISTER_COUNT],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: u64,
    pub fpcr: u32,
    pub fpsr: u32,
    pub d: [u128; 32],
}

impl Default for Arm64Context {
    fn default() -> Self {
        Self {
            x: [0; ARM64_REGISTER_COUNT],
            sp: 0,
            pc: 0,
            nzcv: 0,
            fpcr: 0,
            fpsr: 0,
            d: [0; 32],
        }
    }
}

impl Arm64Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, register: usize) -> u64 {
        self.x.get(register).copied().unwrap_or(0)
    }

    pub fn set(&mut self, register: usize, value: u64) {
        if let Some(slot) = self.x.get_mut(register) {
            *slot = value;
        }
    }

    pub fn x0(&self) -> u64 {
        self.x[0]
    }

    pub fn set_x0(&mut self, value: u64) {
        self.x[0] = value;
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.get(index)
    }

    pub fn set_arg(&mut self, index: usize, value: u64) {
        self.set(index, value);
    }

    pub fn teb(&self) -> u64 {
        self.x[18]
    }

    pub fn set_teb(&mut self, address: u64) {
        self.x[18] = address;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64RuntimeFunction {
    pub begin_address: u32,
    pub unwind_data: u32,
}

pub struct Arm64Teb {
    memory: Box<[u8]>,
    peb: Box<Arm64Peb>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Arm64Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    pub mutant: u64,
    pub image_base_address: u64,
    pub ldr: u64,
    pub process_parameters: u64,
    pub sub_system_data: u64,
    pub process_heap: u64,
    pub fast_peb_lock: u64,
    pub atl_thunk_slist_ptr: u64,
    pub ifeo_key: u64,
    pub cross_process_flags: u32,
    pub nt_global_flag: u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_platform_id: u16,
    pub image_sub_system: u16,
    pub image_sub_system_major_version: u16,
    pub image_sub_system_minor_version: u16,
    pub process_affinity_mask: u64,
    pub gdi_shared_handle_table: u32,
    pub using_immutable_file: u32,
    pub process_id: u64,
    pub thread_id: u64,
}

impl Default for Arm64Teb {
    fn default() -> Self {
        Self::new(DEFAULT_STACK_SIZE as u64)
    }
}

impl Arm64Teb {
    pub fn new(stack_size: u64) -> Self {
        let mut memory = vec![0u8; DEFAULT_TEB_SIZE].into_boxed_slice();
        let peb = Box::new(Arm64Peb {
            os_major_version: 10,
            os_minor_version: 0,
            os_build_number: 22631,
            os_platform_id: 2,
            image_sub_system: 3,
            ..Arm64Peb::default()
        });
        let peb_address = (&*peb as *const Arm64Peb) as u64;
        let teb_address = memory.as_ptr() as u64;
        write_u64_slice(&mut memory, 0x08, teb_address + stack_size);
        write_u64_slice(&mut memory, 0x10, teb_address);
        write_u64_slice(&mut memory, 0x30, teb_address);
        write_u64_slice(&mut memory, 0x40, 1);
        write_u64_slice(&mut memory, 0x48, 1);
        write_u64_slice(&mut memory, 0x60, peb_address);
        Self { memory, peb }
    }

    pub fn address(&self) -> u64 {
        self.memory.as_ptr() as u64
    }

    pub fn peb_address(&self) -> u64 {
        (&*self.peb as *const Arm64Peb) as u64
    }

    pub fn peb(&self) -> &Arm64Peb {
        &self.peb
    }

    pub fn peb_mut(&mut self) -> &mut Arm64Peb {
        &mut self.peb
    }

    pub fn set_image_base(&mut self, image_base: u64) {
        self.peb.image_base_address = image_base;
    }

    pub fn set_last_error(&mut self, value: u32) {
        write_u32_slice(&mut self.memory, 0x68, value);
    }

    pub fn last_error(&self) -> u32 {
        read_u32_slice(&self.memory, 0x68)
    }

    pub fn set_tls_pointer(&mut self, value: u64) {
        write_u64_slice(&mut self.memory, 0x58, value);
    }

    pub fn tls_pointer(&self) -> u64 {
        read_u64_slice(&self.memory, 0x58)
    }

    pub fn set_stack(&mut self, stack_base: u64, stack_limit: u64) {
        write_u64_slice(&mut self.memory, 0x08, stack_base);
        write_u64_slice(&mut self.memory, 0x10, stack_limit);
    }

    pub fn host_context_slot(&self) -> u64 {
        read_u64_slice(&self.memory, TEB_CTX_SLOT)
    }

    pub fn host_stack_slot(&self) -> u64 {
        read_u64_slice(&self.memory, TEB_HOST_SP_SLOT)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64Exception {
    StackMisaligned { sp: u64 },
    NullTeb,
    EntryPointOutsideExecutableRegion { pc: u64 },
}

impl Arm64Exception {
    pub const fn nt_status(self) -> u32 {
        STATUS_ACCESS_VIOLATION
    }

    pub fn to_app_error(self) -> AppError {
        match self {
            Self::StackMisaligned { sp } => AppError::new(
                ReasonCode::RcInvalidParameter,
                format!("ARM64 stack pointer 0x{sp:016x} is not 16-byte aligned"),
            )
            .with_hint(format!("ntstatus=0x{:08x}", self.nt_status())),
            Self::NullTeb => {
                AppError::new(ReasonCode::RcInvalidParameter, "ARM64 x18 (TEB) is null")
                    .with_hint(format!("ntstatus=0x{:08x}", self.nt_status()))
            }
            Self::EntryPointOutsideExecutableRegion { pc } => AppError::new(
                ReasonCode::RcInvalidParameter,
                format!("ARM64 entry point 0x{pc:016x} is outside the executable region"),
            )
            .with_hint(format!("ntstatus=0x{:08x}", self.nt_status())),
        }
    }
}

fn write_u32_slice(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_slice(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32_slice(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_slice(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

struct ExecutableRegion {
    pointer: *mut u8,
    len: usize,
    jit: bool,
    writable: bool,
}

unsafe impl Send for ExecutableRegion {}

impl ExecutableRegion {
    fn allocate(len: usize) -> AppResult<Self> {
        let page = page_size();
        let len = len.max(page).div_ceil(page) * page;
        #[cfg(target_os = "macos")]
        {
            let pointer = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
                    -1,
                    0,
                )
            };
            if pointer != libc::MAP_FAILED {
                unsafe { libc::pthread_jit_write_protect_np(0) };
                return Ok(Self {
                    pointer: pointer as *mut u8,
                    len,
                    jit: true,
                    writable: true,
                });
            }
        }
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                format!("failed to allocate {len} bytes for ARM64 native code"),
            ));
        }
        Ok(Self {
            pointer: pointer as *mut u8,
            len,
            jit: false,
            writable: true,
        })
    }

    fn allocate_data(len: usize) -> AppResult<Self> {
        let page = page_size();
        let len = len.max(page).div_ceil(page) * page;
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                format!("failed to allocate {len} bytes for ARM64 native data"),
            ));
        }
        unsafe { std::ptr::write_bytes(pointer as *mut u8, 0, len) };
        Ok(Self {
            pointer: pointer as *mut u8,
            len,
            jit: false,
            writable: true,
        })
    }

    fn address(&self) -> u64 {
        self.pointer as u64
    }

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer, self.len) }
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) -> AppResult<()> {
        if self.jit || !self.writable {
            self.make_writable()?;
        }
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidParameter, "ARM64 code write overflows")
        })?;
        if end > self.len {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                "ARM64 code write exceeds the executable region",
            ));
        }
        self.as_mut_slice()[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    fn make_writable(&mut self) -> AppResult<()> {
        #[cfg(target_os = "macos")]
        if self.jit {
            unsafe { libc::pthread_jit_write_protect_np(0) };
            self.writable = true;
            return Ok(());
        }
        let result = unsafe {
            libc::mprotect(
                self.pointer as *mut c_void,
                self.len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if result != 0 {
            return Err(AppError::new(
                ReasonCode::RcUnsupportedPlatform,
                "failed to make ARM64 executable memory writable",
            ));
        }
        self.writable = true;
        Ok(())
    }

    fn finish_writes(&mut self) -> AppResult<()> {
        #[cfg(target_os = "macos")]
        if self.jit {
            flush_instruction_cache(self.pointer, self.len);
            unsafe { libc::pthread_jit_write_protect_np(1) };
            self.writable = false;
            return Ok(());
        }
        let result = unsafe {
            libc::mprotect(
                self.pointer as *mut c_void,
                self.len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        if result != 0 {
            return Err(AppError::new(
                ReasonCode::RcUnsupportedPlatform,
                "failed to make ARM64 native code executable",
            ));
        }
        flush_instruction_cache(self.pointer, self.len);
        self.writable = false;
        Ok(())
    }

    fn protect_image_sections(
        &mut self,
        sections: &[SectionMapping],
        image_size: usize,
    ) -> AppResult<()> {
        if self.jit || !self.writable {
            return Ok(());
        }
        let page = page_size();
        let arena_start = image_size.div_ceil(page) * page;
        let mut protected = vec![false; self.len.div_ceil(page)];
        for section in sections {
            let start = (section.virtual_address as usize) & !(page - 1);
            let end = ((section.virtual_address as usize)
                .saturating_add(section.mapped_size as usize)
                .saturating_add(page - 1))
                & !(page - 1);
            let end = end.min(self.len);
            let mut index = start / page;
            while index < end / page {
                if !protected[index] {
                    let protection = section_protection(section);
                    let page_pointer = unsafe { self.pointer.add(index * page) };
                    let result = apply_page_protection(page_pointer, page, protection);
                    if !result {
                        return Err(AppError::new(
                            ReasonCode::RcUnsupportedPlatform,
                            format!(
                                "failed to apply section protection {:?} at RVA 0x{:x}",
                                section.protection, section.virtual_address
                            ),
                        ));
                    }
                    protected[index] = true;
                }
                index += 1;
            }
        }
        for (index, done) in protected.iter().enumerate() {
            if !done {
                let page_pointer = unsafe { self.pointer.add(index * page) };
                let protection = if index * page >= arena_start {
                    // Generated transition thunks must stay executable while
                    // the rest of the image remains read-only.
                    libc::PROT_READ | libc::PROT_EXEC
                } else {
                    libc::PROT_READ
                };
                let result = apply_page_protection(page_pointer, page, protection);
                if !result {
                    return Err(AppError::new(
                        ReasonCode::RcUnsupportedPlatform,
                        "failed to apply image header protection",
                    ));
                }
            }
        }
        flush_instruction_cache(self.pointer, self.len);
        self.writable = false;
        Ok(())
    }
}

impl Drop for ExecutableRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer as *mut c_void, self.len);
        }
    }
}

#[cfg(target_os = "macos")]
fn flush_instruction_cache(pointer: *mut u8, len: usize) {
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut c_void, len: usize);
    }
    unsafe { sys_icache_invalidate(pointer as *mut c_void, len) };
}

#[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
fn flush_instruction_cache(pointer: *mut u8, len: usize) {
    unsafe extern "C" {
        fn __clear_cache(start: *mut i8, end: *mut i8);
    }
    unsafe { __clear_cache(pointer as *mut i8, pointer.add(len) as *mut i8) };
}

#[cfg(not(target_arch = "aarch64"))]
fn flush_instruction_cache(_pointer: *mut u8, _len: usize) {}

#[cfg(target_os = "macos")]
fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(not(target_os = "macos"))]
fn page_size() -> usize {
    4096
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_vm_protect(
        target_task: u32,
        address: u64,
        size: u64,
        set_maximum: bool,
        new_protection: i32,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn apply_page_protection(pointer: *mut u8, len: usize, protection: libc::c_int) -> bool {
    let vm_protection = ((if protection & libc::PROT_READ != 0 {
        1
    } else {
        0
    }) | (if protection & libc::PROT_WRITE != 0 {
        2
    } else {
        0
    }) | (if protection & libc::PROT_EXEC != 0 {
        4
    } else {
        0
    })) as i32;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let result = unsafe { mach_vm_protect(task, pointer as u64, len as u64, false, vm_protection) };
    result == 0
}

#[cfg(not(target_os = "macos"))]
fn apply_page_protection(pointer: *mut u8, len: usize, protection: libc::c_int) -> bool {
    unsafe { libc::mprotect(pointer as *mut c_void, len, protection) == 0 }
}

fn section_protection(section: &SectionMapping) -> libc::c_int {
    let mut protection = libc::PROT_READ;
    if section.protection.write {
        protection |= libc::PROT_WRITE;
    }
    if section.protection.execute {
        protection |= libc::PROT_EXEC;
    }
    protection
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    r#"
    .text
    .global _casa1_arm64_call_bridge
    .p2align 2
_casa1_arm64_call_bridge:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    str x18, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp d8, d9, [sp, #-16]!
    stp d10, d11, [sp, #-16]!
    stp d12, d13, [sp, #-16]!
    stp d14, d15, [sp, #-16]!
    sub sp, sp, #16
    str x0, [sp]

    ldr x9, [x0, #144]
    str x0, [x9, #256]
    mov x10, sp
    str x10, [x9, #264]
    str x18, [x9, #280]

    ldr x9, [x0, #264]
    msr nzcv, x9
    ldr w9, [x0, #272]
    msr fpcr, x9
    ldr w9, [x0, #276]
    msr fpsr, x9

    ldp x1, x2, [x0, #8]
    ldp x3, x4, [x0, #24]
    ldp x5, x6, [x0, #40]
    ldp x7, x8, [x0, #56]
    ldr x9, [x0, #72]
    ldp x10, x11, [x0, #80]
    ldp x12, x13, [x0, #96]
    ldp x14, x15, [x0, #112]
    ldp x16, x17, [x0, #128]
    ldr x18, [x0, #144]
    ldp x19, x20, [x0, #152]
    ldp x21, x22, [x0, #168]
    ldp x23, x24, [x0, #184]
    ldp x25, x26, [x0, #200]
    ldp x27, x28, [x0, #216]
    ldr x29, [x0, #232]
    ldr x30, [x0, #248]
    ldp q0, q1, [x0, #288]
    ldp q2, q3, [x0, #320]
    ldp q4, q5, [x0, #352]
    ldp q6, q7, [x0, #384]
    ldp q8, q9, [x0, #416]
    ldp q10, q11, [x0, #448]
    ldp q12, q13, [x0, #480]
    ldp q14, q15, [x0, #512]
    mov sp, x30
    ldr x30, [x0, #256]
    ldr x0, [x0, #0]
    blr x30

    // macOS may clobber the platform register x18 (our TEB) across a guest
    // page fault or context switch.  Preserve all volatile guest state, ask
    // the host for the TEB again, then restore.  This is a no-op on hosts
    // that preserve x18.
    sub sp, sp, #288
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    str x30, [sp, #144]
    stp q0, q1, [sp, #160]
    stp q2, q3, [sp, #192]
    stp q4, q5, [sp, #224]
    stp q6, q7, [sp, #256]
    bl _casa1_arm64_bridge_recover_teb
    mov x18, x0
    ldp q6, q7, [sp, #256]
    ldp q4, q5, [sp, #224]
    ldp q2, q3, [sp, #192]
    ldp q0, q1, [sp, #160]
    ldr x30, [sp, #144]
    ldp x16, x17, [sp, #128]
    ldp x14, x15, [sp, #112]
    ldp x12, x13, [sp, #96]
    ldp x10, x11, [sp, #80]
    ldp x8, x9, [sp, #64]
    ldp x6, x7, [sp, #48]
    ldp x4, x5, [sp, #32]
    ldp x2, x3, [sp, #16]
    ldp x0, x1, [sp, #0]
    add sp, sp, #288
    // The host stack pointer share a register with guest x9 here; preserve
    // the guest value in TEB scratch space before switching stacks.
    str x9, [x18, #288]
    ldr x9, [x18, #264]
    mov sp, x9
    ldr x9, [x18, #288]

    str x17, [x18, #272]
    ldr x17, [x18, #256]
    str x0, [x17, #0]
    stp x1, x2, [x17, #8]
    stp x3, x4, [x17, #24]
    stp x5, x6, [x17, #40]
    stp x7, x8, [x17, #56]
    str x9, [x17, #72]
    stp x10, x11, [x17, #80]
    stp x12, x13, [x17, #96]
    stp x14, x15, [x17, #112]
    str x16, [x17, #128]
    stp q0, q1, [x17, #288]
    stp q2, q3, [x17, #320]
    stp q4, q5, [x17, #352]
    stp q6, q7, [x17, #384]
    stp q8, q9, [x17, #416]
    stp q10, q11, [x17, #448]
    stp q12, q13, [x17, #480]
    stp q14, q15, [x17, #512]
    ldr x9, [x18, #272]
    str x9, [x17, #136]
    str x18, [x17, #144]
    stp x19, x20, [x17, #152]
    stp x21, x22, [x17, #168]
    stp x23, x24, [x17, #184]
    stp x25, x26, [x17, #200]
    stp x27, x28, [x17, #216]
    str x29, [x17, #232]
    str x30, [x17, #240]
    mov x9, sp
    str x9, [x17, #248]
    mrs x9, nzcv
    str x9, [x17, #264]
    mrs x9, fpcr
    str w9, [x17, #272]
    mrs x9, fpsr
    str w9, [x17, #276]

    ldr x9, [x18, #264]
    mov sp, x9
    add sp, sp, #16
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8, d9, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldr x18, [sp], #16
    ldp x29, x30, [sp], #16
    ret
    "#
);

#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
core::arch::global_asm!(
    r#"
    .text
    .global casa1_arm64_call_bridge
    .p2align 2
casa1_arm64_call_bridge:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    str x18, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp d8, d9, [sp, #-16]!
    stp d10, d11, [sp, #-16]!
    stp d12, d13, [sp, #-16]!
    stp d14, d15, [sp, #-16]!
    sub sp, sp, #16
    str x0, [sp]

    ldr x9, [x0, #144]
    str x0, [x9, #256]
    mov x10, sp
    str x10, [x9, #264]
    str x18, [x9, #280]

    ldr x9, [x0, #264]
    msr nzcv, x9
    ldr w9, [x0, #272]
    msr fpcr, x9
    ldr w9, [x0, #276]
    msr fpsr, x9

    ldp x1, x2, [x0, #8]
    ldp x3, x4, [x0, #24]
    ldp x5, x6, [x0, #40]
    ldp x7, x8, [x0, #56]
    ldr x9, [x0, #72]
    ldp x10, x11, [x0, #80]
    ldp x12, x13, [x0, #96]
    ldp x14, x15, [x0, #112]
    ldp x16, x17, [x0, #128]
    ldr x18, [x0, #144]
    ldp x19, x20, [x0, #152]
    ldp x21, x22, [x0, #168]
    ldp x23, x24, [x0, #184]
    ldp x25, x26, [x0, #200]
    ldp x27, x28, [x0, #216]
    ldr x29, [x0, #232]
    ldr x30, [x0, #248]
    ldp q0, q1, [x0, #288]
    ldp q2, q3, [x0, #320]
    ldp q4, q5, [x0, #352]
    ldp q6, q7, [x0, #384]
    ldp q8, q9, [x0, #416]
    ldp q10, q11, [x0, #448]
    ldp q12, q13, [x0, #480]
    ldp q14, q15, [x0, #512]
    mov sp, x30
    ldr x30, [x0, #256]
    ldr x0, [x0, #0]
    blr x30

    // macOS may clobber the platform register x18 (our TEB) across a guest
    // page fault or context switch.  Preserve all volatile guest state, ask
    // the host for the TEB again, then restore.  This is a no-op on hosts
    // that preserve x18.
    sub sp, sp, #288
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    str x30, [sp, #144]
    stp q0, q1, [sp, #160]
    stp q2, q3, [sp, #192]
    stp q4, q5, [sp, #224]
    stp q6, q7, [sp, #256]
    bl casa1_arm64_bridge_recover_teb
    mov x18, x0
    ldp q6, q7, [sp, #256]
    ldp q4, q5, [sp, #224]
    ldp q2, q3, [sp, #192]
    ldp q0, q1, [sp, #160]
    ldr x30, [sp, #144]
    ldp x16, x17, [sp, #128]
    ldp x14, x15, [sp, #112]
    ldp x12, x13, [sp, #96]
    ldp x10, x11, [sp, #80]
    ldp x8, x9, [sp, #64]
    ldp x6, x7, [sp, #48]
    ldp x4, x5, [sp, #32]
    ldp x2, x3, [sp, #16]
    ldp x0, x1, [sp, #0]
    add sp, sp, #288
    // The host stack pointer share a register with guest x9 here; preserve
    // the guest value in TEB scratch space before switching stacks.
    str x9, [x18, #288]
    ldr x9, [x18, #264]
    mov sp, x9
    ldr x9, [x18, #288]

    str x17, [x18, #272]
    ldr x17, [x18, #256]
    str x0, [x17, #0]
    stp x1, x2, [x17, #8]
    stp x3, x4, [x17, #24]
    stp x5, x6, [x17, #40]
    stp x7, x8, [x17, #56]
    str x9, [x17, #72]
    stp x10, x11, [x17, #80]
    stp x12, x13, [x17, #96]
    stp x14, x15, [x17, #112]
    str x16, [x17, #128]
    stp q0, q1, [x17, #288]
    stp q2, q3, [x17, #320]
    stp q4, q5, [x17, #352]
    stp q6, q7, [x17, #384]
    stp q8, q9, [x17, #416]
    stp q10, q11, [x17, #448]
    stp q12, q13, [x17, #480]
    stp q14, q15, [x17, #512]
    ldr x9, [x18, #272]
    str x9, [x17, #136]
    str x18, [x17, #144]
    stp x19, x20, [x17, #152]
    stp x21, x22, [x17, #168]
    stp x23, x24, [x17, #184]
    stp x25, x26, [x17, #200]
    stp x27, x28, [x17, #216]
    str x29, [x17, #232]
    str x30, [x17, #240]
    mov x9, sp
    str x9, [x17, #248]
    mrs x9, nzcv
    str x9, [x17, #264]
    mrs x9, fpcr
    str w9, [x17, #272]
    mrs x9, fpsr
    str w9, [x17, #276]

    ldr x9, [x18, #264]
    mov sp, x9
    add sp, sp, #16
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8, d9, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldr x18, [sp], #16
    ldp x29, x30, [sp], #16
    ret
    "#
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn casa1_arm64_call_bridge(context: *mut Arm64Context);
}

#[cfg(target_arch = "aarch64")]
thread_local! {
    // TEB pointers for active native bridge invocations.  Kept as a stack
    // because ARM64 import callbacks can re-enter the bridge.
    static BRIDGE_TEB_STACK: std::cell::RefCell<Vec<u64>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Recover the guest TEB after executing native code.  On macOS x18 is the
/// platform register and may be clobbered when a guest faults or is
/// preempted; the bridge therefore re-reads the TEB from Rust TLS instead of
/// trusting the live x18 value.
#[unsafe(no_mangle)]
pub extern "C" fn casa1_arm64_bridge_recover_teb() -> u64 {
    BRIDGE_TEB_STACK.with(|stack| stack.borrow().last().copied().unwrap_or(0))
}

struct BridgeTebGuard;

impl Drop for BridgeTebGuard {
    fn drop(&mut self) {
        BRIDGE_TEB_STACK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

fn invoke_bridge(context: &mut Arm64Context) -> AppResult<()> {
    if context.sp % ARM64_STACK_ALIGNMENT != 0 {
        return Err(Arm64Exception::StackMisaligned { sp: context.sp }.to_app_error());
    }
    if context.x[18] == 0 {
        return Err(Arm64Exception::NullTeb.to_app_error());
    }
    if context.pc == 0 {
        return Err(Arm64Exception::EntryPointOutsideExecutableRegion { pc: 0 }.to_app_error());
    }
    BRIDGE_TEB_STACK.with(|stack| stack.borrow_mut().push(context.x[18]));
    let _teb_guard = BridgeTebGuard;
    #[cfg(target_os = "macos")]
    unsafe {
        libc::pthread_jit_write_protect_np(1);
    }
    unsafe { casa1_arm64_call_bridge(context as *mut Arm64Context) };
    Ok(())
}

#[cfg(not(target_arch = "aarch64"))]
fn invoke_bridge(_context: &mut Arm64Context) -> AppResult<()> {
    Err(AppError::new(
        ReasonCode::RcUnsupportedPlatform,
        "native ARM64 execution requires an aarch64 host",
    ))
}

pub fn native_arm64_available() -> bool {
    cfg!(target_arch = "aarch64")
}

pub struct Arm64Executor {
    code: ExecutableRegion,
    _stack: ExecutableRegion,
    teb: Arm64Teb,
    stack_base: u64,
    stack_limit: u64,
}

impl Arm64Executor {
    pub fn new() -> AppResult<Self> {
        Self::with_sizes(DEFAULT_STACK_SIZE, DEFAULT_STACK_SIZE)
    }

    pub fn with_sizes(stack_size: usize, teb_stack_size: usize) -> AppResult<Self> {
        let code = ExecutableRegion::allocate(page_size())?;
        let stack = ExecutableRegion::allocate_data(stack_size)?;
        let mut teb = Arm64Teb::new(teb_stack_size as u64);
        let stack_base = stack.address() + stack.len() as u64;
        let stack_limit = stack.address();
        teb.set_stack(stack_base, stack_limit);
        Ok(Self {
            code,
            _stack: stack,
            teb,
            stack_base,
            stack_limit,
        })
    }

    pub fn teb_address(&self) -> u64 {
        self.teb.address()
    }

    pub fn teb(&self) -> &Arm64Teb {
        &self.teb
    }

    pub fn teb_mut(&mut self) -> &mut Arm64Teb {
        &mut self.teb
    }

    pub fn stack_base(&self) -> u64 {
        self.stack_base
    }

    pub fn stack_limit(&self) -> u64 {
        self.stack_limit
    }

    pub fn map_code(&mut self, bytes: &[u8]) -> AppResult<u64> {
        let address = self.code.address();
        self.code.write(0, bytes)?;
        self.code.finish_writes()?;
        Ok(address)
    }

    pub fn prepare_context(&self, entry: u64, args: &[u64]) -> Arm64Context {
        let mut context = Arm64Context::new();
        context.pc = entry;
        context.sp = self.stack_base - 8;
        context.sp &= !(ARM64_STACK_ALIGNMENT - 1);
        context.x[18] = self.teb.address();
        context.x[30] = entry;
        for (index, value) in args.iter().copied().enumerate() {
            if index < 8 {
                context.x[index] = value;
            }
        }
        context
    }

    pub fn call_code(&mut self, code: &[u8], args: &[u64]) -> AppResult<Arm64CallResult> {
        let entry = self.map_code(code)?;
        self.call_address(entry, args)
    }

    pub fn call_address(&mut self, entry: u64, args: &[u64]) -> AppResult<Arm64CallResult> {
        if entry < self.code.address() || entry >= self.code.address() + self.code.len() as u64 {
            return Err(
                Arm64Exception::EntryPointOutsideExecutableRegion { pc: entry }.to_app_error(),
            );
        }
        let mut context = self.prepare_context(entry, args);
        invoke_bridge(&mut context)?;
        Ok(Arm64CallResult { context })
    }

    pub fn call_with_context(&mut self, context: &mut Arm64Context) -> AppResult<()> {
        if context.x[18] == 0 {
            context.x[18] = self.teb.address();
        }
        if context.sp == 0 {
            context.sp = self.stack_base - 8;
            context.sp &= !(ARM64_STACK_ALIGNMENT - 1);
        }
        invoke_bridge(context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64CallResult {
    pub context: Arm64Context,
}

impl Arm64CallResult {
    pub fn return_value(&self) -> u64 {
        self.context.x[0]
    }

    pub fn x(&self, register: usize) -> u64 {
        self.context.get(register)
    }

    pub fn sp(&self) -> u64 {
        self.context.sp
    }

    pub fn nzcv(&self) -> u64 {
        self.context.nzcv
    }
}

pub fn execute_arm64_function(code: &[u8], args: &[u64]) -> AppResult<u64> {
    let mut executor = Arm64Executor::new()?;
    let result = executor.call_code(code, args)?;
    Ok(result.return_value())
}

pub fn execute_arm64_context(code: &[u8], context: &mut Arm64Context) -> AppResult<()> {
    let mut executor = Arm64Executor::new()?;
    let entry = executor.map_code(code)?;
    context.pc = entry;
    if context.sp == 0 {
        context.sp = executor.stack_base() - 8;
        context.sp &= !(ARM64_STACK_ALIGNMENT - 1);
    }
    if context.x[18] == 0 {
        context.x[18] = executor.teb_address();
    }
    executor.call_with_context(context)
}

pub struct Arm64Assembler {
    bytes: Vec<u8>,
}

impl Default for Arm64Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Arm64Assembler {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn word(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn nop(&mut self) -> &mut Self {
        self.word(0xd503_201f)
    }

    pub fn ret(&mut self) -> &mut Self {
        self.word(0xd65f_03c0)
    }

    pub fn movz_x(&mut self, rd: u32, imm16: u16, shift: u32) -> &mut Self {
        self.word(0xd280_0000 | ((shift / 16) << 21) | (u32::from(imm16) << 5) | (rd & 31))
    }

    pub fn movk_x(&mut self, rd: u32, imm16: u16, shift: u32) -> &mut Self {
        self.word(0xf280_0000 | ((shift / 16) << 21) | (u32::from(imm16) << 5) | (rd & 31))
    }

    pub fn mov_abs_x(&mut self, rd: u32, value: u64) -> &mut Self {
        self.movz_x(rd, value as u16, 0);
        if value >> 16 != 0 {
            self.movk_x(rd, (value >> 16) as u16, 16);
        }
        if value >> 32 != 0 {
            self.movk_x(rd, (value >> 32) as u16, 32);
        }
        if value >> 48 != 0 {
            self.movk_x(rd, (value >> 48) as u16, 48);
        }
        self
    }

    pub fn mov_x(&mut self, rd: u32, rm: u32) -> &mut Self {
        self.word(0xaa00_03e0 | ((rm & 31) << 16) | (rd & 31))
    }

    pub fn add_x_imm(&mut self, rd: u32, rn: u32, imm12: u32) -> &mut Self {
        self.word(0x9100_0000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn sub_x_imm(&mut self, rd: u32, rn: u32, imm12: u32) -> &mut Self {
        self.word(0xd100_0000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn add_x_reg(&mut self, rd: u32, rn: u32, rm: u32) -> &mut Self {
        self.word(0x8b00_0000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn sub_x_reg(&mut self, rd: u32, rn: u32, rm: u32) -> &mut Self {
        self.word(0xcb00_0000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn cmp_x_imm(&mut self, rn: u32, imm12: u32) -> &mut Self {
        self.word(0xf100_0000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | 31)
    }

    pub fn ldr_x_imm(&mut self, rt: u32, rn: u32, offset: u32) -> &mut Self {
        self.word(0xf940_0000 | (((offset / 8) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    pub fn str_x_imm(&mut self, rt: u32, rn: u32, offset: u32) -> &mut Self {
        self.word(0xf900_0000 | (((offset / 8) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    pub fn br(&mut self, rn: u32) -> &mut Self {
        self.word(0xd61f_0000 | ((rn & 31) << 5))
    }

    pub fn blr(&mut self, rn: u32) -> &mut Self {
        self.word(0xd63f_0000 | ((rn & 31) << 5))
    }

    pub fn ldr_x_literal(&mut self, rt: u32, byte_offset: i32) -> &mut Self {
        let imm19 = (byte_offset / 4) as u32 & 0x7ffff;
        self.word(0x5800_0000 | (imm19 << 5) | (rt & 31))
    }

    pub fn adrp(&mut self, rd: u32, page_delta: i64) -> &mut Self {
        let imm = (page_delta as u64) & 0x1f_ffff;
        let immlo = (imm & 0x3) as u32;
        let immhi = ((imm >> 2) & 0x7_ffff) as u32;
        self.word(0x9000_0000 | (immlo << 29) | (immhi << 5) | (rd & 31))
    }

    pub fn b_cond(&mut self, cond: u32, byte_offset: i32) -> &mut Self {
        let imm19 = (byte_offset / 4) as u32 & 0x7ffff;
        self.word(0x5400_0000 | (imm19 << 5) | (cond & 0xf))
    }

    /// `stp xN, xM, [xK, #offset]` (signed 7-bit scaled offset).
    pub fn stp_x(&mut self, rt: u32, rt2: u32, rn: u32, offset: i32) -> &mut Self {
        let imm7 = ((offset / 8) as u32) & 0x7f;
        self.word(0xa900_0000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    /// `ldp xN, xM, [xK, #offset]`.
    pub fn ldp_x(&mut self, rt: u32, rt2: u32, rn: u32, offset: i32) -> &mut Self {
        let imm7 = ((offset / 8) as u32) & 0x7f;
        self.word(0xa940_0000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    /// `stp qN, qM, [xK, #offset]` (signed 7-bit scaled by 16).
    pub fn stp_q(&mut self, rt: u32, rt2: u32, rn: u32, offset: i32) -> &mut Self {
        let imm7 = ((offset / 16) as u32) & 0x7f;
        self.word(0xad00_0000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    /// `ldp qN, qM, [xK, #offset]`.
    pub fn ldp_q(&mut self, rt: u32, rt2: u32, rn: u32, offset: i32) -> &mut Self {
        let imm7 = ((offset / 16) as u32) & 0x7f;
        self.word(0xad40_0000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt & 31))
    }
}

type ImportCallback = Box<dyn FnMut(u64, u64, u64, u64, u64, u64, u64, u64) -> u64>;

thread_local! {
    static IMPORT_CALLBACKS: RefCell<HashMap<u64, ImportCallback>> = RefCell::new(HashMap::new());
    static NEXT_IMPORT_ID: Cell<u64> = const { Cell::new(1) };
}

extern "C" fn arm64_import_dispatch(
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    id: u64,
) -> u64 {
    let callback = IMPORT_CALLBACKS.with(|cell| cell.borrow_mut().remove(&id));
    let Some(mut callback) = callback else {
        return u64::MAX;
    };
    let result = callback(a0, a1, a2, a3, a4, a5, a6, a7);
    IMPORT_CALLBACKS.with(|cell| {
        cell.borrow_mut().insert(id, callback);
    });
    result
}

pub struct Arm64ImportTable {
    region: ExecutableRegion,
    names: BTreeMap<String, u64>,
    next_offset: usize,
}

impl Arm64ImportTable {
    pub fn new() -> AppResult<Self> {
        let region = ExecutableRegion::allocate(page_size())?;
        Ok(Self {
            region,
            names: BTreeMap::new(),
            next_offset: 0,
        })
    }

    pub fn register(
        &mut self,
        name: impl Into<String>,
        callback: impl FnMut(u64, u64, u64, u64, u64, u64, u64, u64) -> u64 + 'static,
    ) -> AppResult<u64> {
        let id = NEXT_IMPORT_ID.with(|next| {
            let id = next.get();
            next.set(id.wrapping_add(1).max(1));
            id
        });
        IMPORT_CALLBACKS.with(|cell| {
            cell.borrow_mut().insert(id, Box::new(callback));
        });
        let thunk = build_import_thunk(id, arm64_import_dispatch as *const () as usize);
        let offset = self.next_offset;
        let next = offset.checked_add(thunk.len()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidParameter,
                "import thunk table overflow",
            )
        })?;
        if next > self.region.len() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "ARM64 import thunk table is full",
            ));
        }
        self.region.write(offset, &thunk)?;
        self.region.finish_writes()?;
        self.next_offset = next;
        let address = self.region.address() + offset as u64;
        self.names.insert(name.into(), address);
        Ok(address)
    }

    pub fn resolve(&self, name: &str) -> Option<u64> {
        self.names.get(name).copied()
    }

    pub fn names(&self) -> impl Iterator<Item = (&str, u64)> {
        self.names
            .iter()
            .map(|(name, address)| (name.as_str(), *address))
    }

    pub fn call(&self, name: &str, args: &[u64]) -> AppResult<u64> {
        let address = self.resolve(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcImportMissing,
                format!("missing ARM64 import {name}"),
            )
        })?;
        let mut executor = Arm64Executor::new()?;
        let mut context = executor.prepare_context(address, args);
        executor.call_with_context(&mut context)?;
        Ok(context.x[0])
    }
}

fn build_import_thunk(id: u64, dispatch: usize) -> [u8; 72] {
    let mut bytes = [0u8; 72];
    let mut writer = Arm64Assembler::new();
    writer
        .ldr_x_literal(16, 56)
        .sub_x_imm(31, 31, 32)
        .str_x_imm(16, 31, 0)
        .str_x_imm(30, 31, 8)
        .str_x_imm(18, 31, 16)
        .ldr_x_imm(17, 18, 0x118)
        .mov_x(18, 17)
        .ldr_x_literal(16, 36)
        .blr(16)
        .ldr_x_imm(18, 31, 16)
        .ldr_x_imm(30, 31, 8)
        .add_x_imm(31, 31, 32)
        .ret()
        .nop();
    bytes[..writer.bytes().len()].copy_from_slice(writer.bytes());
    bytes[56..64].copy_from_slice(&id.to_le_bytes());
    bytes[64..72].copy_from_slice(&(dispatch as u64).to_le_bytes());
    bytes
}

// ── Native transition thunks and host dispatchers ───────────────────────

/// Frame handed by a generated ARM64EC exit thunk to [`ec_exit_dispatch`].
/// The field order is part of the generated-code ABI.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EcExitFrame {
    /// x0..x9 at the transition point.
    pub gpr: [u64; 10],
    /// q0..q7 at the transition point, each as (low, high).
    pub vec: [[u64; 2]; 8],
    /// Stack pointer at the transition point (EC stack arguments start here).
    pub sp: u64,
    /// x18 (TEB) at the transition point.
    pub teb: u64,
    /// x30 (link register) at the transition point.
    pub lr: u64,
    /// x64 target address (x9 for indirect exits, a literal for direct ones).
    pub target: u64,
    /// Signature registry id (0 selects the default integer signature).
    pub signature_id: u64,
    pub result_gpr: [u64; 2],
    pub _result_pad: [u64; 1],
    /// q0/q1 return values, each as (low, high).
    pub result_vec: [[u64; 2]; 2],
}

/// Request passed to a registered x64 exit hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcExitRequest {
    pub target: u64,
    pub signature: EcSignature,
    pub args: X64CallArguments,
    /// x64-visible non-volatile state projected from the ARM64EC caller.
    pub nonvolatile: X64AbiState,
    /// TEB/x18 value at the transition point.
    pub teb: u64,
}

/// Response returned by the x64 exit hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcExitResponse {
    pub rax: u64,
    pub rdx: u64,
    pub xmm0: u128,
    pub xmm1: u128,
}

impl From<X64Return> for EcExitResponse {
    fn from(value: X64Return) -> Self {
        Self {
            rax: value.rax,
            rdx: value.rdx,
            xmm0: value.xmm0,
            xmm1: value.xmm1,
        }
    }
}

type EcExitHook = Box<dyn FnMut(&EcExitRequest) -> AppResult<EcExitResponse>>;

thread_local! {
    static EC_EXIT_HOOK: RefCell<Option<EcExitHook>> = const { RefCell::new(None) };
    static EC_EXIT_SIGNATURES: RefCell<HashMap<u64, EcSignature>> = RefCell::new(HashMap::new());
    static EC_EXIT_ERROR: RefCell<Option<EcTransitionError>> = const { RefCell::new(None) };
    static EC_CALL_CHECKER: RefCell<Option<EcCallChecker>> = const { RefCell::new(None) };
    static EC_CHECK_ERROR: RefCell<Option<EcTransitionError>> = const { RefCell::new(None) };
}

/// Install the x64 execution hook used by generated exit thunks.
pub fn set_exit_hook(hook: impl FnMut(&EcExitRequest) -> AppResult<EcExitResponse> + 'static) {
    EC_EXIT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

pub fn clear_exit_hook() {
    EC_EXIT_HOOK.with(|slot| *slot.borrow_mut() = None);
}

pub fn set_call_checker(checker: EcCallChecker) {
    EC_CALL_CHECKER.with(|slot| *slot.borrow_mut() = Some(checker));
}

pub fn clear_call_checker() {
    EC_CALL_CHECKER.with(|slot| *slot.borrow_mut() = None);
}

/// Register a signature for generated thunks.  Ids start at 1; id 0 is the
/// default all-integer signature.
pub fn register_exit_signature(id: u64, signature: EcSignature) {
    EC_EXIT_SIGNATURES.with(|slot| {
        slot.borrow_mut().insert(id, signature);
    });
}

pub fn clear_exit_signatures() {
    EC_EXIT_SIGNATURES.with(|slot| slot.borrow_mut().clear());
}

/// Take and clear the error raised by the last generated-thunk transition.
pub fn take_exit_error() -> Option<EcTransitionError> {
    EC_EXIT_ERROR.with(|slot| slot.borrow_mut().take())
}

pub fn take_call_checker_error() -> Option<EcTransitionError> {
    EC_CHECK_ERROR.with(|slot| slot.borrow_mut().take())
}

fn exit_signature(id: u64) -> EcSignature {
    if id == 0 {
        return EcSignature::class_parallel();
    }
    EC_EXIT_SIGNATURES.with(|slot| {
        slot.borrow()
            .get(&id)
            .cloned()
            .unwrap_or_else(EcSignature::all_integer)
    })
}

struct RawStack {
    base: u64,
    pointer: *mut u8,
    len: usize,
}

#[cfg(unix)]
fn host_page_mapped(address: u64) -> bool {
    let page = address & !0xfff;
    let mut resident = 0u8;
    // SAFETY: `mincore` only observes the mapping; the page-aligned address
    // and one-page length are valid for the output byte.
    unsafe {
        libc::mincore(
            page as *mut libc::c_void,
            0x1000,
            &mut resident as *mut u8 as *mut libc::c_char,
        ) == 0
    }
}

#[cfg(not(unix))]
fn host_page_mapped(_address: u64) -> bool {
    true
}

impl EcStackAccess for RawStack {
    fn read_u64(&self, address: u64) -> AppResult<u64> {
        let offset = address.wrapping_sub(self.base) as usize;
        let end = offset.checked_add(8).ok_or_else(|| {
            EcTransitionError::fault("ARM64EC native stack read overflows").to_app_error()
        })?;
        if end > self.len || !host_page_mapped(address) {
            return Err(EcTransitionError::fault(format!(
                "ARM64EC native stack read at 0x{address:016x} is outside the transition stack"
            ))
            .to_app_error());
        }
        // SAFETY: `offset..end` lies inside the stack allocation supplied by
        // the executor, which outlives this synchronous read.
        let bytes = unsafe { std::slice::from_raw_parts(self.pointer.add(offset), 8) };
        Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn write_u64(&mut self, address: u64, value: u64) -> AppResult<()> {
        let offset = address.wrapping_sub(self.base) as usize;
        let end = offset.checked_add(8).ok_or_else(|| {
            EcTransitionError::fault("ARM64EC native stack write overflows").to_app_error()
        })?;
        if end > self.len || !host_page_mapped(address) {
            return Err(EcTransitionError::fault(format!(
                "ARM64EC native stack write at 0x{address:016x} is outside the transition stack"
            ))
            .to_app_error());
        }
        // SAFETY: same bounds argument as `read_u64`.
        let bytes = unsafe { std::slice::from_raw_parts_mut(self.pointer.add(offset), 8) };
        bytes.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

/// Host side of a generated exit thunk.  It translates the live ARM64EC
/// register file/stack into x64 form, invokes the registered hook and writes
/// the x64 result back into the ARM64EC return registers.
extern "C" fn ec_exit_dispatch(frame: *mut EcExitFrame) {
    // SAFETY: generated thunks pass a pointer to their own live stack frame
    // and call this function synchronously.
    let frame = unsafe { &mut *frame };
    // macOS may have clobbered the platform register x18 before the thunk
    // even saved it (e.g. across a guest page fault).  Recover the TEB from
    // the host bridge and write it back so both the x64 callee and the EC
    // caller observe the canonical TEB.
    let recovered_teb = casa1_arm64_bridge_recover_teb();
    if frame.teb == 0 {
        frame.teb = recovered_teb;
    }
    let signature = exit_signature(frame.signature_id);
    let ec = EcAbiState {
        x: {
            let mut x = [0u64; ARM64_REGISTER_COUNT];
            x[..10].copy_from_slice(&frame.gpr[..10]);
            x
        },
        q: {
            let mut q = [0u128; 32];
            for (index, pair) in frame.vec.iter().enumerate() {
                q[index] = u128::from(pair[0]) | (u128::from(pair[1]) << 64);
            }
            q
        },
        sp: frame.sp,
        pc: 0,
        teb: frame.teb,
        lr: frame.lr,
    };
    let stack = RawStack {
        base: frame.sp,
        pointer: frame.sp as *mut u8,
        len: 0x1_0000,
    };
    push_transition_unwind(EcUnwindRecord::from_ec(&ec));
    let outcome = ec_to_x64_arguments(&signature, &ec, &stack).and_then(|args| {
        let mut nonvolatile = X64AbiState::default();
        copy_ec_nonvolatile_to_x64(&ec, &mut nonvolatile);
        let request = EcExitRequest {
            target: frame.target,
            signature: signature.clone(),
            args,
            nonvolatile,
            teb: ec.teb,
        };
        EC_EXIT_HOOK.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(&request),
            None => Err(EcTransitionError::unsupported(
                "x64 exit hook is not installed for the ARM64EC transition",
            )
            .to_app_error()),
        })
    });
    match outcome {
        Ok(response) => {
            pop_transition_unwind();
            frame.result_gpr = [response.rax, response.rdx];
            frame.result_vec = [
                [response.xmm0 as u64, (response.xmm0 >> 64) as u64],
                [response.xmm1 as u64, (response.xmm1 >> 64) as u64],
            ];
        }
        Err(error) => {
            let transition = EcTransitionError::from_app_error(&error);
            unwind_transition(transition.status);
            EC_EXIT_ERROR.with(|slot| *slot.borrow_mut() = Some(transition));
            frame.result_gpr = [0; 2];
            frame.result_vec = [[0; 2]; 2];
        }
    }
}

/// Host side of a generated ARM64EC call-checker thunk.  The generated stub
/// supplies the target (x11) and exit thunk (x10) and receives x9/x10/x11.
extern "C" fn ec_check_dispatch(target: u64, exit_thunk: u64, out: *mut EcCheckResult) {
    let result = EC_CALL_CHECKER.with(|slot| match slot.borrow().as_ref() {
        Some(checker) => checker.check(target, exit_thunk),
        None => Err(
            EcTransitionError::unsupported("ARM64EC call checker is not installed").to_app_error(),
        ),
    });
    // SAFETY: generated stubs pass a pointer into their own live frame.
    let out = unsafe { &mut *out };
    match result {
        Ok(value) => *out = value,
        Err(error) => {
            let transition = EcTransitionError::new(STATUS_NOT_SUPPORTED, error.message);
            EC_CHECK_ERROR.with(|slot| *slot.borrow_mut() = Some(transition));
            *out = EcCheckResult {
                x9: EC_CHECK_FAILED,
                x10: exit_thunk,
                x11: exit_thunk,
            };
        }
    }
}

fn patch_ldr_literal(bytes: &mut [u8], instruction_offset: usize, literal_offset: usize) {
    let delta = literal_offset as i64 - instruction_offset as i64;
    let imm19 = ((delta / 4) as u32) & 0x7ffff;
    let word = u32::from_le_bytes(
        bytes[instruction_offset..instruction_offset + 4]
            .try_into()
            .expect("4 bytes"),
    );
    let patched = (word & !(0x7ffff << 5)) | (imm19 << 5);
    bytes[instruction_offset..instruction_offset + 4].copy_from_slice(&patched.to_le_bytes());
}

fn pad_to(bytes: &mut Vec<u8>, alignment: usize) {
    while bytes.len() % alignment != 0 {
        bytes.extend_from_slice(&0xd503_201fu32.to_le_bytes());
    }
}

/// Generate the ARM64EC exit thunk described by the Windows ABI.  It saves the
/// live argument registers (including full q0-q7), calls the host dispatcher,
/// and returns the x64 result converted to ARM64EC form.
///
/// `target` is embedded when the call target is statically known (direct
/// calls); otherwise x9 supplies the target (indirect calls routed through the
/// call checker).
pub fn build_ec_exit_thunk(target: Option<u64>, signature_id: u64) -> Vec<u8> {
    let mut assembler = Arm64Assembler::new();
    assembler
        .sub_x_imm(31, 31, EC_EXIT_FRAME_SIZE as u32)
        .str_x_imm(18, 31, 216)
        .str_x_imm(30, 31, 224)
        .stp_x(0, 1, 31, 0)
        .stp_x(2, 3, 31, 16)
        .stp_x(4, 5, 31, 32)
        .stp_x(6, 7, 31, 48)
        .stp_x(8, 9, 31, 64)
        .stp_q(0, 1, 31, 80)
        .stp_q(2, 3, 31, 112)
        .stp_q(4, 5, 31, 144)
        .stp_q(6, 7, 31, 176)
        .add_x_imm(9, 31, EC_EXIT_FRAME_SIZE as u32)
        .str_x_imm(9, 31, 208);
    let target_literal_instruction = match target {
        Some(_) => {
            let offset = assembler.bytes().len();
            assembler.ldr_x_literal(10, 0);
            Some(offset)
        }
        None => {
            assembler.ldr_x_imm(10, 31, 72).str_x_imm(10, 31, 232);
            None
        }
    };
    if target.is_some() {
        assembler.str_x_imm(10, 31, 232);
    }
    let signature_literal_instruction = {
        let offset = assembler.bytes().len();
        assembler.ldr_x_literal(10, 0);
        Some(offset)
    };
    assembler.str_x_imm(10, 31, 240).add_x_imm(0, 31, 0);
    let dispatch_literal_instruction = {
        let offset = assembler.bytes().len();
        assembler.ldr_x_literal(10, 0);
        Some(offset)
    };
    assembler
        .blr(10)
        .ldr_x_imm(0, 31, 248)
        .ldr_x_imm(1, 31, 256)
        .ldp_q(0, 1, 31, 272)
        .ldr_x_imm(18, 31, 216)
        .ldr_x_imm(30, 31, 224)
        .add_x_imm(31, 31, EC_EXIT_FRAME_SIZE as u32)
        .ret();
    let mut bytes = assembler.into_bytes();
    pad_to(&mut bytes, 8);
    let target_literal = bytes.len();
    bytes.extend_from_slice(&target.unwrap_or(0).to_le_bytes());
    let signature_literal = bytes.len();
    bytes.extend_from_slice(&signature_id.to_le_bytes());
    let dispatch_literal = bytes.len();
    bytes.extend_from_slice(&(ec_exit_dispatch as *const () as usize as u64).to_le_bytes());
    if let Some(offset) = target_literal_instruction {
        patch_ldr_literal(&mut bytes, offset, target_literal);
    }
    if let Some(offset) = signature_literal_instruction {
        patch_ldr_literal(&mut bytes, offset, signature_literal);
    }
    if let Some(offset) = dispatch_literal_instruction {
        patch_ldr_literal(&mut bytes, offset, dispatch_literal);
    }
    bytes
}

/// Generate a call-checker thunk matching `__os_arm64x_check_icall[_cfg]`.
pub fn build_ec_check_thunk() -> Vec<u8> {
    let mut assembler = Arm64Assembler::new();
    assembler
        .sub_x_imm(31, 31, EC_CHECK_FRAME_SIZE as u32)
        .stp_x(0, 1, 31, 0)
        .stp_x(2, 3, 31, 16)
        .stp_x(4, 5, 31, 32)
        .stp_x(6, 7, 31, 48)
        .str_x_imm(8, 31, 64)
        .str_x_imm(10, 31, 80)
        .str_x_imm(11, 31, 88)
        .str_x_imm(18, 31, 96)
        .str_x_imm(30, 31, 104)
        .stp_q(0, 1, 31, 112)
        .stp_q(2, 3, 31, 144)
        .stp_q(4, 5, 31, 176)
        .stp_q(6, 7, 31, 208)
        .mov_x(0, 11)
        .mov_x(1, 10)
        .add_x_imm(2, 31, 240);
    let dispatch_literal_instruction = {
        let offset = assembler.bytes().len();
        assembler.ldr_x_literal(16, 0);
        Some(offset)
    };
    assembler
        .blr(16)
        .ldr_x_imm(9, 31, 240)
        .ldr_x_imm(10, 31, 248)
        .ldr_x_imm(11, 31, 256)
        .ldp_q(6, 7, 31, 208)
        .ldp_q(4, 5, 31, 176)
        .ldp_q(2, 3, 31, 144)
        .ldp_q(0, 1, 31, 112)
        .ldr_x_imm(18, 31, 96)
        .ldr_x_imm(30, 31, 104)
        .ldr_x_imm(8, 31, 64)
        .ldp_x(6, 7, 31, 48)
        .ldp_x(4, 5, 31, 32)
        .ldp_x(2, 3, 31, 16)
        .ldp_x(0, 1, 31, 0)
        .add_x_imm(31, 31, EC_CHECK_FRAME_SIZE as u32)
        .ret();
    let mut bytes = assembler.into_bytes();
    pad_to(&mut bytes, 8);
    let dispatch_literal = bytes.len();
    bytes.extend_from_slice(&(ec_check_dispatch as *const () as usize as u64).to_le_bytes());
    if let Some(offset) = dispatch_literal_instruction {
        patch_ldr_literal(&mut bytes, offset, dispatch_literal);
    }
    bytes
}

/// Generate the x64-side entry thunk for an ARM64EC function.  On a real
/// Windows ARM64EC process this is x64 code that the emulator recognizes and
/// routes to the ARM64EC entry thunk; the encoding is exposed so callers can
/// emit it into x64-backed export/import slots and inspect it in tests.
pub fn build_x64_entry_stub(ec_target: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&[0x48, 0xb8]); // mov rax, imm64
    bytes.extend_from_slice(&ec_target.to_le_bytes());
    bytes.extend_from_slice(&[0xff, 0xe0]); // jmp rax
    bytes
}

pub struct Arm64Image {
    region: ExecutableRegion,
    pub base: u64,
    pub size: usize,
    pub mapped: MappedImage,
    protected: bool,
    thunk_cursor: usize,
    thunk_limit: usize,
}

impl Arm64Image {
    pub fn load(bytes: &[u8], image: &ParsedPe) -> AppResult<Self> {
        let size = image.size_of_image as usize;
        let page = page_size();
        let arena_start = size.div_ceil(page) * page;
        let mut region = ExecutableRegion::allocate(
            arena_start
                .checked_add(ARM64EC_THUNK_ARENA_SIZE)
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcInvalidParameter,
                        "ARM64 image allocation overflows",
                    )
                })?,
        )?;
        let base = region.address();
        let mapped = pe::map_image_at(bytes, image, base)?;
        if mapped.memory.len() > region.len() {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                "mapped ARM64 image exceeds its host allocation",
            ));
        }
        region.write(0, &mapped.memory)?;
        Ok(Self {
            region,
            base,
            size,
            mapped,
            protected: false,
            thunk_cursor: arena_start,
            thunk_limit: arena_start + ARM64EC_THUNK_ARENA_SIZE,
        })
    }

    /// Copy a generated transition thunk into the image-adjacent arena and
    /// return its host address.
    pub fn alloc_thunk(&mut self, bytes: &[u8]) -> AppResult<u64> {
        let offset = (self.thunk_cursor + 15) & !15;
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidParameter,
                "ARM64EC thunk arena offset overflows",
            )
        })?;
        if end > self.thunk_limit {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "ARM64EC transition thunk arena is full",
            ));
        }
        self.region.write(offset, bytes)?;
        self.region.finish_writes()?;
        self.thunk_cursor = end;
        Ok(self.base + offset as u64)
    }

    /// Rewrite direct `BL`/`B` instructions whose target is x64 code so they
    /// branch to a generated exit thunk instead of executing x64 bytes as
    /// ARM64.
    pub fn patch_cross_isa_direct_calls(
        &mut self,
        image: &ParsedPe,
        checker: &EcCallChecker,
    ) -> AppResult<usize> {
        let Some(chpe) = image.chpe_metadata() else {
            return Ok(0);
        };
        let mut patches = 0usize;
        for range in &chpe.code_map {
            if range.kind == ChpeCodeKind::Amd64 {
                continue;
            }
            let start = range.start_rva as usize;
            let end = (range.start_rva as usize)
                .checked_add(range.length as usize)
                .ok_or_else(|| {
                    AppError::new(ReasonCode::RcPeParseInvalid, "ARM64EC code range overflows")
                })?;
            let end = end.min(self.size);
            let mut offset = start & !3;
            while offset + 4 <= end {
                let word = u32::from_le_bytes(
                    self.region.as_slice()[offset..offset + 4]
                        .try_into()
                        .expect("4 bytes"),
                );
                let opcode = word & 0xfc00_0000;
                if opcode == 0x9400_0000 || opcode == 0x1400_0000 {
                    let pc = self.base + offset as u64;
                    let displacement = (((word & 0x03ff_ffff) << 6) as i32) >> 6;
                    let target = pc.wrapping_add((displacement as i64 * 4) as u64);
                    if checker
                        .classify(target)
                        .is_some_and(arm64x::EcFunctionKind::is_x64)
                    {
                        let thunk = build_ec_exit_thunk(Some(target), 0);
                        let thunk_address = self.alloc_thunk(&thunk)?;
                        let delta = thunk_address as i64 - pc as i64;
                        if delta % 4 != 0 || !(-(1 << 27)..(1 << 27)).contains(&delta) {
                            return Err(EcTransitionError::unsupported(
                                "ARM64EC direct-call thunk is outside BL reach",
                            )
                            .to_app_error());
                        }
                        let imm26 = ((delta / 4) as u32) & 0x03ff_ffff;
                        let patched = (word & 0xfc00_0000) | imm26;
                        self.region.write(offset, &patched.to_le_bytes())?;
                        self.region.finish_writes()?;
                        patches += 1;
                    }
                }
                offset += 4;
            }
        }
        Ok(patches)
    }

    pub fn entry_point(&self, image: &ParsedPe, view: HybridView) -> AppResult<u64> {
        let rva = arm64x::route_entry_point(image, view)?;
        self.address_for_rva(rva)
    }

    pub fn address_for_rva(&self, rva: u32) -> AppResult<u64> {
        if rva as usize >= self.size {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                format!("ARM64 image RVA 0x{rva:x} is outside SizeOfImage"),
            ));
        }
        Ok(self.base + u64::from(rva))
    }

    pub fn write_slot(&mut self, rva: u32, value: u64) -> AppResult<()> {
        let offset = rva as usize;
        let end = offset.checked_add(8).ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidParameter, "ARM64 IAT slot overflows")
        })?;
        if end > self.size {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                "ARM64 IAT slot exceeds SizeOfImage",
            ));
        }
        self.region.write(offset, &value.to_le_bytes())
    }

    pub fn bind_imports(
        &mut self,
        image: &ParsedPe,
        imports: &mut Arm64ImportTable,
    ) -> AppResult<()> {
        for descriptor in image.imports.iter().chain(image.delay_imports.iter()) {
            for thunk in &descriptor.imports {
                let name = match &thunk.symbol {
                    ImportSymbol::ByName { name, .. } => name.clone(),
                    ImportSymbol::ByOrdinal { ordinal } => {
                        format!("{}.{ordinal}", descriptor.dll_name)
                    }
                };
                let key = format!("{}.{}", descriptor.dll_name, name);
                let target = imports.resolve(&key).ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcImportMissing,
                        format!("missing ARM64 import callback {key}"),
                    )
                })?;
                self.write_slot(thunk.iat_rva, target)?;
            }
        }
        Ok(())
    }

    pub fn protect(&mut self) -> AppResult<()> {
        if !self.protected {
            self.region
                .protect_image_sections(&self.mapped.sections, self.size)?;
            self.protected = true;
        }
        Ok(())
    }

    pub fn sections(&self) -> &[SectionMapping] {
        &self.mapped.sections
    }

    pub fn bytes(&self) -> &[u8] {
        self.region.as_slice()
    }

    pub fn executable_region(&self) -> (u64, usize) {
        (self.region.address(), self.region.len())
    }
}

pub struct Arm64NativeRunner {
    pub image: Arm64Image,
    pub executor: Arm64Executor,
    pub imports: Arm64ImportTable,
    transition_stack: ExecutableRegion,
    transition_cursor: u64,
}

impl Arm64NativeRunner {
    pub fn load(bytes: &[u8], image: &ParsedPe) -> AppResult<Self> {
        let image = Arm64Image::load(bytes, image)?;
        let mut executor = Arm64Executor::new()?;
        executor.teb_mut().set_image_base(image.base);
        let imports = Arm64ImportTable::new()?;
        let transition_stack = ExecutableRegion::allocate_data(DEFAULT_STACK_SIZE)?;
        let transition_cursor = transition_stack.address() + transition_stack.len() as u64;
        Ok(Self {
            image,
            executor,
            imports,
            transition_stack,
            transition_cursor,
        })
    }

    /// Reserve an aligned native stack range for one x64 → ARM64EC
    /// transition.  Nested transitions get disjoint ranges.
    pub fn reserve_transition_stack(&mut self) -> AppResult<(u64, u64, u64)> {
        let base = self.transition_stack.address();
        let limit = base + 0x1000;
        let sp = (self.transition_cursor.saturating_sub(0x1000)) & !(ARM64_STACK_ALIGNMENT - 1);
        let next = sp.saturating_sub(0x4000);
        if sp < limit || next < limit {
            return Err(
                EcTransitionError::fault("ARM64EC transition stack is exhausted").to_app_error(),
            );
        }
        self.transition_cursor = next;
        Ok((sp, base, base + self.transition_stack.len() as u64))
    }

    pub fn release_transition_stack(&mut self, sp: u64) {
        self.transition_cursor = sp;
    }

    pub fn prepare(&mut self, image: &ParsedPe) -> AppResult<()> {
        self.image.bind_imports(image, &mut self.imports)?;
        self.image.protect()
    }

    pub fn call_entry(&mut self, image: &ParsedPe, args: &[u64]) -> AppResult<Arm64CallResult> {
        let entry = self.image.entry_point(image, HybridView::Native)?;
        let mut context = self.executor.prepare_context(entry, args);
        self.executor.call_with_context(&mut context)?;
        Ok(Arm64CallResult { context })
    }

    pub fn call_rva(&mut self, rva: u32, args: &[u64]) -> AppResult<Arm64CallResult> {
        let entry = self.image.address_for_rva(rva)?;
        let mut context = self.executor.prepare_context(entry, args);
        self.executor.call_with_context(&mut context)?;
        Ok(Arm64CallResult { context })
    }

    pub fn teb(&self) -> &Arm64Teb {
        self.executor.teb()
    }
}

/// Result of entering ARM64EC from x64 through an entry thunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcNativeCallResult {
    pub result: X64Return,
    pub state: EcAbiState,
    pub return_address: u64,
}

/// Execute an ARM64EC function on behalf of an x64 caller (the entry-thunk
/// direction).  The x64 caller's return address is popped from `[rsp]`; stack
/// arguments are copied to the native ARM64EC stack; x18 is set to the TEB;
/// and x64 non-volatile state is projected into the ARM64EC registers.
pub fn enter_ec_from_x64_native(
    runner: &mut Arm64NativeRunner,
    signature: &EcSignature,
    x64: &X64AbiState,
    x64_stack: &dyn EcStackAccess,
    target_rva: u32,
) -> AppResult<EcNativeCallResult> {
    let rsp = x64.gpr[crate::cpu::Register::Rsp.index()];
    if rsp % 8 != 0 {
        return Err(EcTransitionError::misaligned(rsp, 8).to_app_error());
    }
    let return_address = transition_stack_read(x64_stack, rsp)?;
    let args = x64_to_ec_arguments(signature, x64, x64_stack)?;
    let entry = runner.image.address_for_rva(target_rva)?;
    let (sp, native_base, native_top) = runner.reserve_transition_stack()?;
    if sp % ARM64_STACK_ALIGNMENT != 0 {
        return Err(EcTransitionError::misaligned(sp, ARM64_STACK_ALIGNMENT).to_app_error());
    }
    let mut native_stack = RawStack {
        base: native_base,
        pointer: native_base as *mut u8,
        len: native_top.saturating_sub(native_base) as usize,
    };
    if let Err(error) = write_ec_stack_arguments(&args, &mut native_stack, sp) {
        runner.release_transition_stack(sp);
        return Err(error);
    }
    let mut context = runner.executor.prepare_context(entry, &[]);
    context.pc = entry;
    context.sp = sp;
    context.x[..8].copy_from_slice(&args.gpr);
    context.d[..8].copy_from_slice(&args.vec);
    context.x[18] = runner.executor.teb_address();
    context.x[30] = 0;
    let mut ec = EcAbiState::from_context(&context);
    copy_x64_nonvolatile_to_ec(x64, &mut ec);
    ec.write_to_context(&mut context);
    push_transition_unwind(EcUnwindRecord::from_x64(x64));
    let call_result = runner.executor.call_with_context(&mut context);
    runner.release_transition_stack(sp);
    match call_result {
        Ok(()) => pop_transition_unwind(),
        Err(error) => {
            let transition = EcTransitionError::from_app_error(&error);
            unwind_transition(transition.status);
            return Err(error);
        }
    }
    let state = EcAbiState::from_context(&context);
    Ok(EcNativeCallResult {
        result: ec_result_to_x64(signature, &state),
        state,
        return_address,
    })
}

pub fn code_kind_for(image: &ParsedPe, rva: u32) -> Option<ChpeCodeKind> {
    image
        .chpe_metadata()
        .and_then(|chpe| chpe.code_kind_at(rva))
}

pub fn image_machine_is_native_arm64(image: &ParsedPe) -> bool {
    matches!(
        image.machine,
        IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC | IMAGE_FILE_MACHINE_ARM64X
    )
}

pub fn hybrid_metadata(image: &ParsedPe) -> Option<&Arm64ImageMetadata> {
    image.arm64.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{PeSection, SectionMapping};
    use crate::reason::ReasonCode;

    fn leaf_add(a: u16, b: u16) -> Vec<u8> {
        let mut assembler = Arm64Assembler::new();
        assembler
            .movz_x(0, a, 0)
            .movz_x(1, b, 0)
            .add_x_reg(0, 0, 1)
            .ret();
        assembler.into_bytes()
    }

    #[test]
    fn arm64_bridge_abi_offset_boundaries_are_pinned() {
        assert_eq!(std::mem::offset_of!(Arm64Context, x), 0);
        assert_eq!(std::mem::offset_of!(Arm64Context, sp), 248);
        assert_eq!(std::mem::offset_of!(Arm64Context, pc), 256);
        assert_eq!(std::mem::offset_of!(Arm64Context, nzcv), 264);
        assert_eq!(std::mem::offset_of!(Arm64Context, fpcr), 272);
        assert_eq!(std::mem::offset_of!(Arm64Context, fpsr), 276);
    }

    #[test]
    fn arm64_misaligned_stack_is_rejected_exactly() {
        let mut context = Arm64Context::new();
        context.sp = 0x1001;
        let error = invoke_bridge(&mut context).expect_err("misaligned stack must fail");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "ARM64 stack pointer 0x0000000000001001 is not 16-byte aligned"
        );
    }

    #[test]
    fn arm64_null_teb_is_rejected_exactly() {
        let mut context = Arm64Context::new();
        context.sp = 0x1000;
        let error = invoke_bridge(&mut context).expect_err("null TEB must fail");
        assert_eq!(error.message, "ARM64 x18 (TEB) is null");
    }

    #[test]
    fn arm64_zero_entry_point_is_rejected_exactly() {
        let mut context = Arm64Context::new();
        context.sp = 0x1000;
        context.x[18] = 0x2000;
        let error = invoke_bridge(&mut context).expect_err("null entry must fail");
        assert_eq!(
            error.message,
            "ARM64 entry point 0x0000000000000000 is outside the executable region"
        );
    }

    #[test]
    fn arm64_leaf_execution_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let code = leaf_add(20, 22);
        let result = execute_arm64_function(&code, &[]).expect("execute ARM64 leaf");
        assert_eq!(result, 42);
    }

    #[test]
    fn arm64_register_stack_and_flags_boundary_roundtrip() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler
            .sub_x_imm(31, 31, 32)
            .str_x_imm(3, 31, 0)
            .str_x_imm(4, 31, 8)
            .ldr_x_imm(0, 31, 0)
            .ldr_x_imm(1, 31, 8)
            .add_x_reg(0, 0, 1)
            .cmp_x_imm(0, 123)
            .add_x_imm(31, 31, 32)
            .ret();
        let mut context = Arm64Context::new();
        context.x[3] = 100;
        context.x[4] = 23;
        execute_arm64_context(&assembler.into_bytes(), &mut context)
            .expect("execute ARM64 context");
        assert_eq!(context.x[0], 123);
        assert_eq!(context.nzcv & 0x4000_0000, 0x4000_0000);
    }

    #[test]
    fn arm64_teb_peb_access_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.ldr_x_imm(0, 18, 0x60).ldr_x_imm(0, 0, 0x58).ret();
        let mut executor = Arm64Executor::new().unwrap();
        let code = assembler.into_bytes();
        let entry = executor.map_code(&code).unwrap();
        let mut context = executor.prepare_context(entry, &[]);
        executor.call_with_context(&mut context).unwrap();
        assert_eq!(context.x[0], 10);
        assert_eq!(executor.teb().peb().os_major_version, 10);
    }

    #[test]
    fn arm64_import_callback_argument_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut imports = Arm64ImportTable::new().unwrap();
        let address = imports
            .register("Add", |a0, a1, _a2, _a3, _a4, _a5, _a6, _a7| a0 + a1)
            .unwrap();
        assert_eq!(imports.resolve("Add"), Some(address));
        assert_eq!(imports.call("Add", &[19, 23]).unwrap(), 42);
    }

    #[test]
    fn arm64_native_import_thunk_edge_call_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut imports = Arm64ImportTable::new().unwrap();
        let callback = imports
            .register("Add", |a0, a1, _, _, _, _, _, _| a0 + a1)
            .unwrap();
        let mut assembler = Arm64Assembler::new();
        assembler
            .movz_x(0, 20, 0)
            .movz_x(1, 22, 0)
            .mov_abs_x(9, callback)
            .br(9);
        let mut executor = Arm64Executor::new().unwrap();
        let entry = executor.map_code(&assembler.into_bytes()).unwrap();
        let mut context = executor.prepare_context(entry, &[]);
        executor.call_with_context(&mut context).unwrap();
        assert_eq!(context.x[0], 42);
    }

    #[test]
    fn arm64_missing_import_callback_fails_closed() {
        let imports = Arm64ImportTable::new().unwrap();
        let error = imports
            .call("Missing", &[])
            .expect_err("missing import must fail");
        assert_eq!(error.code, ReasonCode::RcImportMissing);
        assert_eq!(error.message, "missing ARM64 import Missing");
    }

    #[test]
    fn cross_isa_transition_fails_closed_with_exact_status() {
        let error = CrossIsaError::new(Arm64Isa::Arm64, Arm64Isa::X64);
        assert_eq!(error.status, 0xc000_00bb);
        assert_eq!(error.missing_piece, MISSING_CROSS_ISA_PIECE);
        let message = error.to_string();
        assert!(message.contains("missing x64 guest instruction execution"));
        let app = error.to_app_error();
        assert_eq!(app.code, ReasonCode::RcUnimplInsn);
        assert_eq!(app.reproduction_hints[0], "ntstatus=0xc00000bb");
    }

    #[test]
    fn arm64_image_section_protection_boundary_is_pinned() {
        let mut bytes = vec![0u8; 0x800];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let section = optional + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let image = pe::parse(&bytes).expect("parse ARM64 image");
        let mut loaded = Arm64Image::load(&bytes, &image).expect("load ARM64 image");
        assert_eq!(loaded.sections()[0].protection.execute, true);
        loaded.protect().expect("protect ARM64 image");
        assert_eq!(loaded.protected, true);
    }

    fn arm64_pe_with_code(code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let section = optional + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes[0x400..0x400 + code.len()].copy_from_slice(code);
        bytes
    }

    #[test]
    fn arm64_native_pe_entry_execution_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.movz_x(0, 42, 0).ret();
        let bytes = arm64_pe_with_code(&assembler.into_bytes());
        let image = pe::parse(&bytes).expect("parse executable ARM64 PE");
        let mut runner = Arm64NativeRunner::load(&bytes, &image).expect("load ARM64 PE");
        runner.prepare(&image).expect("protect ARM64 PE");
        let result = runner
            .call_entry(&image, &[])
            .expect("execute ARM64 PE entry");
        assert_eq!(result.return_value(), 42);
        assert_eq!(runner.image.sections().len(), 1);
    }

    #[test]
    fn arm64_runtime_executes_native_pe_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.movz_x(0, 7, 0).ret();
        let bytes = arm64_pe_with_code(&assembler.into_bytes());
        let directory = tempfile::tempdir().expect("tempdir");
        let ge = crate::ge::GameEnvironment::create_in(
            directory.path(),
            "arm64-native",
            crate::ge::GeArch::X64,
            "win11-23h2",
        )
        .expect("create game environment");
        let path = directory.path().join("arm64.exe");
        std::fs::write(&path, &bytes).expect("write ARM64 PE");
        let result = crate::runtime::execute(
            &path,
            &[],
            &ge,
            directory.path(),
            &std::collections::BTreeMap::new(),
            true,
            "arm64-native-boundary",
        )
        .expect("execute native ARM64 PE");
        assert_eq!(result.exit_code, 7);
        assert_eq!(
            result.termination,
            crate::runtime::ExecutionTermination::GuestExit { code: 7 }
        );
    }

    fn arm64_pe_with_import(code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x800];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        bytes[optional + 120..optional + 124].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 124..optional + 128].copy_from_slice(&20u32.to_le_bytes());
        bytes[optional + 208..optional + 212].copy_from_slice(&0x2060u32.to_le_bytes());
        bytes[optional + 212..optional + 216].copy_from_slice(&16u32.to_le_bytes());
        let text = optional + 0xF0;
        bytes[text..text + 5].copy_from_slice(b".text");
        bytes[text + 8..text + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[text + 12..text + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[text + 16..text + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[text + 20..text + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[text + 36..text + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let data = text + 40;
        bytes[data..data + 6].copy_from_slice(b".idata");
        bytes[data + 8..data + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[data + 12..data + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[data + 16..data + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[data + 20..data + 24].copy_from_slice(&0x600u32.to_le_bytes());
        bytes[data + 36..data + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());
        bytes[0x400..0x400 + code.len()].copy_from_slice(code);
        bytes[0x600..0x614].copy_from_slice(&[
            0x40, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x20, 0, 0, 0x60, 0x20, 0, 0,
        ]);
        bytes[0x614..0x618].copy_from_slice(&[0, 0, 0, 0]);
        bytes[0x640..0x648].copy_from_slice(&0x20A0u64.to_le_bytes());
        bytes[0x660..0x668].copy_from_slice(&0x20A0u64.to_le_bytes());
        bytes[0x680..0x68D].copy_from_slice(b"kernel32.dll\0");
        bytes[0x6A0..0x6A2].copy_from_slice(&0u16.to_le_bytes());
        bytes[0x6A2..0x6B6].copy_from_slice(b"GetCurrentProcessId\0");
        bytes
    }

    #[test]
    fn arm64_runtime_import_callback_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.movz_x(0, 9, 0).ret();
        let bytes = arm64_pe_with_import(&assembler.into_bytes());
        let directory = tempfile::tempdir().expect("tempdir");
        let ge = crate::ge::GameEnvironment::create_in(
            directory.path(),
            "arm64-import",
            crate::ge::GeArch::X64,
            "win11-23h2",
        )
        .expect("create game environment");
        let path = directory.path().join("arm64-import.exe");
        std::fs::write(&path, &bytes).expect("write ARM64 import PE");
        let result = crate::runtime::execute(
            &path,
            &[],
            &ge,
            directory.path(),
            &std::collections::BTreeMap::new(),
            true,
            "arm64-import-boundary",
        )
        .expect("execute native ARM64 import PE");
        assert_eq!(result.exit_code, 9);
    }

    #[test]
    fn arm64_image_rejects_out_of_range_entry() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let image = pe::parse(&bytes).expect("parse minimal ARM64 image");
        let loaded = Arm64Image::load(&bytes, &image).expect("load minimal ARM64 image");
        let error = loaded
            .entry_point(&image, HybridView::Native)
            .expect_err("entry outside image must fail");
        assert_eq!(
            error.message,
            "ARM64 image RVA 0x2000 is outside SizeOfImage"
        );
    }

    #[test]
    fn arm64_import_slot_outside_image_is_rejected_exactly() {
        let bytes = vec![0u8; 0x400];
        let mut image = pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64;
        let mut loaded = Arm64Image::load(&bytes, &image).expect("load empty image");
        let error = loaded
            .write_slot(0x2000, 1)
            .expect_err("bad slot must fail");
        assert_eq!(error.message, "ARM64 IAT slot exceeds SizeOfImage");
    }

    #[test]
    fn arm64_executor_rejects_code_outside_region() {
        let mut executor = Arm64Executor::new().unwrap();
        let error = executor
            .call_address(0, &[])
            .expect_err("outside entry must fail");
        assert_eq!(
            error.message,
            "ARM64 entry point 0x0000000000000000 is outside the executable region"
        );
    }

    #[test]
    fn arm64_import_thunk_encoding_boundary_is_pinned() {
        let thunk = build_import_thunk(7, 0x1234_5678);
        assert_eq!(&thunk[56..64], &7u64.to_le_bytes());
        assert_eq!(&thunk[64..72], &0x1234_5678u64.to_le_bytes());
        assert_eq!(&thunk[0..4], &0x580001D0u32.to_le_bytes());
    }

    #[test]
    fn arm64_assembler_leaf_encoding_boundary_is_pinned() {
        let code = leaf_add(1, 2);
        assert_eq!(&code[0..4], &0xd2800020u32.to_le_bytes());
        assert_eq!(&code[4..8], &0xd2800041u32.to_le_bytes());
        assert_eq!(&code[8..12], &0x8b010000u32.to_le_bytes());
        assert_eq!(&code[12..16], &0xd65f03c0u32.to_le_bytes());
    }

    #[test]
    fn arm64_section_protection_rwx_boundary_is_pinned() {
        let section = SectionMapping {
            name: ".data".to_string(),
            virtual_address: 0x1000,
            mapped_size: 0x1000,
            raw_data_size: 0x1000,
            protection: crate::pe::MemoryProtection {
                read: true,
                write: true,
                execute: false,
            },
        };
        assert_eq!(
            section_protection(&section) & libc::PROT_WRITE,
            libc::PROT_WRITE
        );
        assert_ne!(
            section_protection(&section) & libc::PROT_EXEC,
            libc::PROT_EXEC
        );
    }

    #[test]
    fn arm64_code_kind_missing_chpe_map_route_is_pinned() {
        let mut image = pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64EC;
        image.arm64 = Some(Arm64ImageMetadata {
            machine: IMAGE_FILE_MACHINE_ARM64EC,
            chpe: None,
            dynamic_relocations: Vec::new(),
            extra_rfe_table: None,
            exception_tables: Vec::new(),
        });
        assert_eq!(code_kind_for(&image, 0x1000), None);
        assert!(image_machine_is_native_arm64(&image));
        assert!(hybrid_metadata(&image).is_some());
    }
    fn ec_test_image() -> ParsedPe {
        let mut image = pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64EC;
        image.image_base = 0x1_8000_0000;
        image.size_of_image = 0x3000;
        let chpe = arm64x::ChpeMetadata {
            code_map: vec![
                arm64x::ChpeCodeRange {
                    start_rva: 0x1000,
                    length: 0x1000,
                    kind: ChpeCodeKind::Arm64Ec,
                },
                arm64x::ChpeCodeRange {
                    start_rva: 0x2000,
                    length: 0x1000,
                    kind: ChpeCodeKind::Amd64,
                },
            ],
            ..arm64x::ChpeMetadata::default()
        };
        image.arm64 = Some(Arm64ImageMetadata {
            machine: IMAGE_FILE_MACHINE_ARM64EC,
            chpe: Some(chpe),
            dynamic_relocations: Vec::new(),
            extra_rfe_table: None,
            exception_tables: Vec::new(),
        });
        image
    }

    #[test]
    fn arm64ec_ec_x64_register_mapping_boundary_is_pinned() {
        use crate::cpu::Register;
        assert_eq!(X64_GPR_TO_ARM64[Register::Rax.index()], Some(8));
        assert_eq!(X64_GPR_TO_ARM64[Register::Rcx.index()], Some(0));
        assert_eq!(X64_GPR_TO_ARM64[Register::Rdx.index()], Some(1));
        assert_eq!(X64_GPR_TO_ARM64[Register::Rbx.index()], Some(27));
        assert_eq!(X64_GPR_TO_ARM64[Register::Rsp.index()], None);
        assert_eq!(X64_GPR_TO_ARM64[Register::R15.index()], Some(22));
        assert_eq!(ARM64_GPR_TO_X64[8], Some(Register::Rax.index()));
        assert_eq!(ARM64_GPR_TO_X64[18], None);
        assert_eq!(ARM64_GPR_TO_X64[30], None);
        assert_eq!(arm64x::EC_BLOCKED_ARM64_REGISTERS, [13, 14, 23, 24, 28]);
        assert_eq!(EC_NONVOLATILE_GPR_PAIRS[0], (3, 27));
        assert_eq!(EC_NONVOLATILE_VECTOR_INDICES[0], 6);
    }

    #[test]
    fn arm64ec_ec_mixed_float_stack_argument_boundary_is_exact() {
        use crate::cpu::Register;
        let signature = EcSignature::new(
            vec![
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
                EcParamKind::Float,
            ],
            EcReturnKind::Integer,
        );
        let mut memory = vec![0u8; 0x100];
        let base = 0x8000u64;
        let mut stack = BufferStack {
            base,
            bytes: &mut memory,
        };
        let mut x64 = X64AbiState::default();
        x64.gpr[Register::Rsp.index()] = base;
        x64.gpr[Register::Rcx.index()] = 0x11;
        x64.gpr[Register::Rdx.index()] = 0x22;
        x64.gpr[Register::R8.index()] = 0x33;
        x64.gpr[Register::R9.index()] = 0x44;
        x64.xmm[0] = 1.5f64.to_bits() as u128;
        x64.xmm[1] = 2.5f64.to_bits() as u128;
        x64.xmm[2] = 3.5f64.to_bits() as u128;
        x64.xmm[3] = 4.5f64.to_bits() as u128;
        stack.write_u64(base + 0x28, 0x55).unwrap();
        stack.write_u64(base + 0x30, 5.5f64.to_bits()).unwrap();
        let ec = x64_to_ec_arguments(&signature, &x64, &stack).expect("translate to EC");
        assert_eq!(ec.gpr[..6], [0x11, 0x22, 0x33, 0x44, 0x55, 0]);
        assert_eq!(ec.vec[0], 1.5f64.to_bits() as u128);
        assert_eq!(ec.vec[3], 4.5f64.to_bits() as u128);
        assert_eq!(ec.vec[4], 5.5f64.to_bits() as u128);
        assert_eq!(ec.stack, Vec::<u64>::new());

        let mut ec_state = EcAbiState::default();
        ec_state.sp = 0x9000;
        ec_state.x[..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0]);
        ec_state.q[0] = 1.5f64.to_bits() as u128;
        ec_state.q[1] = 2.5f64.to_bits() as u128;
        ec_state.q[2] = 3.5f64.to_bits() as u128;
        ec_state.q[3] = 4.5f64.to_bits() as u128;
        ec_state.q[4] = 5.5f64.to_bits() as u128;
        let mut out = vec![0u8; 0x100];
        let mut out_stack = BufferStack {
            base: 0x9000,
            bytes: &mut out,
        };
        let back =
            ec_to_x64_arguments(&signature, &ec_state, &out_stack).expect("translate to x64");
        assert_eq!(
            back.gpr[Register::Rcx.index()],
            0x11,
            "first integer stays in rcx"
        );
        assert_eq!(back.gpr[Register::R9.index()], 0x44);
        assert_eq!(back.vec[3], 4.5f64.to_bits() as u128);
        assert_eq!(back.stack, vec![0x55, 5.5f64.to_bits()]);
        write_x64_stack_arguments(&back, &mut out_stack, 0x9000).unwrap();
        assert_eq!(out_stack.read_u64(0x9000 + 0x28).unwrap(), 0x55);
        assert_eq!(out_stack.read_u64(0x9000 + 0x30).unwrap(), 5.5f64.to_bits());
    }

    #[test]
    fn arm64ec_ec_call_checker_rejects_missing_chpe_map_exactly() {
        let mut image = pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64EC;
        let error = EcCallChecker::for_image(&image).expect_err("missing map must fail");
        assert_eq!(error.code, ReasonCode::RcPeParseInvalid);
        assert_eq!(error.message, "ARM64EC image is missing CHPE metadata");
        assert_eq!(error.reproduction_hints[0], "ntstatus=0xc000007b");
    }

    #[test]
    fn arm64ec_ec_checker_routes_indirect_targets_by_code_map_exactly() {
        let image = ec_test_image();
        let checker = EcCallChecker::for_image(&image).expect("checker");
        let base = image.image_base;
        let exit = base + 0x1800;
        let native = checker.check(base + 0x1000, exit).expect("native target");
        assert_eq!(native.x11, base + 0x1000);
        assert_eq!(native.x10, exit);
        assert_eq!(native.x9, base + 0x1000);
        let x64 = checker.check(base + 0x2000, exit).expect("x64 target");
        assert_eq!(x64.x11, exit);
        assert_eq!(x64.x10, exit);
        assert_eq!(x64.x9, base + 0x2000);
        let error = checker
            .check(0xdead_beef, exit)
            .expect_err("unclassified target must fail closed");
        assert_eq!(error.code, ReasonCode::RcUnimplInsn);
        assert_eq!(error.reproduction_hints[0], "ntstatus=0xc00000bb");
    }

    #[test]
    fn arm64ec_ec_transition_unwind_restores_nonvolatile_state_exactly() {
        use crate::cpu::Register;
        let mut x64 = X64AbiState::default();
        x64.gpr[Register::Rsp.index()] = 0x7000;
        x64.gpr[Register::Rbx.index()] = 0xbb;
        x64.gpr[Register::R12.index()] = 0xcc;
        x64.xmm[6] = 0x1234_5678_9abc_def0_1122_3344_5566_7788;
        x64.rip = 0x4444;
        let record = EcUnwindRecord::from_x64(&x64);
        x64.gpr[Register::Rbx.index()] = 0;
        x64.gpr[Register::R12.index()] = 0;
        x64.xmm[6] = 0;
        x64.gpr[Register::Rsp.index()] = 0;
        record.restore_x64(&mut x64);
        assert_eq!(x64.gpr[Register::Rbx.index()], 0xbb);
        assert_eq!(x64.gpr[Register::R12.index()], 0xcc);
        assert_eq!(x64.xmm[6], 0x1234_5678_9abc_def0_1122_3344_5566_7788);
        assert_eq!(x64.gpr[Register::Rsp.index()], 0x7000);
        assert_eq!(x64.rip, 0x4444);

        let mut chain = EcUnwindChain::default();
        chain.push(EcUnwindRecord::from_x64(&x64));
        chain.push(EcUnwindRecord::from_ec(&EcAbiState::default()));
        assert_eq!(chain.depth(), 2);
        let records = chain.unwind(STATUS_ACCESS_VIOLATION);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].status, STATUS_ACCESS_VIOLATION);
        assert_eq!(chain.depth(), 0);
    }

    #[test]
    fn arm64ec_ec_exit_thunk_mixed_argument_boundary_is_exact() {
        if !native_arm64_available() {
            return;
        }
        use crate::cpu::Register;
        clear_exit_signatures();
        clear_exit_hook();
        let signature = EcSignature::new(
            vec![
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
                EcParamKind::Float,
                EcParamKind::Integer,
            ],
            EcReturnKind::Integer,
        );
        register_exit_signature(1, signature.clone());
        let observed = std::rc::Rc::new(std::cell::RefCell::new(None));
        let observed_slot = observed.clone();
        set_exit_hook(move |request| {
            *observed_slot.borrow_mut() = Some(request.clone());
            Ok(EcExitResponse {
                rax: 0xfeed_face,
                rdx: 0x1234,
                xmm0: 0xaaaa,
                xmm1: 0,
            })
        });
        clear_call_checker();
        let thunk = build_ec_exit_thunk(Some(0x1_8000_2000), 1);
        let mut executor = Arm64Executor::new().expect("executor");
        let entry = executor.map_code(&thunk).expect("map exit thunk");
        let mut context = executor.prepare_context(entry, &[]);
        context.x[0] = 0x11;
        context.x[1] = 0x22;
        context.x[2] = 0x33;
        context.x[3] = 0x44;
        context.x[4] = 0x99;
        context.d[0] = 1.5f64.to_bits() as u128;
        context.d[1] = 2.5f64.to_bits() as u128;
        context.d[2] = 3.5f64.to_bits() as u128;
        context.d[3] = 4.5f64.to_bits() as u128;
        // Ninth integer argument uses ARM64EC x4 and overflows to the x64
        // stack in the exit thunk.
        executor
            .call_with_context(&mut context)
            .expect("execute exit thunk");
        let request = observed
            .borrow_mut()
            .take()
            .expect("exit hook must observe the transition");
        assert_eq!(request.target, 0x1_8000_2000);
        assert_eq!(request.signature, signature);
        assert_eq!(
            request.args.gpr[Register::Rcx.index()],
            0x11,
            "integer args keep x64 order"
        );
        assert_eq!(request.args.gpr[Register::R9.index()], 0x44);
        assert_eq!(request.args.vec[0], 1.5f64.to_bits() as u128);
        assert_eq!(request.args.stack, vec![0x99]);
        assert_eq!(request.args.gpr[Register::Rcx.index()], 0x11);
        assert_eq!(context.x[0], 0xfeed_face, "rax maps to x0");
        assert_eq!(context.x[1], 0x1234, "rdx maps to x1");
        assert_eq!(context.d[0], 0xaaaa, "xmm0 maps to d0");
        assert!(take_exit_error().is_none());
        clear_exit_hook();
        clear_exit_signatures();
    }

    #[test]
    fn arm64ec_ec_check_thunk_routes_targets_and_reports_failure_exactly() {
        if !native_arm64_available() {
            return;
        }
        let image = ec_test_image();
        let checker = EcCallChecker::for_image(&image).expect("checker");
        set_call_checker(checker);
        let thunk = build_ec_check_thunk();
        let mut executor = Arm64Executor::new().expect("executor");
        let entry = executor.map_code(&thunk).expect("map check thunk");
        let base = image.image_base;
        let exit = base + 0x1800;
        let mut context = executor.prepare_context(entry, &[]);
        context.x[10] = exit;
        context.x[11] = base + 0x2000;
        context.x[0] = 0x41;
        executor
            .call_with_context(&mut context)
            .expect("execute check thunk");
        assert_eq!(context.x[9], base + 0x2000);
        assert_eq!(context.x[10], exit);
        assert_eq!(context.x[11], exit);
        assert_eq!(context.x[0], 0x41, "checker preserves x0");

        context = executor.prepare_context(entry, &[]);
        context.x[10] = exit;
        context.x[11] = 0xdead_beef;
        executor
            .call_with_context(&mut context)
            .expect("execute failing check thunk");
        assert_eq!(context.x[9], EC_CHECK_FAILED);
        let error = take_call_checker_error().expect("checker failure recorded");
        assert_eq!(error.status, STATUS_NOT_SUPPORTED);
        assert_eq!(
            error.detail,
            "ARM64EC call checker cannot classify target 0x00000000deadbeef"
        );
        clear_call_checker();
    }

    #[test]
    fn arm64ec_ec_x64_entry_stub_encoding_boundary_is_pinned() {
        let stub = build_x64_entry_stub(0x1_8000_2000);
        assert_eq!(&stub[0..2], &[0x48, 0xb8]);
        assert_eq!(&stub[2..10], &0x1_8000_2000u64.to_le_bytes());
        assert_eq!(&stub[10..12], &[0xff, 0xe0]);
    }

    #[test]
    fn arm64ec_ec_exit_frame_layout_boundary_is_pinned() {
        assert_eq!(std::mem::size_of::<EcExitFrame>(), EC_EXIT_FRAME_SIZE);
        assert_eq!(std::mem::offset_of!(EcExitFrame, sp), 208);
        assert_eq!(std::mem::offset_of!(EcExitFrame, target), 232);
        assert_eq!(std::mem::offset_of!(EcExitFrame, result_vec), 272);
        assert_eq!(std::mem::size_of::<EcCheckResult>(), 24);
    }

    fn arm64ec_hybrid_pe(entry_rva: u32, ec_code: &[u8], x64_code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x3400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64EC.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&entry_rva.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        // LOAD_CONFIG directory points at the synthetic load config.
        bytes[optional + 112 + 10 * 8..optional + 112 + 10 * 8 + 4]
            .copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[optional + 112 + 10 * 8 + 4..optional + 112 + 10 * 8 + 8]
            .copy_from_slice(&0x100u32.to_le_bytes());
        let section = optional + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0xE000_0020u32.to_le_bytes());
        // CHPE metadata at RVA 0x1100 (raw 0x500).
        bytes[0x500..0x504].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x504..0x508].copy_from_slice(&0x1180u32.to_le_bytes());
        bytes[0x508..0x50c].copy_from_slice(&3u32.to_le_bytes());
        bytes[0x580..0x584].copy_from_slice(&(0x1000u32 | 1).to_le_bytes());
        bytes[0x584..0x588].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x588..0x58c].copy_from_slice(&(0x2000u32 | 2).to_le_bytes());
        bytes[0x58c..0x590].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0x590..0x594].copy_from_slice(&(0x3000u32 | 2).to_le_bytes());
        bytes[0x594..0x598].copy_from_slice(&0x1000u32.to_le_bytes());
        // Load config CHPEMetadataPointer at RVA 0x1200 + 0xc8.
        bytes[0x6c8..0x6d0].copy_from_slice(&0x1_8000_1100u64.to_le_bytes());
        bytes[0x400..0x400 + ec_code.len()].copy_from_slice(ec_code);
        bytes[0x1400..0x1400 + x64_code.len()].copy_from_slice(x64_code);
        bytes
    }

    fn run_arm64ec_image(
        bytes: &[u8],
        test_id: &str,
    ) -> AppResult<crate::runtime::PeExecutionResult> {
        let directory = tempfile::tempdir().expect("tempdir");
        let ge = crate::ge::GameEnvironment::create_in(
            directory.path(),
            "arm64ec-hybrid",
            crate::ge::GeArch::X64,
            "win11-23h2",
        )
        .expect("create game environment");
        let path = directory.path().join("arm64ec-hybrid.exe");
        std::fs::write(&path, bytes).expect("write ARM64EC PE");
        crate::runtime::execute(
            &path,
            &[],
            &ge,
            directory.path(),
            &std::collections::BTreeMap::new(),
            true,
            test_id,
        )
    }

    #[test]
    fn arm64ec_ec_class_parallel_float_boundary_is_exact() {
        use crate::cpu::Register;
        let signature = EcSignature::class_parallel();
        let mut memory = vec![0u8; 0x100];
        let base = 0x4000u64;
        let stack = BufferStack {
            base,
            bytes: &mut memory,
        };
        let mut x64 = X64AbiState::default();
        x64.gpr[Register::Rsp.index()] = base;
        x64.gpr[Register::Rcx.index()] = 0x11;
        x64.gpr[Register::R8.index()] = 0x33;
        x64.xmm[0] = 1.25f64.to_bits() as u128;
        x64.xmm[2] = 3.25f64.to_bits() as u128;
        let ec = x64_to_ec_arguments(&signature, &x64, &stack).expect("class-parallel");
        assert_eq!(ec.gpr[0], 0x11);
        assert_eq!(ec.gpr[1], 0);
        assert_eq!(ec.gpr[2], 0x33);
        assert_eq!(ec.vec[0], 1.25f64.to_bits() as u128);
        assert_eq!(ec.vec[2], 3.25f64.to_bits() as u128);
        assert_eq!(
            ec_result_to_x64(&signature, &EcAbiState::default()).xmm0,
            0,
            "class-parallel return publishes both classes"
        );
        let mut result = EcAbiState::default();
        result.x[0] = 7;
        result.q[0] = 2.5f64.to_bits() as u128;
        let mapped = ec_result_to_x64(&signature, &result);
        assert_eq!(mapped.rax, 7);
        assert_eq!(mapped.xmm0, 2.5f64.to_bits() as u128);

        let mut ec_state = EcAbiState::default();
        ec_state.sp = 0x5000;
        ec_state.x[0] = 9;
        ec_state.q[0] = 4.5f64.to_bits() as u128;
        let mut out = vec![0u8; 0x100];
        let out_stack = BufferStack {
            base: 0x5000,
            bytes: &mut out,
        };
        let back =
            ec_to_x64_arguments(&signature, &ec_state, &out_stack).expect("class-parallel reverse");
        assert_eq!(back.gpr[Register::Rcx.index()], 9);
        assert_eq!(back.vec[0], 4.5f64.to_bits() as u128);
        assert_eq!(back.returns, EcReturnKind::Auto);
    }

    #[test]
    fn arm64ec_ec_entry_stack_misalignment_is_rejected_exactly() {
        if !native_arm64_available() {
            return;
        }
        let mut ec = Arm64Assembler::new();
        ec.ret();
        let bytes = arm64ec_hybrid_pe(0x1000, &ec.into_bytes(), &[0xc3]);
        let image = pe::parse(&bytes).expect("parse hybrid image");
        let mut runner = Arm64NativeRunner::load(&bytes, &image).expect("runner");
        let mut x64 = X64AbiState::default();
        x64.gpr[crate::cpu::Register::Rsp.index()] = 0x1001;
        let mut memory = vec![0u8; 0x100];
        let stack = BufferStack {
            base: 0,
            bytes: &mut memory,
        };
        let error = enter_ec_from_x64_native(
            &mut runner,
            &EcSignature::all_integer(),
            &x64,
            &stack,
            0x1000,
        )
        .expect_err("misaligned x64 stack must be rejected before the transition");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "ARM64EC stack pointer 0x0000000000001001 is not 8-byte aligned"
        );
        assert_eq!(
            error.reproduction_hints,
            vec!["ntstatus=0xc0000005".to_string()]
        );
    }

    #[test]
    fn arm64ec_ec_mixed_x64_ec_x64_chain_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut ec = Arm64Assembler::new();
        ec.sub_x_imm(31, 31, 16).str_x_imm(30, 31, 0);
        // bl 0x3000 from RVA 0x1008: (0x3000 - 0x1008) / 4 = 0x7fe.
        ec.word(0x9400_0000 | 0x7fe);
        ec.ldr_x_imm(30, 31, 0).add_x_imm(31, 31, 16).ret();
        let ec_code = ec.into_bytes();
        let mut x64 = Vec::new();
        x64.extend_from_slice(&[0xb9, 10, 0, 0, 0]); // mov ecx, 10
        let next_rva = 0x2000u32 + x64.len() as u32 + 5;
        let displacement = 0x1000i32 - next_rva as i32;
        x64.push(0xe8);
        x64.extend_from_slice(&displacement.to_le_bytes());
        x64.push(0xc3);
        let mut bytes = arm64ec_hybrid_pe(0x2000, &ec_code, &x64);
        // x64 helper at RVA 0x3000: mov eax, ecx; add eax, 5; ret.
        bytes[0x2400..0x2407].copy_from_slice(&[0x89, 0xc8, 0x83, 0xc0, 5, 0xc3, 0x90]);
        let result = run_arm64ec_image(&bytes, "arm64ec-chain").expect("mixed chain");
        assert_eq!(result.exit_code, 15);
        assert_eq!(
            result.termination,
            crate::runtime::ExecutionTermination::GuestExit { code: 15 }
        );
    }

    #[test]
    fn arm64ec_ec_unwind_across_transition_reports_exact_status() {
        if !native_arm64_available() {
            return;
        }
        let mut ec = Arm64Assembler::new();
        ec.sub_x_imm(31, 31, 16).str_x_imm(30, 31, 0);
        // bl 0x2000 from RVA 0x1008: (0x2000 - 0x1008) / 4 = 0x3fe.
        ec.word(0x9400_0000 | 0x3fe);
        ec.ldr_x_imm(30, 31, 0).add_x_imm(31, 31, 16).ret();
        let ec_code = ec.into_bytes();
        // mov rax, qword ptr [0]; ret -> the x64 side faults at address 0.
        let x64 = vec![0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0xc3];
        let bytes = arm64ec_hybrid_pe(0x1000, &ec_code, &x64);
        let error = match run_arm64ec_image(&bytes, "arm64ec-unwind") {
            Ok(_) => panic!("an x64 access violation must abort the transition"),
            Err(error) => error,
        };
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.reproduction_hints,
            vec!["ntstatus=0xc0000005".to_string()]
        );
        assert_eq!(error.message, "unmapped guest memory at 0x0");
        let records = take_last_unwind_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, STATUS_ACCESS_VIOLATION);
        assert_eq!(records[0].from, Arm64Isa::Arm64);
        assert_eq!(records[0].to, Arm64Isa::X64);
    }

    #[test]
    fn arm64ec_ec_hybrid_direct_x64_to_native_call_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut ec = Arm64Assembler::new();
        ec.add_x_imm(0, 0, 1).ret();
        let ec_code = ec.into_bytes();
        let mut x64 = Vec::new();
        x64.extend_from_slice(&[0xb9, 41, 0, 0, 0]); // mov ecx, 41 (zero-extends)
        let next_rva = 0x2000u32 + x64.len() as u32 + 5;
        let displacement = 0x1000i32 - next_rva as i32;
        x64.push(0xe8);
        x64.extend_from_slice(&displacement.to_le_bytes());
        x64.push(0xc3);
        let bytes = arm64ec_hybrid_pe(0x2000, &ec_code, &x64);
        let image = pe::parse(&bytes).expect("parse hybrid image");
        let result = run_arm64ec_image(&bytes, "arm64ec-x64-to-ec").expect("execute hybrid");
        assert_eq!(
            crate::arm64::code_kind_for(&image, 0x1000),
            Some(ChpeCodeKind::Arm64Ec)
        );
        assert_eq!(
            crate::arm64::code_kind_for(&image, 0x2000),
            Some(ChpeCodeKind::Amd64)
        );
        assert_eq!(result.exit_code, 42);
        assert_eq!(
            result.termination,
            crate::runtime::ExecutionTermination::GuestExit { code: 42 }
        );
    }

    #[test]
    fn arm64ec_ec_hybrid_direct_native_to_x64_call_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut ec = Arm64Assembler::new();
        ec.sub_x_imm(31, 31, 16)
            .str_x_imm(30, 31, 0)
            .movz_x(0, 41, 0);
        // bl 0x2000 from RVA 0x100c: (0x2000 - 0x100c) / 4 = 0x3fd.
        ec.word(0x9400_0000 | 0x3fd);
        ec.ldr_x_imm(30, 31, 0).add_x_imm(31, 31, 16).ret();
        let ec_code = ec.into_bytes();
        // mov rax, rcx; inc rax; ret
        let x64 = vec![0x48, 0x89, 0xc8, 0x48, 0xff, 0xc0, 0xc3];
        let bytes = arm64ec_hybrid_pe(0x1000, &ec_code, &x64);
        let result = run_arm64ec_image(&bytes, "arm64ec-ec-to-x64").expect("execute hybrid");
        assert_eq!(result.exit_code, 42);
        assert_eq!(
            result.termination,
            crate::runtime::ExecutionTermination::GuestExit { code: 42 }
        );
    }
}
