#![allow(unused_imports)]

use super::*;
use crate::cpu::{
    ConditionCode, CpuState, GuestArch, GuestMemoryFault, GuestMemoryStore, IrInstruction,
    MemoryImage, Register,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

// ---------------------------------------------------------------------------
// JIT compiler: IR -> ARM64 machine code
// ---------------------------------------------------------------------------

/// Exit reason codes written by JIT code to signal back to the host.
pub(super) const EXIT_NORMAL: u64 = 0;
pub(super) const EXIT_THUNK: u64 = 1;
pub(super) const EXIT_UNIMPL: u64 = 2;
#[allow(dead_code)]
pub(super) const EXIT_COND_BRANCH: u64 = 3;
#[allow(dead_code)]
pub(super) const EXIT_INDIRECT_CALL: u64 = 4;
pub(super) const EXIT_RET: u64 = 5;
#[allow(dead_code)]
pub(super) const EXIT_MEM_ACCESS: u64 = 6;
pub(super) const EXIT_CPUID: u64 = 7;
#[allow(dead_code)]
pub(super) const EXIT_EXCEPTION: u64 = 8;
/// Block ended in an unconditional Jump — the dispatcher must set state.rip
/// to the jump target (carried in the last IR instruction) so the main loop
/// dispatches the target block next.  Without this, EXIT_NORMAL leaves rip at
/// the block start and the main loop re-dispatches the same block forever.
pub(super) const EXIT_JUMP: u64 = 9;
/// Block hit the host safepoint flag (`JIT_SAFEPOINT_REQUESTED`) — the
/// dispatcher must run the host-side safepoint body and re-dispatch the
/// block.  Emitted by `emit_safepoint_check`.
pub(super) const EXIT_SAFEPOINT: u64 = 10;
/// A guest load/store faulted on unmapped memory INSIDE the block.  The
/// immediate flag test after every helper call branches here so the block
/// aborts at the faulting instruction — Windows requires that an access
/// violation at instruction N prevents instructions N+1.. from executing.
/// The dispatcher reads the precise fault from `CpuState::jit_pending_fault`
/// (+ `jit_pending_fault_write`) and raises the same access-violation error
/// the interpreter produces.
pub(super) const EXIT_GUEST_FAULT: u64 = 11;
/// Production-worker indirect control transfers.  The compiled block cannot
/// write `state.rip` (unstable repr(Rust) offset) and has no live
/// `MemoryImage`, so it publishes the resolved target (register operand) or the
/// guest address the target must be loaded from (memory operand) into the
/// per-thread cell word `cell[2]` and exits with one of these codes.  The
/// worker resolves the target and continues natively (inline cache) instead of
/// yielding to the runtime owner.
pub(super) const EXIT_INDIRECT_JUMP_REG: u64 = 12;
pub(super) const EXIT_INDIRECT_CALL_REG: u64 = 13;
pub(super) const EXIT_INDIRECT_JUMP_MEM: u64 = 14;
pub(super) const EXIT_INDIRECT_CALL_MEM: u64 = 15;
/// Production-worker direct `call target`: the static target is published in
/// the per-thread exit cell payload (same convention as the indirect codes).
/// The worker pushes the static return address and either chains to the
/// compiled callee block or reports the target as a host barrier.
pub(super) const EXIT_CALL_DIRECT: u64 = 16;
/// Direct call whose return address was already pushed natively by the
/// compiled block.  The worker must not push it a second time.
pub(super) const EXIT_CALL_PUSHED: u64 = 17;
/// The compiled block's link-budget counter reached zero.  The current block
/// has NOT executed; the dispatcher refills the counter and re-enters it.
pub(super) const EXIT_LINK_BUDGET: u64 = 18;
/// The block's prologue observed a guest-code write epoch change.  The block
/// has NOT executed; the dispatcher invalidates stale translated code.
pub(super) const EXIT_CODE_EPOCH: u64 = 19;
/// A native `Jcc` determined the branch was taken / not taken.  The host no
/// longer re-evaluates the condition; it only maps the outcome to RIP.
pub(super) const EXIT_COND_TAKEN: u64 = 20;
pub(super) const EXIT_COND_NOT_TAKEN: u64 = 21;
/// Native worker `ret`: the return address was already loaded from guest
/// `[rsp]`, `rsp` was advanced, and the result is in the payload word.
pub(super) const EXIT_RET_RESOLVED: u64 = 22;

/// Byte offset (within the per-thread exit cell) of the indirect payload word.
pub(crate) const EXIT_CELL_PAYLOAD_OFFSET: u64 = 16;

/// Atomic link slots belonging to one block.  Each slot is published by the
/// runtime after translation (and cleared on invalidation) and read by the
/// compiled block with an acquire load.  Keeping every edge separate means a
/// direct call or a two-way conditional branch can be linked independently
/// without patching instruction memory (which would race executors).
#[derive(Clone)]
pub(super) struct LinkSlots {
    pub(super) jump: Arc<AtomicU64>,
    pub(super) taken: Arc<AtomicU64>,
    pub(super) fallthrough: Arc<AtomicU64>,
    pub(super) call: Arc<AtomicU64>,
    pub(super) return_entry: Arc<AtomicU64>,
}

impl LinkSlots {
    pub(super) fn new() -> Self {
        Self {
            jump: Arc::new(AtomicU64::new(0)),
            taken: Arc::new(AtomicU64::new(0)),
            fallthrough: Arc::new(AtomicU64::new(0)),
            call: Arc::new(AtomicU64::new(0)),
            return_entry: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Helper functions whose absolute address is embedded in translated code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AotHelper {
    Load,
    Store,
    ExecuteInsn,
    SegmentBase,
    SetFlags,
    MaterializeFlags,
    LockXadd,
    Shift,
}

impl AotHelper {
    pub(super) fn address(self) -> u64 {
        match self {
            Self::Load => jit_helper_load as *const () as u64,
            Self::Store => jit_helper_store as *const () as u64,
            Self::ExecuteInsn => jit_helper_execute_insn as *const () as u64,
            Self::SegmentBase => jit_helper_segment_base as *const () as u64,
            Self::SetFlags => jit_helper_set_flags as *const () as u64,
            Self::MaterializeFlags => jit_helper_materialize_flags as *const () as u64,
            Self::LockXadd => jit_helper_lock_xadd as *const () as u64,
            Self::Shift => jit_helper_shift as *const () as u64,
        }
    }

    pub(super) fn code(self) -> u32 {
        match self {
            Self::Load => 1,
            Self::Store => 2,
            Self::ExecuteInsn => 3,
            Self::SegmentBase => 4,
            Self::SetFlags => 5,
            Self::MaterializeFlags => 6,
            Self::LockXadd => 7,
            Self::Shift => 8,
        }
    }

    pub(super) fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            1 => Self::Load,
            2 => Self::Store,
            3 => Self::ExecuteInsn,
            4 => Self::SegmentBase,
            5 => Self::SetFlags,
            6 => Self::MaterializeFlags,
            7 => Self::LockXadd,
            8 => Self::Shift,
            _ => return None,
        })
    }
}

/// One absolute value embedded in translated code that must be re-bound when
/// the block is loaded from the persistent AOT cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AotRelocation {
    /// Byte offset of the fixed four-instruction `movz`/`movk` sequence.
    pub(super) offset: u32,
    pub(super) kind: AotRelocKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AotRelocKind {
    SafepointFlag,
    CodeEpoch,
    JumpLink,
    TakenLink,
    FallthroughLink,
    CallLink,
    ReturnEntryLink,
    Helper(AotHelper),
}

impl AotRelocKind {
    pub(super) fn code(self) -> u32 {
        match self {
            Self::SafepointFlag => 0,
            Self::CodeEpoch => 1,
            Self::JumpLink => 2,
            Self::TakenLink => 3,
            Self::FallthroughLink => 4,
            Self::CallLink => 5,
            Self::ReturnEntryLink => 6,
            Self::Helper(helper) => 0x100 + helper.code(),
        }
    }

    pub(super) fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => Self::SafepointFlag,
            1 => Self::CodeEpoch,
            2 => Self::JumpLink,
            3 => Self::TakenLink,
            4 => Self::FallthroughLink,
            5 => Self::CallLink,
            6 => Self::ReturnEntryLink,
            other => Self::Helper(AotHelper::from_code(other.checked_sub(0x100)?)?),
        })
    }
}

/// Persistent-cache format version.  Bumped whenever the emitted-code ABI
/// (chain-state offsets, exit codes, relocation layout) changes.
pub const AOT_FORMAT_VERSION: u32 = 2;
/// Cache key component: bump when code generation changes without changing the
/// IR hash (e.g. an emitter fix).  A stale file is rejected, never executed.
pub const AOT_TRANSLATOR_VERSION: u32 = 6;

/// Optimization-profile key component for worker-slice Tier0 blocks.
pub(super) const AOT_SLICE_OPT_PROFILE: u32 = 1;

/// Absolute target CPU profile stored in the AOT key.
pub fn aot_target_cpu_profile() -> u64 {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in arch.bytes().chain(os.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

/// A serializer/deserializer for one translated block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AotRecord {
    pub(super) format: u32,
    pub(super) translator: u32,
    pub(super) machine: u64,
    pub(super) cpu_profile: u64,
    /// Image content hash this record was produced from.  Validated when the
    /// runtime is bound to an image; a record from another image is rejected.
    pub(super) image_hash: String,
    pub(super) optimization_profile: u32,
    pub(super) guest_address: u64,
    pub(super) code_hash: u64,
    pub(super) logical_code_hash: u64,
    pub(super) instruction_count: u64,
    pub(super) code_size: u32,
    pub(super) worker_safe: bool,
    pub(super) exit_info: Option<BlockExitInfo>,
    pub(super) code: Vec<u8>,
    pub(super) relocations: Vec<AotRelocation>,
}

impl AotRecord {
    const MAGIC: &'static [u8; 8] = b"C1AOTC\0\0";

    pub(super) fn machine_tag() -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in std::env::consts::ARCH
            .bytes()
            .chain(std::env::consts::OS.bytes())
            .chain(std::env::consts::FAMILY.bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.code.len() + self.relocations.len() * 8);
        out.extend_from_slice(Self::MAGIC);
        out.extend_from_slice(&self.format.to_le_bytes());
        out.extend_from_slice(&self.translator.to_le_bytes());
        out.extend_from_slice(&self.machine.to_le_bytes());
        out.extend_from_slice(&self.cpu_profile.to_le_bytes());
        out.extend_from_slice(&(self.image_hash.len() as u16).to_le_bytes());
        out.extend_from_slice(self.image_hash.as_bytes());
        out.extend_from_slice(&self.optimization_profile.to_le_bytes());
        out.extend_from_slice(&self.guest_address.to_le_bytes());
        out.extend_from_slice(&self.code_hash.to_le_bytes());
        out.extend_from_slice(&self.logical_code_hash.to_le_bytes());
        out.extend_from_slice(&self.instruction_count.to_le_bytes());
        out.extend_from_slice(&self.code_size.to_le_bytes());
        out.push(u8::from(self.worker_safe));
        encode_exit_info(&mut out, self.exit_info);
        out.extend_from_slice(&(self.relocations.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.code);
        for relocation in &self.relocations {
            out.extend_from_slice(&relocation.offset.to_le_bytes());
            out.extend_from_slice(&relocation.kind.code().to_le_bytes());
        }
        let checksum = fnv1a(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 + 4 * 10 + 1 + 2 + 1 + 4 + 8 {
            return Err("truncated record header");
        }
        if &bytes[..8] != Self::MAGIC {
            return Err("bad magic");
        }
        let payload_end = bytes.len() - 8;
        let expected = u64::from_le_bytes(
            bytes[payload_end..]
                .try_into()
                .map_err(|_| "truncated checksum")?,
        );
        if fnv1a(&bytes[..payload_end]) != expected {
            return Err("checksum mismatch");
        }
        let mut cursor = 8;
        let read_u32 = |cursor: &mut usize| -> Result<u32, &'static str> {
            let value = u32::from_le_bytes(
                bytes
                    .get(*cursor..*cursor + 4)
                    .ok_or("truncated u32")?
                    .try_into()
                    .map_err(|_| "truncated u32")?,
            );
            *cursor += 4;
            Ok(value)
        };
        let read_u64 = |cursor: &mut usize| -> Result<u64, &'static str> {
            let value = u64::from_le_bytes(
                bytes
                    .get(*cursor..*cursor + 8)
                    .ok_or("truncated u64")?
                    .try_into()
                    .map_err(|_| "truncated u64")?,
            );
            *cursor += 8;
            Ok(value)
        };
        let read_u16 = |cursor: &mut usize| -> Result<u16, &'static str> {
            let value = u16::from_le_bytes(
                bytes
                    .get(*cursor..*cursor + 2)
                    .ok_or("truncated u16")?
                    .try_into()
                    .map_err(|_| "truncated u16")?,
            );
            *cursor += 2;
            Ok(value)
        };
        let format = read_u32(&mut cursor)?;
        let translator = read_u32(&mut cursor)?;
        let machine = read_u64(&mut cursor)?;
        let cpu_profile = read_u64(&mut cursor)?;
        let image_hash_len = read_u16(&mut cursor)? as usize;
        let image_hash_end = cursor
            .checked_add(image_hash_len)
            .ok_or("image hash overflow")?;
        let image_hash = std::str::from_utf8(
            bytes
                .get(cursor..image_hash_end)
                .ok_or("truncated image hash")?,
        )
        .map_err(|_| "invalid image hash encoding")?
        .to_string();
        cursor = image_hash_end;
        let optimization_profile = read_u32(&mut cursor)?;
        let guest_address = read_u64(&mut cursor)?;
        let code_hash = read_u64(&mut cursor)?;
        let logical_code_hash = read_u64(&mut cursor)?;
        let instruction_count = read_u64(&mut cursor)?;
        let code_size = read_u32(&mut cursor)?;
        let worker_safe = *bytes.get(cursor).ok_or("truncated flag")? != 0;
        cursor += 1;
        let exit_info = decode_exit_info(bytes, &mut cursor)?;
        let relocation_count = read_u32(&mut cursor)? as usize;
        let code_end = cursor
            .checked_add(code_size as usize)
            .ok_or("code size overflow")?;
        let code = bytes
            .get(cursor..code_end)
            .ok_or("truncated code")?
            .to_vec();
        cursor = code_end;
        let table_end = cursor
            .checked_add(relocation_count * 8)
            .ok_or("relocation overflow")?;
        if table_end > payload_end {
            return Err("truncated relocation table");
        }
        let mut relocations = Vec::with_capacity(relocation_count);
        for _ in 0..relocation_count {
            let offset = read_u32(&mut cursor)?;
            let kind = AotRelocKind::from_code(read_u32(&mut cursor)?).ok_or("unknown reloc")?;
            relocations.push(AotRelocation { offset, kind });
        }
        if cursor != payload_end {
            return Err("trailing bytes");
        }
        Ok(Self {
            format,
            translator,
            machine,
            cpu_profile,
            image_hash,
            optimization_profile,
            guest_address,
            code_hash,
            logical_code_hash,
            instruction_count,
            code_size,
            worker_safe,
            exit_info,
            code,
            relocations,
        })
    }
}

pub(super) fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

pub(super) fn encode_exit_info(out: &mut Vec<u8>, info: Option<BlockExitInfo>) {
    match info {
        None => out.push(0),
        Some(BlockExitInfo::Jump { target }) => {
            out.push(1);
            out.extend_from_slice(&target.to_le_bytes());
        }
        Some(BlockExitInfo::JumpIf {
            condition,
            target,
            fallthrough,
        }) => {
            out.push(2);
            out.push(condition_code_tag(condition));
            out.extend_from_slice(&target.to_le_bytes());
            out.extend_from_slice(&fallthrough.to_le_bytes());
        }
        Some(BlockExitInfo::Return { stack_adjust }) => {
            out.push(3);
            out.extend_from_slice(&stack_adjust.to_le_bytes());
        }
        Some(BlockExitInfo::Call {
            target,
            return_address,
        }) => {
            out.push(4);
            out.extend_from_slice(&target.to_le_bytes());
            out.extend_from_slice(&return_address.to_le_bytes());
        }
        Some(BlockExitInfo::CallIndirect { return_address }) => {
            out.push(5);
            out.extend_from_slice(&return_address.to_le_bytes());
        }
    }
}

pub(super) fn decode_exit_info(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<BlockExitInfo>, &'static str> {
    let tag = *bytes.get(*cursor).ok_or("truncated exit info")?;
    *cursor += 1;
    let read_u64 = |cursor: &mut usize| -> Result<u64, &'static str> {
        let value = u64::from_le_bytes(
            bytes
                .get(*cursor..*cursor + 8)
                .ok_or("truncated exit info value")?
                .try_into()
                .map_err(|_| "truncated exit info value")?,
        );
        *cursor += 8;
        Ok(value)
    };
    Ok(Some(match tag {
        0 => return Ok(None),
        1 => BlockExitInfo::Jump {
            target: read_u64(cursor)?,
        },
        2 => {
            let condition = condition_from_tag(*bytes.get(*cursor).ok_or("truncated condition")?)
                .ok_or("unknown condition")?;
            *cursor += 1;
            BlockExitInfo::JumpIf {
                condition,
                target: read_u64(cursor)?,
                fallthrough: read_u64(cursor)?,
            }
        }
        3 => BlockExitInfo::Return {
            stack_adjust: read_u64(cursor)?,
        },
        4 => BlockExitInfo::Call {
            target: read_u64(cursor)?,
            return_address: read_u64(cursor)?,
        },
        5 => BlockExitInfo::CallIndirect {
            return_address: read_u64(cursor)?,
        },
        _ => return Err("unknown exit info tag"),
    }))
}

pub(super) fn condition_code_tag(condition: ConditionCode) -> u8 {
    match condition {
        ConditionCode::Equal => 0,
        ConditionCode::NotEqual => 1,
        ConditionCode::Overflow => 2,
        ConditionCode::NotOverflow => 3,
        ConditionCode::Below => 4,
        ConditionCode::NotBelow => 5,
        ConditionCode::Above => 6,
        ConditionCode::NotAbove => 7,
        ConditionCode::Sign => 8,
        ConditionCode::NotSign => 9,
        ConditionCode::Less => 10,
        ConditionCode::GreaterEqual => 11,
        ConditionCode::LessEqual => 12,
        ConditionCode::Greater => 13,
        ConditionCode::Parity => 14,
        ConditionCode::NotParity => 15,
    }
}

pub(super) fn condition_from_tag(tag: u8) -> Option<ConditionCode> {
    Some(match tag {
        0 => ConditionCode::Equal,
        1 => ConditionCode::NotEqual,
        2 => ConditionCode::Overflow,
        3 => ConditionCode::NotOverflow,
        4 => ConditionCode::Below,
        5 => ConditionCode::NotBelow,
        6 => ConditionCode::Above,
        7 => ConditionCode::NotAbove,
        8 => ConditionCode::Sign,
        9 => ConditionCode::NotSign,
        10 => ConditionCode::Less,
        11 => ConditionCode::GreaterEqual,
        12 => ConditionCode::LessEqual,
        13 => ConditionCode::Greater,
        14 => ConditionCode::Parity,
        15 => ConditionCode::NotParity,
        _ => return None,
    })
}
