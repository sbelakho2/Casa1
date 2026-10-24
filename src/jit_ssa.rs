//! Tier-2 whole-function SSA optimizer for the Casa1 JIT.
//!
//! Takes a function made of several decoded basic blocks, builds a CFG and
//! real SSA form, runs GVN/SCCP/DCE/LICM and exact-address load/store
//! forwarding, allocates the guest register file across block boundaries, and
//! lowers the result to IR for the existing ARM64 backend.  Unsupported
//! constructs are rejected as a unit so the runtime can keep Tier-0.

use crate::cpu::{
    CompareOperand, ConditionCode, GuestArch, IrInstruction, MemoryOperand, Register,
    SegmentRegister,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

pub const FLAGS_VAR: u8 = 16;
pub const VAR_COUNT: usize = 17;
pub const SPILL_SLOTS: usize = 32;
const PHI_STAGE_BASE: usize = 16;
const SPILL_SCRATCH: [usize; 3] = [13, 14, 15];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tier2Metrics {
    pub functions_compiled: u64,
    pub functions_fallback: u64,
    pub blocks: u64,
    pub ssa_values: u64,
    pub instructions_before: u64,
    pub instructions_after: u64,
    pub sccp_eliminated: u64,
    pub gvn_eliminated: u64,
    pub dce_eliminated: u64,
    pub licm_hoisted: u64,
    pub load_forwarded: u64,
    pub store_eliminated: u64,
    pub register_spills: u64,
    pub fallback_reasons: BTreeMap<String, u64>,
}

static FUNCTIONS_COMPILED: AtomicU64 = AtomicU64::new(0);
static FUNCTIONS_FALLBACK: AtomicU64 = AtomicU64::new(0);
static BLOCKS: AtomicU64 = AtomicU64::new(0);
static SSA_VALUES: AtomicU64 = AtomicU64::new(0);
static INSTRUCTIONS_BEFORE: AtomicU64 = AtomicU64::new(0);
static INSTRUCTIONS_AFTER: AtomicU64 = AtomicU64::new(0);
static SCCP_ELIMINATED: AtomicU64 = AtomicU64::new(0);
static GVN_ELIMINATED: AtomicU64 = AtomicU64::new(0);
static DCE_ELIMINATED: AtomicU64 = AtomicU64::new(0);
static LICM_HOISTED: AtomicU64 = AtomicU64::new(0);
static LOAD_FORWARDED: AtomicU64 = AtomicU64::new(0);
static STORE_ELIMINATED: AtomicU64 = AtomicU64::new(0);
static REGISTER_SPILLS: AtomicU64 = AtomicU64::new(0);
static FALLBACK_REASONS: LazyLock<Mutex<BTreeMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub fn tier2_metrics() -> Tier2Metrics {
    Tier2Metrics {
        functions_compiled: FUNCTIONS_COMPILED.load(Ordering::Relaxed),
        functions_fallback: FUNCTIONS_FALLBACK.load(Ordering::Relaxed),
        blocks: BLOCKS.load(Ordering::Relaxed),
        ssa_values: SSA_VALUES.load(Ordering::Relaxed),
        instructions_before: INSTRUCTIONS_BEFORE.load(Ordering::Relaxed),
        instructions_after: INSTRUCTIONS_AFTER.load(Ordering::Relaxed),
        sccp_eliminated: SCCP_ELIMINATED.load(Ordering::Relaxed),
        gvn_eliminated: GVN_ELIMINATED.load(Ordering::Relaxed),
        dce_eliminated: DCE_ELIMINATED.load(Ordering::Relaxed),
        licm_hoisted: LICM_HOISTED.load(Ordering::Relaxed),
        load_forwarded: LOAD_FORWARDED.load(Ordering::Relaxed),
        store_eliminated: STORE_ELIMINATED.load(Ordering::Relaxed),
        register_spills: REGISTER_SPILLS.load(Ordering::Relaxed),
        fallback_reasons: FALLBACK_REASONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
    }
}

pub fn reset_tier2_metrics() {
    FUNCTIONS_COMPILED.store(0, Ordering::Relaxed);
    FUNCTIONS_FALLBACK.store(0, Ordering::Relaxed);
    BLOCKS.store(0, Ordering::Relaxed);
    SSA_VALUES.store(0, Ordering::Relaxed);
    INSTRUCTIONS_BEFORE.store(0, Ordering::Relaxed);
    INSTRUCTIONS_AFTER.store(0, Ordering::Relaxed);
    SCCP_ELIMINATED.store(0, Ordering::Relaxed);
    GVN_ELIMINATED.store(0, Ordering::Relaxed);
    DCE_ELIMINATED.store(0, Ordering::Relaxed);
    LICM_HOISTED.store(0, Ordering::Relaxed);
    LOAD_FORWARDED.store(0, Ordering::Relaxed);
    STORE_ELIMINATED.store(0, Ordering::Relaxed);
    REGISTER_SPILLS.store(0, Ordering::Relaxed);
    FALLBACK_REASONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

fn fallback(reason: &str) -> Fallback {
    FUNCTIONS_FALLBACK.fetch_add(1, Ordering::Relaxed);
    *FALLBACK_REASONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(reason.to_string())
        .or_insert(0) += 1;
    Fallback {
        reason: reason.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FunctionBlock {
    pub guest_address: u64,
    pub instructions: Vec<IrInstruction>,
}

impl FunctionBlock {
    pub fn new(guest_address: u64, instructions: Vec<IrInstruction>) -> Self {
        Self {
            guest_address,
            instructions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fallback {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OptimizedBlock {
    pub guest_address: u64,
    pub instructions: Vec<IrInstruction>,
    pub terminator: OptimizedTerminator,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OptimizedTerminator {
    Jump {
        target: u64,
        copies: Vec<IrInstruction>,
    },
    JumpIf {
        condition: ConditionCode,
        target: u64,
        fallthrough: u64,
        taken_copies: Vec<IrInstruction>,
        fallthrough_copies: Vec<IrInstruction>,
    },
    Return {
        stack_adjust: u64,
    },
    Exit,
}

#[derive(Debug, Clone)]
pub struct OptimizationResult {
    pub blocks: Vec<OptimizedBlock>,
    pub metrics: Tier2Metrics,
    pub original_instructions: usize,
}

pub fn optimize_function(
    blocks: &[FunctionBlock],
    arch: GuestArch,
) -> Result<OptimizationResult, Fallback> {
    optimize_function_inner(blocks, arch)
}

pub fn optimize_block_ir(
    ir: &[IrInstruction],
    arch: GuestArch,
) -> Result<Vec<IrInstruction>, Fallback> {
    let optimized = optimize_function(&[FunctionBlock::new(0, ir.to_vec())], arch)?;
    let Some(block) = optimized.blocks.into_iter().next() else {
        return Err(fallback("no lowered block"));
    };
    let mut out = block.instructions;
    match block.terminator {
        OptimizedTerminator::Jump { target, copies } => {
            out.extend(copies);
            out.push(IrInstruction::Jump { target });
        }
        OptimizedTerminator::JumpIf {
            condition,
            target,
            fallthrough,
            taken_copies,
            fallthrough_copies,
        } => {
            if !taken_copies.is_empty() || !fallthrough_copies.is_empty() {
                return Err(fallback("edge copies unsupported in single block"));
            }
            out.push(IrInstruction::JumpIf {
                condition,
                target,
                fallthrough,
            });
        }
        OptimizedTerminator::Return { stack_adjust } => {
            out.push(IrInstruction::Return { stack_adjust });
        }
        OptimizedTerminator::Exit => {}
    }
    Ok(out)
}

type ValueId = u32;
type BlockId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Operand {
    Value(ValueId),
    Imm(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BinOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UnOp {
    Neg,
    Not,
    Inc,
    Dec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FlagKind {
    Add,
    Sub,
    Logic,
    Cmp,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Address {
    base: Option<ValueId>,
    index: Option<ValueId>,
    scale: u8,
    displacement: i32,
    absolute_address: Option<u64>,
    segment: Option<SegmentRegister>,
}

#[derive(Debug, Clone, PartialEq)]
enum SsaOp {
    EntryVar(u8),
    Const(u64),
    Copy {
        src: ValueId,
        width: u8,
    },
    Binary {
        op: BinOp,
        lhs: Operand,
        rhs: Operand,
        width: u8,
    },
    Unary {
        op: UnOp,
        val: Operand,
        width: u8,
    },
    SetFlags {
        kind: FlagKind,
        lhs: Operand,
        rhs: Operand,
        result: Option<Operand>,
        width: u8,
    },
    Load {
        address: Address,
        width: u8,
    },
    Store {
        address: Address,
        value: Operand,
        width: u8,
    },
    Phi {
        var: u8,
        incoming: Vec<(BlockId, ValueId)>,
    },
}

#[derive(Debug, Clone)]
struct SsaInst {
    op: SsaOp,
    defs: Vec<(u8, ValueId)>,
    uses: Vec<ValueId>,
    removed: bool,
}

impl SsaInst {
    fn def_value(&self) -> Option<ValueId> {
        self.defs.first().map(|(_, value)| *value)
    }
    fn def_var(&self) -> Option<u8> {
        self.defs.first().map(|(var, _)| *var)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Term {
    Jump {
        target: u64,
    },
    JumpIf {
        condition: ConditionCode,
        target: u64,
        fallthrough: u64,
    },
    Return {
        stack_adjust: u64,
    },
    Exit,
}

#[derive(Debug, Clone)]
struct RawBlock {
    guest_address: u64,
    body: Vec<IrInstruction>,
    term: Term,
    succs: Vec<BlockId>,
}

#[derive(Debug, Clone)]
struct SsaBlock {
    guest_address: u64,
    phis: Vec<SsaInst>,
    insts: Vec<SsaInst>,
    term: Term,
    term_flags: Option<ValueId>,
    preds: Vec<BlockId>,
    succs: Vec<BlockId>,
}

fn width_mask(width: u8) -> u64 {
    match width {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

fn is_supported(insn: &IrInstruction) -> bool {
    matches!(
        insn,
        IrInstruction::Nop
            | IrInstruction::MovImm { .. }
            | IrInstruction::MovReg { .. }
            | IrInstruction::AddImm { .. }
            | IrInstruction::SubImm { .. }
            | IrInstruction::AndImm { .. }
            | IrInstruction::OrImm { .. }
            | IrInstruction::XorImm { .. }
            | IrInstruction::ShlImm { .. }
            | IrInstruction::ShrImm { .. }
            | IrInstruction::SarImm { .. }
            | IrInstruction::IncReg { .. }
            | IrInstruction::DecReg { .. }
            | IrInstruction::NegReg { .. }
            | IrInstruction::NotReg { .. }
            | IrInstruction::AddOperand { .. }
            | IrInstruction::SubOperand { .. }
            | IrInstruction::AndReg { .. }
            | IrInstruction::OrReg { .. }
            | IrInstruction::XorReg { .. }
            | IrInstruction::Compare { .. }
            | IrInstruction::Test { .. }
            | IrInstruction::LoadMemory { .. }
            | IrInstruction::StoreMemory { .. }
            | IrInstruction::StoreImmediate { .. }
    )
}

fn term_of(insn: &IrInstruction) -> Option<Term> {
    Some(match insn {
        IrInstruction::Jump { target } => Term::Jump { target: *target },
        IrInstruction::JumpIf {
            condition,
            target,
            fallthrough,
        } => Term::JumpIf {
            condition: *condition,
            target: *target,
            fallthrough: *fallthrough,
        },
        IrInstruction::Return { stack_adjust } => Term::Return {
            stack_adjust: *stack_adjust,
        },
        _ => return None,
    })
}

fn reads_flags(insn: &IrInstruction) -> bool {
    matches!(
        insn,
        IrInstruction::JumpIf { .. }
            | IrInstruction::Setcc { .. }
            | IrInstruction::SetccMemory { .. }
            | IrInstruction::Cmov { .. }
            | IrInstruction::AdcImm { .. }
            | IrInstruction::AdcOperand { .. }
            | IrInstruction::AdcImm8 { .. }
            | IrInstruction::AdcReg8Op { .. }
            | IrInstruction::SbbImm { .. }
            | IrInstruction::SbbOperand { .. }
            | IrInstruction::SbbImm8 { .. }
            | IrInstruction::SbbReg8 { .. }
            | IrInstruction::RclImm { .. }
            | IrInstruction::RcrImm { .. }
            | IrInstruction::RclCl { .. }
            | IrInstruction::RcrCl { .. }
            | IrInstruction::PushFlags { .. }
            | IrInstruction::Lahf
    )
}

fn writes_flags(insn: &IrInstruction) -> bool {
    matches!(
        insn,
        IrInstruction::AddImm { .. }
            | IrInstruction::SubImm { .. }
            | IrInstruction::AndImm { .. }
            | IrInstruction::OrImm { .. }
            | IrInstruction::XorImm { .. }
            | IrInstruction::AddOperand { .. }
            | IrInstruction::SubOperand { .. }
            | IrInstruction::AndReg { .. }
            | IrInstruction::OrReg { .. }
            | IrInstruction::XorReg { .. }
            | IrInstruction::IncReg { .. }
            | IrInstruction::DecReg { .. }
            | IrInstruction::NegReg { .. }
            | IrInstruction::ShlImm { .. }
            | IrInstruction::ShrImm { .. }
            | IrInstruction::SarImm { .. }
            | IrInstruction::Compare { .. }
            | IrInstruction::Test { .. }
    )
}

fn exact_flag_producer(insn: &IrInstruction) -> bool {
    matches!(
        insn,
        IrInstruction::AddImm { .. }
            | IrInstruction::SubImm { .. }
            | IrInstruction::AndImm { .. }
            | IrInstruction::OrImm { .. }
            | IrInstruction::XorImm { .. }
            | IrInstruction::AddOperand { .. }
            | IrInstruction::SubOperand { .. }
            | IrInstruction::AndReg { .. }
            | IrInstruction::OrReg { .. }
            | IrInstruction::XorReg { .. }
            | IrInstruction::NegReg { .. }
            | IrInstruction::Compare { .. }
            | IrInstruction::Test { .. }
    )
}

fn compare_operand_ssa(
    operand: &CompareOperand,
    read: &impl Fn(usize) -> ValueId,
) -> Option<Operand> {
    match operand {
        CompareOperand::Register(reg) => Some(Operand::Value(read(reg.index()))),
        CompareOperand::ImmediateU64(value) => Some(Operand::Imm(*value)),
        _ => None,
    }
}

fn memory_address(operand: &MemoryOperand, read: &impl Fn(usize) -> ValueId) -> Option<Address> {
    if operand.rip_relative {
        return None;
    }
    Some(Address {
        base: operand.base.map(|reg| read(reg.index())),
        index: operand.index.map(|reg| read(reg.index())),
        scale: operand.scale,
        displacement: operand.displacement,
        absolute_address: operand.absolute_address,
        segment: operand.segment,
    })
}

fn build_cfg(blocks: &[FunctionBlock]) -> Result<(Vec<RawBlock>, HashMap<u64, BlockId>), Fallback> {
    if blocks.is_empty() {
        return Err(fallback("no blocks"));
    }
    let mut addresses = HashMap::new();
    for (index, block) in blocks.iter().enumerate() {
        if addresses.insert(block.guest_address, index).is_some() {
            return Err(fallback("duplicate block address"));
        }
        if block.instructions.is_empty() {
            return Err(fallback("empty block"));
        }
    }
    let mut raw = Vec::with_capacity(blocks.len());
    for block in blocks {
        let mut body = Vec::new();
        let mut term = Term::Exit;
        let last = block.instructions.len() - 1;
        for (index, insn) in block.instructions.iter().enumerate() {
            if let Some(parsed) = term_of(insn) {
                if index != last {
                    return Err(fallback("control flow inside block"));
                }
                term = parsed;
                continue;
            }
            if matches!(
                insn,
                IrInstruction::Call { .. }
                    | IrInstruction::CallRegister { .. }
                    | IrInstruction::CallMemory { .. }
                    | IrInstruction::JumpRegister { .. }
                    | IrInstruction::JumpMemory { .. }
            ) {
                return Err(fallback("call or indirect control flow"));
            }
            if let IrInstruction::LoadMemory { address, .. }
            | IrInstruction::StoreMemory { address, .. }
            | IrInstruction::StoreImmediate { address, .. } = insn
                && address.rip_relative
            {
                return Err(fallback("rip-relative memory"));
            }
            if let IrInstruction::MovReg { width, .. } = insn
                && *width != 4
                && *width != 8
            {
                return Err(fallback("unsupported move width"));
            }
            if let IrInstruction::LoadMemory { width, .. } = insn
                && !matches!(*width, 4 | 8)
            {
                return Err(fallback("unsupported load width"));
            }
            if let IrInstruction::StoreMemory { width, .. } = insn
                && !matches!(*width, 1 | 2 | 4 | 8)
            {
                return Err(fallback("unsupported store width"));
            }
            if let IrInstruction::AddOperand { src, .. }
            | IrInstruction::SubOperand { src, .. }
            | IrInstruction::AndReg { src, .. }
            | IrInstruction::OrReg { src, .. }
            | IrInstruction::XorReg { src, .. }
            | IrInstruction::Compare { rhs: src, .. }
            | IrInstruction::Test { rhs: src, .. } = insn
                && matches!(src, CompareOperand::Memory(_))
            {
                return Err(fallback("memory-source ALU"));
            }
            if let IrInstruction::Compare { lhs, .. } | IrInstruction::Test { lhs, .. } = insn
                && matches!(lhs, CompareOperand::Memory(_))
            {
                return Err(fallback("memory-source ALU"));
            }
            if !is_supported(insn) {
                return Err(fallback(&format!("unsupported opcode: {insn:?}")));
            }
            body.push(insn.clone());
        }
        raw.push(RawBlock {
            guest_address: block.guest_address,
            body,
            term,
            succs: Vec::new(),
        });
    }
    for block in &mut raw {
        let mut succs = Vec::new();
        match &block.term {
            Term::Jump { target } => {
                if let Some(index) = addresses.get(target) {
                    succs.push(*index);
                }
            }
            Term::JumpIf {
                target,
                fallthrough,
                ..
            } => {
                if let Some(index) = addresses.get(target) {
                    succs.push(*index);
                }
                if let Some(index) = addresses.get(fallthrough)
                    && !succs.contains(index)
                {
                    succs.push(*index);
                }
            }
            Term::Return { .. } | Term::Exit => {}
        }
        block.succs = succs;
    }
    let mut reachable = vec![false; raw.len()];
    let mut queue = VecDeque::from([0usize]);
    reachable[0] = true;
    while let Some(block) = queue.pop_front() {
        for succ in &raw[block].succs {
            if !reachable[*succ] {
                reachable[*succ] = true;
                queue.push_back(*succ);
            }
        }
    }
    if reachable.iter().any(|value| !value) {
        return Err(fallback("unreachable block"));
    }
    Ok((raw, addresses))
}

fn compute_dominators(raw: &[RawBlock]) -> (Vec<HashSet<BlockId>>, Vec<BlockId>) {
    let count = raw.len();
    let mut preds = vec![Vec::new(); count];
    for (index, block) in raw.iter().enumerate() {
        for succ in &block.succs {
            preds[*succ].push(index);
        }
    }
    let all: HashSet<BlockId> = (0..count).collect();
    let mut dom = vec![all; count];
    dom[0] = HashSet::from([0usize]);
    loop {
        let mut changed = false;
        for block in 1..count {
            let mut next: Option<HashSet<BlockId>> = None;
            for pred in &preds[block] {
                next = Some(match next {
                    None => dom[*pred].clone(),
                    Some(current) => current.intersection(&dom[*pred]).copied().collect(),
                });
            }
            let mut next = next.unwrap_or_default();
            next.insert(block);
            if next != dom[block] {
                dom[block] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut idom = vec![0usize; count];
    for block in 1..count {
        idom[block] = dom[block]
            .iter()
            .copied()
            .filter(|candidate| *candidate != block)
            .max_by_key(|candidate| dom[*candidate].len())
            .unwrap_or(0);
    }
    (dom, idom)
}

fn dominance_frontiers(raw: &[RawBlock], idom: &[BlockId]) -> Vec<HashSet<BlockId>> {
    let mut frontiers = vec![HashSet::new(); raw.len()];
    for (block, data) in raw.iter().enumerate() {
        if data.succs.len() < 2 {
            continue;
        }
        for succ in &data.succs {
            let mut runner = *succ;
            while runner != idom[block] && runner != block {
                frontiers[runner].insert(block);
                let next = idom[runner];
                if next == runner {
                    break;
                }
                runner = next;
            }
            if runner == block {
                frontiers[block].insert(block);
            }
        }
    }
    frontiers
}

fn block_flag_liveness(raw: &[RawBlock]) -> (Vec<bool>, Vec<bool>) {
    let count = raw.len();
    let mut uses = vec![false; count];
    let mut defs = vec![false; count];
    for (index, block) in raw.iter().enumerate() {
        let mut defined = false;
        for insn in &block.body {
            if reads_flags(insn) && !defined {
                uses[index] = true;
            }
            if writes_flags(insn) {
                defined = true;
                defs[index] = true;
            }
        }
    }
    let mut live_in = vec![false; count];
    let mut live_out = vec![false; count];
    loop {
        let mut changed = false;
        for block in (0..count).rev() {
            let out = raw[block].succs.iter().any(|succ| live_in[*succ]);
            let new_in = uses[block] || (out && !defs[block]);
            if live_out[block] != out {
                live_out[block] = out;
                changed = true;
            }
            if live_in[block] != new_in {
                live_in[block] = new_in;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    (live_in, live_out)
}

fn validate_flag_producers(raw: &[RawBlock], live_out: &[bool]) -> Result<(), Fallback> {
    for (index, block) in raw.iter().enumerate() {
        let mut live = live_out[index];
        for insn in block.body.iter().rev() {
            if live
                && !exact_flag_producer(insn)
                && matches!(
                    insn,
                    IrInstruction::IncReg { .. }
                        | IrInstruction::DecReg { .. }
                        | IrInstruction::ShlImm { .. }
                        | IrInstruction::ShrImm { .. }
                        | IrInstruction::SarImm { .. }
                )
            {
                return Err(fallback("flags live across unsupported producer"));
            }
            if reads_flags(insn) {
                live = true;
            }
            if writes_flags(insn) {
                live = false;
            }
        }
    }
    Ok(())
}

fn instruction_dst(insn: &IrInstruction) -> Option<Register> {
    match insn {
        IrInstruction::MovImm { dst, .. }
        | IrInstruction::MovReg { dst, .. }
        | IrInstruction::AddImm { dst, .. }
        | IrInstruction::SubImm { dst, .. }
        | IrInstruction::AndImm { dst, .. }
        | IrInstruction::OrImm { dst, .. }
        | IrInstruction::XorImm { dst, .. }
        | IrInstruction::ShlImm { dst, .. }
        | IrInstruction::ShrImm { dst, .. }
        | IrInstruction::SarImm { dst, .. }
        | IrInstruction::IncReg { dst, .. }
        | IrInstruction::DecReg { dst, .. }
        | IrInstruction::NegReg { dst, .. }
        | IrInstruction::NotReg { dst, .. }
        | IrInstruction::AddOperand { dst, .. }
        | IrInstruction::SubOperand { dst, .. }
        | IrInstruction::AndReg { dst, .. }
        | IrInstruction::OrReg { dst, .. }
        | IrInstruction::XorReg { dst, .. }
        | IrInstruction::LoadMemory { dst, .. } => Some(*dst),
        _ => None,
    }
}

fn instruction_def_vars(insn: &IrInstruction) -> Vec<u8> {
    let mut defs = Vec::new();
    if let Some(dst) = instruction_dst(insn) {
        defs.push(dst.index() as u8);
    }
    if writes_flags(insn) {
        defs.push(FLAGS_VAR);
    }
    defs
}

struct Builder {
    blocks: Vec<SsaBlock>,
    next_value: ValueId,
}

impl Builder {
    fn value(&mut self) -> ValueId {
        let value = self.next_value;
        self.next_value += 1;
        value
    }
    fn inst(&mut self, op: SsaOp, defs: Vec<(u8, ValueId)>) -> SsaInst {
        let mut uses = Vec::new();
        operand_values(&op, &mut uses);
        SsaInst {
            op,
            defs,
            uses,
            removed: false,
        }
    }
}

fn build_ssa(raw: Vec<RawBlock>) -> Result<(Vec<SsaBlock>, ValueId), Fallback> {
    let count = raw.len();
    let (_dom, idom) = compute_dominators(&raw);
    let frontiers = dominance_frontiers(&raw, &idom);
    let mut preds = vec![Vec::new(); count];
    for (index, block) in raw.iter().enumerate() {
        for succ in &block.succs {
            preds[*succ].push(index);
        }
    }
    let mut builder = Builder {
        blocks: raw
            .iter()
            .map(|block| SsaBlock {
                guest_address: block.guest_address,
                phis: Vec::new(),
                insts: Vec::new(),
                term: block.term.clone(),
                term_flags: None,
                preds: Vec::new(),
                succs: block.succs.clone(),
            })
            .collect(),
        next_value: 0,
    };
    for index in 0..count {
        builder.blocks[index].preds = preds[index].clone();
    }

    let mut def_blocks: [Vec<BlockId>; VAR_COUNT] = std::array::from_fn(|_| Vec::new());
    for (index, block) in raw.iter().enumerate() {
        let mut defined = [false; VAR_COUNT];
        for insn in &block.body {
            for var in instruction_def_vars(insn) {
                if !defined[var as usize] {
                    defined[var as usize] = true;
                    def_blocks[var as usize].push(index);
                }
            }
        }
    }
    for var in 0..VAR_COUNT {
        let mut worklist: VecDeque<BlockId> = def_blocks[var].iter().copied().collect();
        let mut has_phi = vec![false; count];
        let mut queued: HashSet<BlockId> = worklist.iter().copied().collect();
        while let Some(block) = worklist.pop_front() {
            queued.remove(&block);
            for frontier in frontiers[block].iter().copied().collect::<Vec<_>>() {
                if has_phi[frontier] {
                    continue;
                }
                has_phi[frontier] = true;
                let value = builder.value();
                let phi = builder.inst(
                    SsaOp::Phi {
                        var: var as u8,
                        incoming: Vec::new(),
                    },
                    vec![(var as u8, value)],
                );
                builder.blocks[frontier].phis.push(phi);
                if !def_blocks[var].contains(&frontier) && queued.insert(frontier) {
                    worklist.push_back(frontier);
                }
            }
        }
    }

    let mut current = Vec::with_capacity(VAR_COUNT);
    for var in 0..VAR_COUNT {
        let value = builder.value();
        let entry = builder.inst(SsaOp::EntryVar(var as u8), vec![(var as u8, value)]);
        builder.blocks[0].insts.push(entry);
        current.push(value);
    }

    let mut children = vec![Vec::new(); count];
    for block in 1..count {
        children[idom[block]].push(block);
    }
    rename(&mut builder, &raw, 0, &mut current, &children);

    for block in &builder.blocks {
        for phi in &block.phis {
            if let SsaOp::Phi { incoming, .. } = &phi.op
                && incoming.is_empty()
                && !block.preds.is_empty()
            {
                return Err(fallback("phi without incoming value"));
            }
        }
    }
    Ok((builder.blocks, builder.next_value))
}

fn rename(
    builder: &mut Builder,
    raw: &[RawBlock],
    block: BlockId,
    current: &mut [ValueId],
    children: &[Vec<BlockId>],
) {
    let phis = builder.blocks[block].phis.clone();
    for phi in &phis {
        if let Some((var, value)) = phi.defs.first() {
            current[*var as usize] = *value;
        }
    }
    for insn in &raw[block].body {
        let mut produced = lower_instruction(insn, builder, current);
        for item in produced.iter_mut() {
            for (var, value) in &item.defs {
                current[*var as usize] = *value;
            }
        }
        builder.blocks[block].insts.append(&mut produced);
    }
    if let Term::JumpIf { .. } = builder.blocks[block].term {
        builder.blocks[block].term_flags = Some(current[FLAGS_VAR as usize]);
    }
    let succs = builder.blocks[block].succs.clone();
    for succ in succs {
        let phis = builder.blocks[succ].phis.clone();
        for (index, phi) in phis.iter().enumerate() {
            if let SsaOp::Phi { var, .. } = &phi.op {
                let value = current[*var as usize];
                if let SsaOp::Phi { incoming, .. } = &mut builder.blocks[succ].phis[index].op {
                    incoming.push((block, value));
                }
            }
        }
    }
    for child in &children[block] {
        let mut child_values = current.to_vec();
        rename(builder, raw, *child, &mut child_values, children);
    }
}

fn lower_instruction(
    insn: &IrInstruction,
    builder: &mut Builder,
    current: &[ValueId],
) -> Vec<SsaInst> {
    let read = |index: usize| current[index];
    let mut out = Vec::new();
    let dst = instruction_dst(insn);
    let define_gpr = |builder: &mut Builder| {
        dst.map(|reg| {
            let value = builder.value();
            (reg.index() as u8, value)
        })
    };

    match insn {
        IrInstruction::Nop => {}
        IrInstruction::MovImm { value, .. } => {
            if let Some((var, result)) = define_gpr(builder) {
                out.push(builder.inst(SsaOp::Const(*value), vec![(var, result)]));
            }
        }
        IrInstruction::MovReg { src, width, .. } => {
            if let Some((var, result)) = define_gpr(builder) {
                out.push(builder.inst(
                    SsaOp::Copy {
                        src: read(src.index()),
                        width: (*width).min(8) as u8,
                    },
                    vec![(var, result)],
                ));
            }
        }
        IrInstruction::AddImm { value, width, .. }
        | IrInstruction::SubImm { value, width, .. }
        | IrInstruction::AndImm { value, width, .. }
        | IrInstruction::OrImm { value, width, .. }
        | IrInstruction::XorImm { value, width, .. } => {
            let dst = dst.expect("binary instruction has destination");
            let op = match insn {
                IrInstruction::AddImm { .. } => BinOp::Add,
                IrInstruction::SubImm { .. } => BinOp::Sub,
                IrInstruction::AndImm { .. } => BinOp::And,
                IrInstruction::OrImm { .. } => BinOp::Or,
                _ => BinOp::Xor,
            };
            let result = builder.value();
            let lhs = Operand::Value(read(dst.index()));
            let rhs = Operand::Imm(*value);
            out.push(builder.inst(
                SsaOp::Binary {
                    op,
                    lhs,
                    rhs,
                    width: (*width).min(8) as u8,
                },
                vec![(dst.index() as u8, result)],
            ));
            let flags = builder.value();
            let kind = match op {
                BinOp::Add => FlagKind::Add,
                BinOp::Sub => FlagKind::Sub,
                _ => FlagKind::Logic,
            };
            out.push(builder.inst(
                SsaOp::SetFlags {
                    kind,
                    lhs,
                    rhs,
                    result: Some(Operand::Value(result)),
                    width: (*width).min(8) as u8,
                },
                vec![(FLAGS_VAR, flags)],
            ));
        }
        IrInstruction::ShlImm { count, width, .. }
        | IrInstruction::ShrImm { count, width, .. }
        | IrInstruction::SarImm { count, width, .. } => {
            let dst = dst.expect("shift has destination");
            let op = match insn {
                IrInstruction::ShlImm { .. } => BinOp::Shl,
                IrInstruction::ShrImm { .. } => BinOp::Shr,
                _ => BinOp::Sar,
            };
            let result = builder.value();
            out.push(builder.inst(
                SsaOp::Binary {
                    op,
                    lhs: Operand::Value(read(dst.index())),
                    rhs: Operand::Imm(u64::from(*count)),
                    width: (*width).min(8) as u8,
                },
                vec![(dst.index() as u8, result)],
            ));
        }
        IrInstruction::AddOperand { dst, src, width }
        | IrInstruction::SubOperand { dst, src, width }
        | IrInstruction::AndReg { dst, src, width }
        | IrInstruction::OrReg { dst, src, width }
        | IrInstruction::XorReg { dst, src, width } => {
            let op = match insn {
                IrInstruction::AddOperand { .. } => BinOp::Add,
                IrInstruction::SubOperand { .. } => BinOp::Sub,
                IrInstruction::AndReg { .. } => BinOp::And,
                IrInstruction::OrReg { .. } => BinOp::Or,
                _ => BinOp::Xor,
            };
            let Some(rhs) = compare_operand_ssa(src, &read) else {
                return out;
            };
            let result = builder.value();
            let lhs = Operand::Value(read(dst.index()));
            out.push(builder.inst(
                SsaOp::Binary {
                    op,
                    lhs,
                    rhs,
                    width: (*width).min(8) as u8,
                },
                vec![(dst.index() as u8, result)],
            ));
            let kind = match op {
                BinOp::Add => FlagKind::Add,
                BinOp::Sub => FlagKind::Sub,
                _ => FlagKind::Logic,
            };
            let flags = builder.value();
            out.push(builder.inst(
                SsaOp::SetFlags {
                    kind,
                    lhs,
                    rhs,
                    result: Some(Operand::Value(result)),
                    width: (*width).min(8) as u8,
                },
                vec![(FLAGS_VAR, flags)],
            ));
        }
        IrInstruction::IncReg { dst, width } | IrInstruction::DecReg { dst, width } => {
            let result = builder.value();
            out.push(builder.inst(
                SsaOp::Unary {
                    op: if matches!(insn, IrInstruction::IncReg { .. }) {
                        UnOp::Inc
                    } else {
                        UnOp::Dec
                    },
                    val: Operand::Value(read(dst.index())),
                    width: (*width).min(8) as u8,
                },
                vec![(dst.index() as u8, result)],
            ));
        }
        IrInstruction::NegReg { dst, width } => {
            let result = builder.value();
            out.push(builder.inst(
                SsaOp::Unary {
                    op: UnOp::Neg,
                    val: Operand::Value(read(dst.index())),
                    width: (*width).min(8) as u8,
                },
                vec![(dst.index() as u8, result)],
            ));
            let flags = builder.value();
            out.push(builder.inst(
                SsaOp::SetFlags {
                    kind: FlagKind::Sub,
                    lhs: Operand::Imm(0),
                    rhs: Operand::Value(result),
                    result: Some(Operand::Value(result)),
                    width: (*width).min(8) as u8,
                },
                vec![(FLAGS_VAR, flags)],
            ));
        }
        IrInstruction::NotReg { dst, width } => {
            let result = builder.value();
            out.push(builder.inst(
                SsaOp::Unary {
                    op: UnOp::Not,
                    val: Operand::Value(read(dst.index())),
                    width: (*width).min(8) as u8,
                },
                vec![(dst.index() as u8, result)],
            ));
        }
        IrInstruction::Compare { lhs, rhs, width } | IrInstruction::Test { lhs, rhs, width } => {
            let Some(lhs) = compare_operand_ssa(lhs, &read) else {
                return out;
            };
            let Some(rhs) = compare_operand_ssa(rhs, &read) else {
                return out;
            };
            let flags = builder.value();
            out.push(builder.inst(
                SsaOp::SetFlags {
                    kind: if matches!(insn, IrInstruction::Compare { .. }) {
                        FlagKind::Cmp
                    } else {
                        FlagKind::Test
                    },
                    lhs,
                    rhs,
                    result: None,
                    width: (*width).min(8) as u8,
                },
                vec![(FLAGS_VAR, flags)],
            ));
        }
        IrInstruction::LoadMemory {
            dst,
            address,
            width,
        } => {
            let Some(address) = memory_address(address, &read) else {
                return out;
            };
            let result = builder.value();
            out.push(builder.inst(
                SsaOp::Load {
                    address,
                    width: (*width).min(8) as u8,
                },
                vec![(dst.index() as u8, result)],
            ));
        }
        IrInstruction::StoreMemory {
            src,
            address,
            width,
        } => {
            let Some(address) = memory_address(address, &read) else {
                return out;
            };
            out.push(builder.inst(
                SsaOp::Store {
                    address,
                    value: Operand::Value(read(src.index())),
                    width: (*width).min(8) as u8,
                },
                Vec::new(),
            ));
        }
        IrInstruction::StoreImmediate {
            address,
            value,
            width,
        } => {
            let Some(address) = memory_address(address, &read) else {
                return out;
            };
            out.push(builder.inst(
                SsaOp::Store {
                    address,
                    value: Operand::Imm(*value),
                    width: (*width).min(8) as u8,
                },
                Vec::new(),
            ));
        }
        _ => {}
    }
    out
}

fn all_insts(block: &SsaBlock) -> impl Iterator<Item = &SsaInst> {
    block.phis.iter().chain(block.insts.iter())
}

fn all_insts_mut(block: &mut SsaBlock) -> impl Iterator<Item = &mut SsaInst> {
    block.phis.iter_mut().chain(block.insts.iter_mut())
}

fn operand_values(op: &SsaOp, out: &mut Vec<ValueId>) {
    match op {
        SsaOp::EntryVar(_) | SsaOp::Const(_) | SsaOp::Phi { .. } => {}
        SsaOp::Copy { src, .. } => out.push(*src),
        SsaOp::Binary { lhs, rhs, .. } => {
            if let Operand::Value(value) = lhs {
                out.push(*value);
            }
            if let Operand::Value(value) = rhs {
                out.push(*value);
            }
        }
        SsaOp::Unary { val, .. } => {
            if let Operand::Value(value) = val {
                out.push(*value);
            }
        }
        SsaOp::SetFlags {
            lhs, rhs, result, ..
        } => {
            if let Operand::Value(value) = lhs {
                out.push(*value);
            }
            if let Operand::Value(value) = rhs {
                out.push(*value);
            }
            if let Some(Operand::Value(value)) = result {
                out.push(*value);
            }
        }
        SsaOp::Load { address, .. } => {
            if let Some(value) = address.base {
                out.push(value);
            }
            if let Some(value) = address.index {
                out.push(value);
            }
        }
        SsaOp::Store { address, value, .. } => {
            if let Some(value) = address.base {
                out.push(value);
            }
            if let Some(value) = address.index {
                out.push(value);
            }
            if let Operand::Value(value) = value {
                out.push(*value);
            }
        }
    }
}

fn replace_uses(blocks: &mut [SsaBlock], replacements: &HashMap<ValueId, Operand>) {
    for block in blocks {
        for inst in all_insts_mut(block) {
            replace_in_op(&mut inst.op, replacements);
            inst.uses.clear();
            operand_values(&inst.op, &mut inst.uses);
        }
    }
}

fn replace_in_op(op: &mut SsaOp, replacements: &HashMap<ValueId, Operand>) {
    let replace = |operand: &mut Operand| {
        if let Operand::Value(value) = operand
            && let Some(next) = replacements.get(value)
        {
            *operand = *next;
        }
    };
    let replace_value = |value: &mut ValueId| {
        if let Some(Operand::Value(next)) = replacements.get(value) {
            *value = *next;
        }
    };
    match op {
        SsaOp::EntryVar(_) | SsaOp::Const(_) => {}
        SsaOp::Copy { src, .. } => replace_value(src),
        SsaOp::Binary { lhs, rhs, .. } => {
            replace(lhs);
            replace(rhs);
        }
        SsaOp::Unary { val, .. } => replace(val),
        SsaOp::SetFlags {
            lhs, rhs, result, ..
        } => {
            replace(lhs);
            replace(rhs);
            if let Some(result) = result {
                replace(result);
            }
        }
        SsaOp::Load { address, .. } => {
            if let Some(base) = address.base {
                if let Some(Operand::Value(next)) = replacements.get(&base) {
                    address.base = Some(*next);
                }
            }
            if let Some(index) = address.index {
                if let Some(Operand::Value(next)) = replacements.get(&index) {
                    address.index = Some(*next);
                }
            }
        }
        SsaOp::Store { address, value, .. } => {
            if let Some(base) = address.base {
                if let Some(Operand::Value(next)) = replacements.get(&base) {
                    address.base = Some(*next);
                }
            }
            if let Some(index) = address.index {
                if let Some(Operand::Value(next)) = replacements.get(&index) {
                    address.index = Some(*next);
                }
            }
            replace(value);
        }
        SsaOp::Phi { incoming, .. } => {
            for (_, value) in incoming {
                if let Some(Operand::Value(next)) = replacements.get(value) {
                    *value = *next;
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lattice {
    Undefined,
    Const(u64),
    Over,
}

fn lattice_join(current: Lattice, next: Lattice) -> Lattice {
    match (current, next) {
        (Lattice::Over, _) | (_, Lattice::Over) => Lattice::Over,
        (Lattice::Undefined, value) => value,
        (value, Lattice::Undefined) => value,
        (Lattice::Const(a), Lattice::Const(b)) if a == b => Lattice::Const(a),
        _ => Lattice::Over,
    }
}

fn operand_lattice(operand: Operand, values: &HashMap<ValueId, Lattice>) -> Lattice {
    match operand {
        Operand::Imm(value) => Lattice::Const(value),
        Operand::Value(value) => values.get(&value).copied().unwrap_or(Lattice::Undefined),
    }
}

fn eval_binary(op: BinOp, lhs: u64, rhs: u64, width: u8) -> u64 {
    let mask = width_mask(width);
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    match op {
        BinOp::Add => lhs.wrapping_add(rhs) & mask,
        BinOp::Sub => lhs.wrapping_sub(rhs) & mask,
        BinOp::And => (lhs & rhs) & mask,
        BinOp::Or => (lhs | rhs) & mask,
        BinOp::Xor => (lhs ^ rhs) & mask,
        BinOp::Shl => lhs.wrapping_shl((rhs & 0x3f) as u32) & mask,
        BinOp::Shr => lhs.wrapping_shr((rhs & 0x3f) as u32) & mask,
        BinOp::Sar => {
            let sign_bit = 1u64 << (width as u32 * 8 - 1);
            let extended = if lhs & sign_bit != 0 {
                lhs | !mask
            } else {
                lhs
            };
            ((extended as i64) >> ((rhs & 0x3f) as u32)) as u64 & mask
        }
    }
}

fn eval_condition(
    kind: FlagKind,
    lhs: u64,
    rhs: u64,
    result: u64,
    width: u8,
    condition: ConditionCode,
) -> Option<bool> {
    let mask = width_mask(width);
    let bits = width as u32 * 8;
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    let result = result & mask;
    let cf = match kind {
        FlagKind::Cmp | FlagKind::Sub => lhs < rhs,
        FlagKind::Add => lhs.checked_add(rhs).map_or(true, |sum| sum > mask),
        FlagKind::Logic | FlagKind::Test => false,
    };
    let zf = result == 0;
    let sf = (result >> (bits - 1)) & 1 == 1;
    let of = match kind {
        FlagKind::Cmp | FlagKind::Sub => (((lhs ^ rhs) & (lhs ^ result)) >> (bits - 1)) & 1 == 1,
        FlagKind::Add => (((lhs ^ result) & (rhs ^ result)) >> (bits - 1)) & 1 == 1,
        FlagKind::Logic | FlagKind::Test => false,
    };
    Some(match condition {
        ConditionCode::Equal => zf,
        ConditionCode::NotEqual => !zf,
        ConditionCode::Overflow => of,
        ConditionCode::NotOverflow => !of,
        ConditionCode::Below => cf,
        ConditionCode::NotBelow => !cf,
        ConditionCode::Above => !cf && !zf,
        ConditionCode::NotAbove => cf || zf,
        ConditionCode::Sign => sf,
        ConditionCode::NotSign => !sf,
        ConditionCode::Less => sf != of,
        ConditionCode::GreaterEqual => sf == of,
        ConditionCode::LessEqual => zf || sf != of,
        ConditionCode::Greater => !zf && sf == of,
        ConditionCode::Parity => result.count_ones() % 2 == 0,
        ConditionCode::NotParity => result.count_ones() % 2 == 1,
    })
}

fn sccp(blocks: &mut [SsaBlock]) -> u64 {
    let mut values: HashMap<ValueId, Lattice> = HashMap::new();
    loop {
        let mut changed = false;
        for block in blocks.iter() {
            for inst in all_insts(block) {
                if inst.removed {
                    continue;
                }
                let outgoing = match &inst.op {
                    SsaOp::EntryVar(_) => Some(Lattice::Over),
                    SsaOp::Const(value) => Some(Lattice::Const(*value)),
                    SsaOp::Copy { src, .. } => {
                        Some(values.get(src).copied().unwrap_or(Lattice::Undefined))
                    }
                    SsaOp::Binary {
                        op,
                        lhs,
                        rhs,
                        width,
                    } => {
                        match (
                            operand_lattice(*lhs, &values),
                            operand_lattice(*rhs, &values),
                        ) {
                            (Lattice::Const(lhs), Lattice::Const(rhs)) => {
                                Some(Lattice::Const(eval_binary(*op, lhs, rhs, *width)))
                            }
                            (Lattice::Over, _) | (_, Lattice::Over) => Some(Lattice::Over),
                            _ => None,
                        }
                    }
                    SsaOp::Unary { op, val, width } => match operand_lattice(*val, &values) {
                        Lattice::Const(value) => Some(Lattice::Const(match op {
                            UnOp::Neg => 0u64.wrapping_sub(value) & width_mask(*width),
                            UnOp::Not => !value & width_mask(*width),
                            UnOp::Inc => value.wrapping_add(1) & width_mask(*width),
                            UnOp::Dec => value.wrapping_sub(1) & width_mask(*width),
                        })),
                        Lattice::Over => Some(Lattice::Over),
                        Lattice::Undefined => None,
                    },
                    SsaOp::SetFlags { .. } | SsaOp::Load { .. } | SsaOp::Store { .. } => {
                        Some(Lattice::Over)
                    }
                    SsaOp::Phi { incoming, .. } => {
                        let mut result = Lattice::Undefined;
                        for (_, value) in incoming {
                            result = lattice_join(
                                result,
                                values.get(value).copied().unwrap_or(Lattice::Undefined),
                            );
                        }
                        Some(result)
                    }
                };
                if let Some(outgoing) = outgoing
                    && let Some(value) = inst.def_value()
                {
                    let current = values.get(&value).copied().unwrap_or(Lattice::Undefined);
                    let joined = lattice_join(current, outgoing);
                    if joined != current {
                        values.insert(value, joined);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut replacements = HashMap::new();
    let mut eliminated = 0u64;
    for block in blocks.iter_mut() {
        for inst in all_insts_mut(block) {
            if inst.removed {
                continue;
            }
            let Some(value) = inst.def_value() else {
                continue;
            };
            let Some(Lattice::Const(constant)) = values.get(&value).copied() else {
                continue;
            };
            if matches!(
                inst.op,
                SsaOp::Load { .. }
                    | SsaOp::EntryVar(_)
                    | SsaOp::SetFlags { .. }
                    | SsaOp::Phi { .. }
            ) {
                continue;
            }
            // Keep the architectural destination definition, but make it a
            // literal.  Uses are folded to immediates below; DCE can then drop
            // the whole dead chain while the last value still reaches the
            // guest register.
            inst.op = SsaOp::Const(constant);
            inst.uses.clear();
            replacements.insert(value, Operand::Imm(constant));
            eliminated += 1;
        }
    }
    if !replacements.is_empty() {
        replace_uses(blocks, &replacements);
    }

    for block in blocks.iter_mut() {
        let Term::JumpIf {
            condition,
            target,
            fallthrough,
        } = block.term.clone()
        else {
            continue;
        };
        let Some(flags_value) = block.term_flags else {
            continue;
        };
        let definition = block.insts.iter().rev().find_map(|inst| {
            if inst.def_value() == Some(flags_value) {
                if let SsaOp::SetFlags {
                    kind,
                    lhs,
                    rhs,
                    result,
                    width,
                } = &inst.op
                {
                    return Some((*kind, *lhs, *rhs, *result, *width));
                }
            }
            None
        });
        let Some((kind, lhs, rhs, result, width)) = definition else {
            continue;
        };
        let lhs = operand_lattice(lhs, &values);
        let rhs = operand_lattice(rhs, &values);
        let result = result
            .map(|operand| operand_lattice(operand, &values))
            .unwrap_or(lhs);
        if let (Lattice::Const(lhs), Lattice::Const(rhs), Lattice::Const(result)) =
            (lhs, rhs, result)
            && let Some(taken) = eval_condition(kind, lhs, rhs, result, width, condition)
        {
            block.term = Term::Jump {
                target: if taken { target } else { fallthrough },
            };
            eliminated += 1;
        }
    }
    eliminated
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum GvnKey {
    Const(u64),
    Copy(ValueId),
    Binary(BinOp, Operand, Operand, u8),
    Unary(UnOp, Operand, u8),
    SetFlags(FlagKind, Operand, Operand, Option<Operand>, u8),
    Entry(u8),
}

fn gvn(blocks: &mut [SsaBlock]) -> u64 {
    let mut value_vars = HashMap::new();
    for block in blocks.iter() {
        for inst in all_insts(block) {
            for (var, value) in &inst.defs {
                value_vars.insert(*value, *var);
            }
        }
    }
    let mut replacements = HashMap::new();
    let mut eliminated = 0u64;
    for block in blocks.iter_mut() {
        let mut leaders: HashMap<GvnKey, ValueId> = HashMap::new();
        let mut current_def: HashMap<u8, ValueId> = HashMap::new();
        for inst in all_insts_mut(block) {
            if inst.removed {
                continue;
            }
            let Some(value) = inst.def_value() else {
                continue;
            };
            let identity = match &inst.op {
                SsaOp::Binary { op, lhs, rhs, .. } => match (op, lhs, rhs) {
                    (BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor, lhs, Operand::Imm(0)) => {
                        Some(Identity::Same(*lhs))
                    }
                    (BinOp::And, _, Operand::Imm(0)) => Some(Identity::Constant(0)),
                    (BinOp::Sub | BinOp::Xor, lhs, rhs) if lhs == rhs => {
                        Some(Identity::Constant(0))
                    }
                    _ => None,
                },
                _ => None,
            };
            if let Some(identity) = identity {
                match identity {
                    Identity::Same(lhs) => {
                        replacements.insert(value, lhs);
                        inst.removed = true;
                    }
                    Identity::Constant(constant) => {
                        // Keep the architectural definition: RBX must actually
                        // become zero at function exit.
                        inst.op = SsaOp::Const(constant);
                    }
                }
                inst.uses.clear();
                eliminated += 1;
                continue;
            }
            let key = match &inst.op {
                SsaOp::EntryVar(var) => Some(GvnKey::Entry(*var)),
                SsaOp::Const(constant) => Some(GvnKey::Const(*constant)),
                SsaOp::Copy { src, .. } => Some(GvnKey::Copy(*src)),
                SsaOp::Binary {
                    op,
                    lhs,
                    rhs,
                    width,
                } => Some(GvnKey::Binary(*op, *lhs, *rhs, *width)),
                SsaOp::Unary { op, val, width } => Some(GvnKey::Unary(*op, *val, *width)),
                SsaOp::SetFlags {
                    kind,
                    lhs,
                    rhs,
                    result,
                    width,
                } => Some(GvnKey::SetFlags(*kind, *lhs, *rhs, *result, *width)),
                SsaOp::Load { .. } | SsaOp::Store { .. } | SsaOp::Phi { .. } => None,
            };
            let Some(key) = key else {
                continue;
            };
            if let Some(existing) = leaders.get(&key).copied() {
                let existing_var = value_vars.get(&existing).copied();
                // The replacement is only valid if the leader's home still
                // holds that value at this point.
                let leader_is_current =
                    existing_var.and_then(|var| current_def.get(&var).copied()) == Some(existing);
                if leader_is_current {
                    let same_var = value_vars.get(&value) == value_vars.get(&existing);
                    if same_var {
                        replacements.insert(value, Operand::Value(existing));
                        inst.removed = true;
                    } else {
                        // Cross-register CSE must still write the destination.
                        inst.op = SsaOp::Copy {
                            src: existing,
                            width: 8,
                        };
                        inst.uses.clear();
                        inst.uses.push(existing);
                    }
                    eliminated += 1;
                } else {
                    // The register was overwritten since the leader was
                    // computed; this value is the new leader for the key.
                    leaders.insert(key, value);
                }
            } else {
                leaders.insert(key, value);
            }
            for (var, defined) in &inst.defs {
                current_def.insert(*var, *defined);
            }
        }
    }
    if !replacements.is_empty() {
        replace_uses(blocks, &replacements);
    }
    eliminated
}

enum Identity {
    Same(Operand),
    Constant(u64),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum StoreValue {
    Imm(u64),
    Value(ValueId),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct AddrKey {
    base: Option<ValueId>,
    index: Option<ValueId>,
    scale: u8,
    displacement: i32,
    absolute: Option<u64>,
}

fn address_key(address: &Address) -> AddrKey {
    AddrKey {
        base: address.base,
        index: address.index,
        scale: address.scale,
        displacement: address.displacement,
        absolute: address.absolute_address,
    }
}

fn load_store_forwarding(blocks: &mut [SsaBlock]) -> (u64, u64) {
    let mut forwarded = 0u64;
    let mut eliminated_stores = 0u64;
    for block in blocks.iter_mut() {
        let mut last_store: HashMap<AddrKey, (StoreValue, u8, usize)> = HashMap::new();
        let mut last_load: HashMap<AddrKey, (ValueId, u8)> = HashMap::new();
        let mut removed = Vec::new();
        for index in 0..block.insts.len() {
            if block.insts[index].removed {
                continue;
            }
            if let SsaOp::Load { address, width } = &block.insts[index].op {
                let key = address_key(address);
                let forwarded_value = if let Some((stored, stored_width, _)) = last_store.get(&key)
                    && *stored_width == *width
                {
                    Some(match stored {
                        StoreValue::Imm(value) => Operand::Imm(*value),
                        StoreValue::Value(value) => Operand::Value(*value),
                    })
                } else if let Some((value, loaded_width)) = last_load.get(&key)
                    && *loaded_width == *width
                {
                    Some(Operand::Value(*value))
                } else {
                    None
                };
                if let Some(replacement) = forwarded_value {
                    // Replace the memory read with a register/constant value,
                    // but keep the architectural destination definition: a
                    // load of [addr] into RBX must still leave RBX holding the
                    // loaded value at function exit.
                    block.insts[index].op = match replacement {
                        Operand::Imm(value) => SsaOp::Const(value),
                        Operand::Value(value) => SsaOp::Copy {
                            src: value,
                            width: *width,
                        },
                    };
                    let mut uses = Vec::new();
                    operand_values(&block.insts[index].op, &mut uses);
                    block.insts[index].uses = uses;
                    forwarded += 1;
                    continue;
                }
                if let Some(def) = block.insts[index].def_value() {
                    last_load.insert(key, (def, *width));
                }
            } else if let SsaOp::Store {
                address,
                value,
                width,
            } = &block.insts[index].op
            {
                let key = address_key(address);
                let stored = match value {
                    Operand::Imm(value) => StoreValue::Imm(*value),
                    Operand::Value(value) => StoreValue::Value(*value),
                };
                if let Some((previous, stored_width, _)) = last_store.get(&key)
                    && *stored_width == *width
                    && *previous == stored
                {
                    // The previous identical store already established the
                    // mapping (a fault would have happened there), so this
                    // duplicate store is unobservable.
                    removed.push(index);
                    eliminated_stores += 1;
                }
                if !last_store.is_empty() && !last_store.contains_key(&key) {
                    last_store.clear();
                    last_load.clear();
                }
                last_store.insert(key, (stored, *width, index));
                last_load.remove(&key);
            }
        }
        for index in removed {
            block.insts[index].removed = true;
        }
    }
    (forwarded, eliminated_stores)
}

fn dce(blocks: &mut [SsaBlock]) -> u64 {
    let count = blocks.len();
    if count == 0 {
        return 0;
    }
    let idom = idom_from_blocks(blocks);
    let mut order = Vec::with_capacity(count);
    let mut children = vec![Vec::new(); count];
    for block in 1..count {
        children[idom[block]].push(block);
    }
    let mut stack = vec![0usize];
    while let Some(block) = stack.pop() {
        order.push(block);
        for child in &children[block] {
            stack.push(*child);
        }
    }
    if order.len() != count {
        // Unreachable islands (should have been rejected earlier); include them
        // conservatively so their definitions are not silently dropped.
        for block in 0..count {
            if !order.contains(&block) {
                order.push(block);
            }
        }
    }

    // Value of every SSA variable at the end of each block.
    let mut end_values = vec![[None; VAR_COUNT]; count];
    for &block in &order {
        let mut values = if block == 0 {
            [None; VAR_COUNT]
        } else {
            end_values[idom[block]]
        };
        for phi in &blocks[block].phis {
            for (var, value) in &phi.defs {
                values[*var as usize] = Some(*value);
            }
        }
        for inst in &blocks[block].insts {
            for (var, value) in &inst.defs {
                values[*var as usize] = Some(*value);
            }
        }
        end_values[block] = values;
    }

    let mut block_use: Vec<HashSet<ValueId>> = vec![HashSet::new(); count];
    let mut block_def: Vec<HashSet<ValueId>> = vec![HashSet::new(); count];
    for (index, block) in blocks.iter().enumerate() {
        let mut defined = HashSet::new();
        for inst in &block.insts {
            for value in &inst.uses {
                if !defined.contains(value) {
                    block_use[index].insert(*value);
                }
            }
            for (_, value) in &inst.defs {
                defined.insert(*value);
                block_def[index].insert(*value);
            }
        }
        for phi in &block.phis {
            for (_, value) in &phi.defs {
                defined.insert(*value);
                block_def[index].insert(*value);
            }
        }
        if let Some(flags) = block.term_flags
            && !defined.contains(&flags)
        {
            block_use[index].insert(flags);
        }
    }

    // Values consumed by successor phi edges.
    let mut edge_uses: Vec<HashSet<ValueId>> = vec![HashSet::new(); count];
    for (index, block) in blocks.iter().enumerate() {
        for succ in &block.succs {
            for phi in &blocks[*succ].phis {
                if let SsaOp::Phi { incoming, .. } = &phi.op {
                    for (pred, value) in incoming {
                        if *pred == index {
                            edge_uses[index].insert(*value);
                        }
                    }
                }
            }
        }
    }

    let mut live_in: Vec<HashSet<ValueId>> = vec![HashSet::new(); count];
    let mut live_out: Vec<HashSet<ValueId>> = vec![HashSet::new(); count];
    loop {
        let mut changed = false;
        for block in (0..count).rev() {
            let mut out = HashSet::new();
            for succ in &blocks[block].succs {
                out.extend(live_in[*succ].iter().copied());
            }
            out.extend(edge_uses[block].iter().copied());
            if block_can_exit(&blocks[block]) {
                for value in end_values[block].iter().flatten() {
                    out.insert(*value);
                }
            }
            let mut inn = block_use[block].clone();
            for value in &out {
                if !block_def[block].contains(value) {
                    inn.insert(*value);
                }
            }
            if out != live_out[block] {
                live_out[block] = out;
                changed = true;
            }
            if inn != live_in[block] {
                live_in[block] = inn;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut live_values = HashSet::new();
    for block in 0..count {
        live_values.extend(live_in[block].iter().copied());
        live_values.extend(live_out[block].iter().copied());
        live_values.extend(block_use[block].iter().copied());
        live_values.extend(edge_uses[block].iter().copied());
    }

    // Side-effecting roots: stores and loads that survived forwarding.
    for block in blocks.iter() {
        for inst in &block.insts {
            if matches!(inst.op, SsaOp::Store { .. } | SsaOp::Load { .. }) {
                if let Some(value) = inst.def_value() {
                    live_values.insert(value);
                }
                for value in &inst.uses {
                    live_values.insert(*value);
                }
            }
        }
    }

    let mut defs = HashMap::new();
    for (block_index, block) in blocks.iter().enumerate() {
        for (index, inst) in block.phis.iter().enumerate() {
            if let Some(value) = inst.def_value() {
                defs.insert(value, (block_index, true, index));
            }
        }
        for (index, inst) in block.insts.iter().enumerate() {
            if let Some(value) = inst.def_value() {
                defs.insert(value, (block_index, false, index));
            }
        }
    }
    let mut marked = HashSet::new();
    let mut queue: VecDeque<ValueId> = live_values.into_iter().collect();
    while let Some(value) = queue.pop_front() {
        let Some((block_index, is_phi, index)) = defs.get(&value).copied() else {
            continue;
        };
        if !marked.insert((block_index, is_phi, index)) {
            continue;
        }
        let inst = if is_phi {
            &blocks[block_index].phis[index]
        } else {
            &blocks[block_index].insts[index]
        };
        for operand in &inst.uses {
            queue.push_back(*operand);
        }
    }

    let mut removed = 0u64;
    for (block_index, block) in blocks.iter_mut().enumerate() {
        for (index, inst) in block.insts.iter_mut().enumerate() {
            if inst.removed {
                continue;
            }
            if matches!(inst.op, SsaOp::Store { .. } | SsaOp::Load { .. }) {
                continue;
            }
            if !marked.contains(&(block_index, false, index)) {
                inst.removed = true;
                removed += 1;
            }
        }
        for (index, inst) in block.phis.iter_mut().enumerate() {
            if !marked.contains(&(block_index, true, index)) {
                inst.removed = true;
                removed += 1;
            }
        }
    }
    removed
}

fn block_can_exit(block: &SsaBlock) -> bool {
    match &block.term {
        Term::Return { .. } | Term::Exit => true,
        Term::Jump { .. } => block.succs.is_empty(),
        Term::JumpIf { .. } => block.succs.len() < 2,
    }
}

fn idom_from_blocks(blocks: &[SsaBlock]) -> Vec<BlockId> {
    let count = blocks.len();
    let mut preds = vec![Vec::new(); count];
    for (index, block) in blocks.iter().enumerate() {
        for succ in &block.succs {
            preds[*succ].push(index);
        }
    }
    let all: HashSet<BlockId> = (0..count).collect();
    let mut dom = vec![all; count];
    dom[0] = HashSet::from([0usize]);
    loop {
        let mut changed = false;
        for block in 1..count {
            let mut next: Option<HashSet<BlockId>> = None;
            for pred in &preds[block] {
                next = Some(match next {
                    None => dom[*pred].clone(),
                    Some(current) => current.intersection(&dom[*pred]).copied().collect(),
                });
            }
            let mut next = next.unwrap_or_default();
            next.insert(block);
            if next != dom[block] {
                dom[block] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut idom = vec![0usize; count];
    for block in 1..count {
        idom[block] = dom[block]
            .iter()
            .copied()
            .filter(|candidate| *candidate != block)
            .max_by_key(|candidate| dom[*candidate].len())
            .unwrap_or(0);
    }
    idom
}

fn licm(blocks: &mut [SsaBlock]) -> u64 {
    let idom = idom_from_blocks(blocks);
    let mut hoisted = 0u64;
    let mut loops = Vec::new();
    for tail in 0..blocks.len() {
        for header in blocks[tail].succs.clone() {
            if dominates(&idom, header, tail) {
                let mut body = HashSet::new();
                body.insert(header);
                let mut stack = vec![tail];
                while let Some(node) = stack.pop() {
                    if body.insert(node) {
                        for pred in &blocks[node].preds {
                            stack.push(*pred);
                        }
                    }
                }
                let outside: Vec<BlockId> = blocks[header]
                    .preds
                    .iter()
                    .copied()
                    .filter(|pred| !body.contains(pred))
                    .collect();
                if outside.len() == 1 {
                    loops.push((header, body, outside[0]));
                }
            }
        }
    }
    for (header, body, preheader) in loops {
        if body.contains(&preheader) {
            continue;
        }
        let mut defined_in_loop = HashSet::new();
        let mut def_counts: HashMap<u8, usize> = HashMap::new();
        let mut loop_phi_vars: HashSet<u8> = HashSet::new();
        for block in &body {
            for phi in &blocks[*block].phis {
                if let Some(var) = phi.def_var() {
                    loop_phi_vars.insert(var);
                }
            }
            for inst in all_insts(&blocks[*block]) {
                if let Some(value) = inst.def_value() {
                    defined_in_loop.insert(value);
                }
            }
            // Phi definitions are entry merges, not loop redefinitions.
            for inst in &blocks[*block].insts {
                for (var, _) in &inst.defs {
                    *def_counts.entry(*var).or_insert(0) += 1;
                }
            }
        }
        let phi_vars_with_preheader: HashSet<u8> = blocks[header]
            .phis
            .iter()
            .filter_map(|phi| {
                let var = phi.def_var()?;
                match &phi.op {
                    SsaOp::Phi { incoming, .. }
                        if incoming.iter().any(|(pred, _)| *pred == preheader) =>
                    {
                        Some(var)
                    }
                    _ => None,
                }
            })
            .collect();
        let mut moved = Vec::new();
        let mut keep = Vec::new();
        for inst in blocks[header].insts.drain(..) {
            let destination_is_single_def = inst.def_var().is_some_and(|var| {
                if def_counts.get(&var).copied() != Some(1) {
                    return false;
                }
                !loop_phi_vars.contains(&var) || phi_vars_with_preheader.contains(&var)
            });
            let invariant = !inst.removed
                && destination_is_single_def
                && matches!(
                    inst.op,
                    SsaOp::Const(_)
                        | SsaOp::Copy { .. }
                        | SsaOp::Binary { .. }
                        | SsaOp::Unary { .. }
                        | SsaOp::SetFlags { .. }
                )
                && inst
                    .uses
                    .iter()
                    .all(|value| !defined_in_loop.contains(value));
            if invariant {
                moved.push(inst);
                hoisted += 1;
            } else {
                keep.push(inst);
            }
        }
        blocks[header].insts = keep;
        for inst in &moved {
            let Some(var) = inst.def_var() else {
                continue;
            };
            let Some(value) = inst.def_value() else {
                continue;
            };
            for phi in &mut blocks[header].phis {
                if phi.def_var() != Some(var) {
                    continue;
                }
                if let SsaOp::Phi { incoming, .. } = &mut phi.op {
                    for (pred, incoming_value) in incoming {
                        if *pred == preheader {
                            *incoming_value = value;
                        }
                    }
                }
            }
        }
        blocks[preheader].insts.extend(moved);
    }
    hoisted
}

fn dominates(idom: &[BlockId], mut block: BlockId, target: BlockId) -> bool {
    if block == target {
        return true;
    }
    for _ in 0..idom.len() {
        let parent = idom[block];
        if parent == block {
            return false;
        }
        block = parent;
        if block == target {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Location {
    Reg(u8),
    Spill(u16),
    Flags,
}

fn home_location(var: u8) -> Location {
    match var {
        0..=12 => Location::Reg(var),
        13 => Location::Spill(0),
        14 => Location::Spill(1),
        15 => Location::Spill(2),
        _ => Location::Flags,
    }
}

struct Lowerer {
    value_var: HashMap<ValueId, u8>,
}

impl Lowerer {
    fn location(&self, value: ValueId) -> Location {
        home_location(self.value_var.get(&value).copied().unwrap_or(15))
    }
}

struct Scratch {
    used: [bool; 3],
}

impl Scratch {
    fn take(&mut self) -> Option<u8> {
        for (index, used) in self.used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(SPILL_SCRATCH[index] as u8);
            }
        }
        None
    }
}

fn lower_operand(
    operand: Operand,
    lowerer: &Lowerer,
    out: &mut Vec<IrInstruction>,
    scratch: &mut Scratch,
) -> Result<u8, Fallback> {
    match operand {
        Operand::Imm(value) => {
            let reg = scratch
                .take()
                .ok_or_else(|| fallback("spill scratch exhausted"))?;
            out.push(IrInstruction::MovImm {
                dst: Register::from_index(reg as usize),
                value,
            });
            Ok(reg)
        }
        Operand::Value(value) => match lowerer.location(value) {
            Location::Reg(reg) => Ok(reg),
            Location::Spill(slot) => {
                let reg = scratch
                    .take()
                    .ok_or_else(|| fallback("spill scratch exhausted"))?;
                out.push(IrInstruction::SpillLoad {
                    slot,
                    dst: Register::from_index(reg as usize),
                });
                Ok(reg)
            }
            Location::Flags => Err(fallback("flags value used as operand")),
        },
    }
}

fn lower_address(
    address: &Address,
    lowerer: &Lowerer,
    out: &mut Vec<IrInstruction>,
    scratch: &mut Scratch,
) -> Result<MemoryOperand, Fallback> {
    let base = match address.base {
        Some(value) => {
            Some(Register::from_index(
                lower_operand(Operand::Value(value), lowerer, out, scratch)? as usize,
            ))
        }
        None => None,
    };
    let index = match address.index {
        Some(value) => {
            Some(Register::from_index(
                lower_operand(Operand::Value(value), lowerer, out, scratch)? as usize,
            ))
        }
        None => None,
    };
    Ok(MemoryOperand {
        base,
        index,
        scale: address.scale,
        displacement: address.displacement,
        rip_relative: false,
        rip_base: 0,
        segment: address.segment,
        address_size_32: false,
        absolute_address: address.absolute_address,
    })
}

fn lower_store(slot: u16, src: u8, out: &mut Vec<IrInstruction>) {
    out.push(IrInstruction::SpillStore {
        slot,
        src: Register::from_index(src as usize),
    });
}

fn lower_block(
    block: &SsaBlock,
    block_index: BlockId,
    all_blocks: &[SsaBlock],
    by_address: &HashMap<u64, BlockId>,
    lowerer: &Lowerer,
) -> Result<(Vec<IrInstruction>, OptimizedTerminator), Fallback> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < block.insts.len() {
        let inst = &block.insts[index];
        if inst.removed {
            index += 1;
            continue;
        }
        let paired_flags = match &inst.op {
            SsaOp::Binary { .. } => block.insts.get(index + 1).and_then(|next| {
                if next.removed {
                    return None;
                }
                match &next.op {
                    SsaOp::SetFlags {
                        kind: FlagKind::Add | FlagKind::Sub | FlagKind::Logic,
                        result: Some(Operand::Value(result)),
                        ..
                    } if Some(*result) == inst.def_value() => Some(next),
                    _ => None,
                }
            }),
            _ => None,
        };
        if let Some(flags) = paired_flags {
            lower_alu_with_flags(inst, flags, lowerer, &mut out)?;
            index += 2;
        } else {
            lower_one(inst, lowerer, &mut out)?;
            index += 1;
        }
    }
    // R13/R14/R15 double as spill scratch, so their architectural home
    // registers may hold a temporary.  Reload the spill slots before any
    // control transfer (internal branch or function exit) so guest-visible
    // state is exact at every boundary.
    for (slot, reg) in [(0u16, 13usize), (1, 14), (2, 15)] {
        out.push(IrInstruction::SpillLoad {
            slot,
            dst: Register::from_index(reg),
        });
    }
    let terminator = match &block.term {
        Term::Jump { target } => OptimizedTerminator::Jump {
            target: *target,
            copies: edge_copies(block_index, *target, all_blocks, by_address, lowerer)?,
        },
        Term::JumpIf {
            condition,
            target,
            fallthrough,
        } => OptimizedTerminator::JumpIf {
            condition: *condition,
            target: *target,
            fallthrough: *fallthrough,
            taken_copies: edge_copies(block_index, *target, all_blocks, by_address, lowerer)?,
            fallthrough_copies: edge_copies(
                block_index,
                *fallthrough,
                all_blocks,
                by_address,
                lowerer,
            )?,
        },
        Term::Return { stack_adjust } => OptimizedTerminator::Return {
            stack_adjust: *stack_adjust,
        },
        Term::Exit => OptimizedTerminator::Exit,
    };
    Ok((out, terminator))
}

/// Lower an ALU instruction and its immediately-following flags producer as
/// one unit.  The producer's `lhs` is the *pre*-instruction value of the
/// destination register, so it must be saved before the ALU overwrites that
/// home register.
fn lower_alu_with_flags(
    alu: &SsaInst,
    flags: &SsaInst,
    lowerer: &Lowerer,
    out: &mut Vec<IrInstruction>,
) -> Result<(), Fallback> {
    const LHS_STAGE: u16 = 18;
    const RHS_STAGE: u16 = 19;
    let SsaOp::SetFlags {
        kind,
        lhs,
        rhs,
        width,
        ..
    } = &flags.op
    else {
        return Err(fallback("flag pair without SetFlags"));
    };
    let mut save = Scratch { used: [false; 3] };
    match lhs {
        Operand::Imm(value) => {
            let reg = save
                .take()
                .ok_or_else(|| fallback("spill scratch exhausted"))?;
            out.push(IrInstruction::MovImm {
                dst: Register::from_index(reg as usize),
                value: *value,
            });
            lower_store(LHS_STAGE, reg, out);
        }
        Operand::Value(value) => {
            let reg = lower_operand(Operand::Value(*value), lowerer, out, &mut save)?;
            lower_store(LHS_STAGE, reg, out);
        }
    }
    match rhs {
        Operand::Imm(value) => {
            let reg = save
                .take()
                .ok_or_else(|| fallback("spill scratch exhausted"))?;
            out.push(IrInstruction::MovImm {
                dst: Register::from_index(reg as usize),
                value: *value,
            });
            lower_store(RHS_STAGE, reg, out);
        }
        Operand::Value(value) => {
            let reg = lower_operand(Operand::Value(*value), lowerer, out, &mut save)?;
            lower_store(RHS_STAGE, reg, out);
        }
    }
    lower_one(alu, lowerer, out)?;
    // Reload the saved operands and the result into dedicated scratch regs.
    out.push(IrInstruction::SpillLoad {
        slot: LHS_STAGE,
        dst: Register::from_index(SPILL_SCRATCH[0]),
    });
    out.push(IrInstruction::SpillLoad {
        slot: RHS_STAGE,
        dst: Register::from_index(SPILL_SCRATCH[1]),
    });
    let result_reg = match alu.def_var().map(home_location) {
        Some(Location::Reg(reg)) => reg,
        Some(Location::Spill(slot)) => {
            out.push(IrInstruction::SpillLoad {
                slot,
                dst: Register::from_index(SPILL_SCRATCH[2]),
            });
            SPILL_SCRATCH[2] as u8
        }
        _ => return Err(fallback("alu flags without register result")),
    };
    out.push(IrInstruction::ExplicitFlags {
        op: match kind {
            FlagKind::Add => 0,
            FlagKind::Sub => 1,
            FlagKind::Logic => 2,
            FlagKind::Cmp | FlagKind::Test => unreachable!(),
        },
        lhs: Register::from_index(SPILL_SCRATCH[0]),
        rhs: Register::from_index(SPILL_SCRATCH[1]),
        result: Register::from_index(result_reg as usize),
        width: *width as usize,
    });
    Ok(())
}

fn lower_one(
    inst: &SsaInst,
    lowerer: &Lowerer,
    out: &mut Vec<IrInstruction>,
) -> Result<(), Fallback> {
    let mut scratch = Scratch { used: [false; 3] };
    let target = inst.def_var().map(home_location);
    match &inst.op {
        SsaOp::EntryVar(_) | SsaOp::Phi { .. } => {}
        SsaOp::Const(value) => match target {
            Some(Location::Reg(reg)) => out.push(IrInstruction::MovImm {
                dst: Register::from_index(reg as usize),
                value: *value,
            }),
            Some(Location::Spill(slot)) => {
                let reg = scratch
                    .take()
                    .ok_or_else(|| fallback("spill scratch exhausted"))?;
                out.push(IrInstruction::MovImm {
                    dst: Register::from_index(reg as usize),
                    value: *value,
                });
                lower_store(slot, reg, out);
            }
            _ => return Err(fallback("const without register destination")),
        },
        SsaOp::Copy { src, width } => {
            let target = target.ok_or_else(|| fallback("copy without destination"))?;
            let src_reg = lower_operand(Operand::Value(*src), lowerer, out, &mut scratch)?;
            match target {
                Location::Reg(reg) => {
                    if reg != src_reg {
                        let dst = Register::from_index(reg as usize);
                        let src = Register::from_index(src_reg as usize);
                        out.push(IrInstruction::MovReg {
                            dst,
                            src,
                            width: *width as usize,
                        });
                    }
                }
                Location::Spill(slot) => {
                    if *width != 8 {
                        let reg = scratch
                            .take()
                            .ok_or_else(|| fallback("spill scratch exhausted"))?;
                        out.push(IrInstruction::MovReg {
                            dst: Register::from_index(reg as usize),
                            src: Register::from_index(src_reg as usize),
                            width: *width as usize,
                        });
                        lower_store(slot, reg, out);
                    } else {
                        lower_store(slot, src_reg, out);
                    }
                }
                Location::Flags => return Err(fallback("copy assigned to flags")),
            }
        }
        SsaOp::Binary {
            op,
            lhs,
            rhs,
            width,
        } => {
            let target = target.ok_or_else(|| fallback("binary without destination"))?;
            let (dst_reg, store) = match target {
                Location::Reg(reg) => (reg, None),
                Location::Spill(slot) => {
                    let reg = scratch
                        .take()
                        .ok_or_else(|| fallback("spill scratch exhausted"))?;
                    (reg, Some(slot))
                }
                Location::Flags => return Err(fallback("binary assigned to flags")),
            };
            let lhs_reg = bind_lhs(*lhs, dst_reg, lowerer, out, &mut scratch)?;
            let dst = Register::from_index(dst_reg as usize);
            match (op, rhs) {
                (
                    BinOp::Add | BinOp::Sub | BinOp::And | BinOp::Or | BinOp::Xor,
                    Operand::Imm(value),
                ) => {
                    out.push(match op {
                        BinOp::Add => IrInstruction::AddImm {
                            dst,
                            value: *value,
                            width: *width as usize,
                        },
                        BinOp::Sub => IrInstruction::SubImm {
                            dst,
                            value: *value,
                            width: *width as usize,
                        },
                        BinOp::And => IrInstruction::AndImm {
                            dst,
                            value: *value,
                            width: *width as usize,
                        },
                        BinOp::Or => IrInstruction::OrImm {
                            dst,
                            value: *value,
                            width: *width as usize,
                        },
                        _ => IrInstruction::XorImm {
                            dst,
                            value: *value,
                            width: *width as usize,
                        },
                    });
                }
                (BinOp::Shl | BinOp::Shr | BinOp::Sar, Operand::Imm(value)) => {
                    out.push(match op {
                        BinOp::Shl => IrInstruction::ShlImm {
                            dst,
                            count: *value as u8,
                            width: *width as usize,
                        },
                        BinOp::Shr => IrInstruction::ShrImm {
                            dst,
                            count: *value as u8,
                            width: *width as usize,
                        },
                        _ => IrInstruction::SarImm {
                            dst,
                            count: *value as u8,
                            width: *width as usize,
                        },
                    });
                }
                _ => {
                    let rhs_reg = lower_operand(*rhs, lowerer, out, &mut scratch)?;
                    let src = CompareOperand::Register(Register::from_index(rhs_reg as usize));
                    out.push(match op {
                        BinOp::Add => IrInstruction::AddOperand {
                            dst,
                            src,
                            width: *width as usize,
                        },
                        BinOp::Sub => IrInstruction::SubOperand {
                            dst,
                            src,
                            width: *width as usize,
                        },
                        BinOp::And => IrInstruction::AndReg {
                            dst,
                            src,
                            width: *width as usize,
                        },
                        BinOp::Or => IrInstruction::OrReg {
                            dst,
                            src,
                            width: *width as usize,
                        },
                        BinOp::Xor => IrInstruction::XorReg {
                            dst,
                            src,
                            width: *width as usize,
                        },
                        BinOp::Shl | BinOp::Shr | BinOp::Sar => {
                            return Err(fallback("variable shift"));
                        }
                    });
                }
            }
            if let Some(slot) = store {
                lower_store(slot, dst_reg, out);
            }
            let _ = lhs_reg;
        }
        SsaOp::Unary { op, val, width } => {
            let target = target.ok_or_else(|| fallback("unary without destination"))?;
            let (dst_reg, store) = match target {
                Location::Reg(reg) => (reg, None),
                Location::Spill(slot) => {
                    let reg = scratch
                        .take()
                        .ok_or_else(|| fallback("spill scratch exhausted"))?;
                    (reg, Some(slot))
                }
                Location::Flags => return Err(fallback("unary assigned to flags")),
            };
            let src_reg = lower_operand(*val, lowerer, out, &mut scratch)?;
            if src_reg != dst_reg {
                out.push(IrInstruction::MovReg {
                    dst: Register::from_index(dst_reg as usize),
                    src: Register::from_index(src_reg as usize),
                    width: 8,
                });
            }
            let dst = Register::from_index(dst_reg as usize);
            out.push(match op {
                UnOp::Neg => IrInstruction::NegReg {
                    dst,
                    width: *width as usize,
                },
                UnOp::Not => IrInstruction::NotReg {
                    dst,
                    width: *width as usize,
                },
                UnOp::Inc => IrInstruction::IncReg {
                    dst,
                    width: *width as usize,
                },
                UnOp::Dec => IrInstruction::DecReg {
                    dst,
                    width: *width as usize,
                },
            });
            if let Some(slot) = store {
                lower_store(slot, dst_reg, out);
            }
        }
        SsaOp::SetFlags {
            kind,
            lhs,
            rhs,
            result,
            width,
        } => {
            if matches!(kind, FlagKind::Cmp | FlagKind::Test) {
                let lhs_reg = lower_operand(*lhs, lowerer, out, &mut scratch)?;
                let rhs_reg = lower_operand(*rhs, lowerer, out, &mut scratch)?;
                let lhs = CompareOperand::Register(Register::from_index(lhs_reg as usize));
                let rhs = CompareOperand::Register(Register::from_index(rhs_reg as usize));
                out.push(if matches!(kind, FlagKind::Cmp) {
                    IrInstruction::Compare {
                        lhs,
                        rhs,
                        width: *width as usize,
                    }
                } else {
                    IrInstruction::Test {
                        lhs,
                        rhs,
                        width: *width as usize,
                    }
                });
            } else {
                let result = result.ok_or_else(|| fallback("alu flags without result"))?;
                let lhs_reg = lower_operand(*lhs, lowerer, out, &mut scratch)?;
                let rhs_reg = lower_operand(*rhs, lowerer, out, &mut scratch)?;
                let result_reg = lower_operand(result, lowerer, out, &mut scratch)?;
                out.push(IrInstruction::ExplicitFlags {
                    op: match kind {
                        FlagKind::Add => 0,
                        FlagKind::Sub => 1,
                        FlagKind::Logic => 2,
                        FlagKind::Cmp | FlagKind::Test => unreachable!(),
                    },
                    lhs: Register::from_index(lhs_reg as usize),
                    rhs: Register::from_index(rhs_reg as usize),
                    result: Register::from_index(result_reg as usize),
                    width: *width as usize,
                });
            }
        }
        SsaOp::Load { address, width } => {
            let target = target.ok_or_else(|| fallback("load without destination"))?;
            let address = lower_address(address, lowerer, out, &mut scratch)?;
            match target {
                Location::Reg(reg) => out.push(IrInstruction::LoadMemory {
                    dst: Register::from_index(reg as usize),
                    address,
                    width: *width as usize,
                }),
                Location::Spill(slot) => {
                    let reg = scratch
                        .take()
                        .ok_or_else(|| fallback("spill scratch exhausted"))?;
                    out.push(IrInstruction::LoadMemory {
                        dst: Register::from_index(reg as usize),
                        address,
                        width: *width as usize,
                    });
                    lower_store(slot, reg, out);
                }
                Location::Flags => return Err(fallback("load assigned to flags")),
            }
        }
        SsaOp::Store {
            address,
            value,
            width,
        } => {
            let address = lower_address(address, lowerer, out, &mut scratch)?;
            let value_reg = lower_operand(*value, lowerer, out, &mut scratch)?;
            out.push(IrInstruction::StoreMemory {
                src: Register::from_index(value_reg as usize),
                address,
                width: *width as usize,
            });
        }
    }
    Ok(())
}

fn bind_lhs(
    lhs: Operand,
    dst_reg: u8,
    lowerer: &Lowerer,
    out: &mut Vec<IrInstruction>,
    scratch: &mut Scratch,
) -> Result<u8, Fallback> {
    match lhs {
        Operand::Imm(value) => {
            out.push(IrInstruction::MovImm {
                dst: Register::from_index(dst_reg as usize),
                value,
            });
            Ok(dst_reg)
        }
        Operand::Value(value) => {
            let reg = lower_operand(Operand::Value(value), lowerer, out, scratch)?;
            if reg != dst_reg {
                out.push(IrInstruction::MovReg {
                    dst: Register::from_index(dst_reg as usize),
                    src: Register::from_index(reg as usize),
                    width: 8,
                });
            }
            Ok(dst_reg)
        }
    }
}

fn edge_copies(
    predecessor_index: BlockId,
    target_address: u64,
    all_blocks: &[SsaBlock],
    by_address: &HashMap<u64, BlockId>,
    lowerer: &Lowerer,
) -> Result<Vec<IrInstruction>, Fallback> {
    let Some(target_index) = by_address.get(&target_address).copied() else {
        return Ok(Vec::new());
    };
    let target = &all_blocks[target_index];
    let mut staged = Vec::new();
    for phi in &target.phis {
        let SsaOp::Phi { var, incoming } = &phi.op else {
            continue;
        };
        let Some((_, incoming_value)) =
            incoming.iter().find(|(pred, _)| *pred == predecessor_index)
        else {
            return Err(fallback("phi missing predecessor edge"));
        };
        if *var == FLAGS_VAR {
            continue;
        }
        let destination = home_location(*var);
        let source = lowerer.location(*incoming_value);
        if source != destination {
            staged.push((*incoming_value, destination));
        }
    }
    if staged.len() > SPILL_SLOTS - PHI_STAGE_BASE {
        return Err(fallback("too many phi copies"));
    }
    let mut out = Vec::new();
    for (index, (value, _)) in staged.iter().enumerate() {
        let slot = (PHI_STAGE_BASE + index) as u16;
        match lowerer.location(*value) {
            Location::Reg(reg) => lower_store(slot, reg, &mut out),
            Location::Spill(source_slot) => {
                out.push(IrInstruction::SpillLoad {
                    slot: source_slot,
                    dst: Register::from_index(SPILL_SCRATCH[0]),
                });
                lower_store(slot, SPILL_SCRATCH[0] as u8, &mut out);
            }
            Location::Flags => {}
        }
    }
    for (index, (_, destination)) in staged.iter().enumerate() {
        let slot = (PHI_STAGE_BASE + index) as u16;
        match destination {
            Location::Reg(reg) => out.push(IrInstruction::SpillLoad {
                slot,
                dst: Register::from_index(*reg as usize),
            }),
            Location::Spill(dest_slot) => {
                out.push(IrInstruction::SpillLoad {
                    slot,
                    dst: Register::from_index(SPILL_SCRATCH[0]),
                });
                lower_store(*dest_slot, SPILL_SCRATCH[0] as u8, &mut out);
            }
            Location::Flags => {}
        }
    }
    Ok(out)
}

fn optimize_function_inner(
    blocks: &[FunctionBlock],
    _arch: GuestArch,
) -> Result<OptimizationResult, Fallback> {
    let original_instructions: usize = blocks.iter().map(|block| block.instructions.len()).sum();
    let (raw, _addresses) = build_cfg(blocks)?;
    let (_live_in, live_out) = block_flag_liveness(&raw);
    validate_flag_producers(&raw, &live_out)?;
    let (mut ssa, value_count) = build_ssa(raw)?;
    let sccp_eliminated = sccp(&mut ssa);
    let gvn_eliminated = gvn(&mut ssa);
    let (load_forwarded, store_eliminated) = load_store_forwarding(&mut ssa);
    let licm_hoisted = licm(&mut ssa);
    let dce_eliminated = dce(&mut ssa);
    let after: u64 = ssa
        .iter()
        .map(|block| all_insts(block).filter(|inst| !inst.removed).count() as u64)
        .sum();

    let mut value_var = HashMap::new();
    for block in &ssa {
        for inst in all_insts(block) {
            for (var, value) in &inst.defs {
                value_var.insert(*value, *var);
            }
        }
    }
    let spills = value_var
        .values()
        .filter(|var| (13..=15).contains(*var))
        .count() as u64;
    let lowerer = Lowerer { value_var };
    let mut by_address = HashMap::new();
    for (index, block) in ssa.iter().enumerate() {
        by_address.insert(block.guest_address, index);
    }
    let mut optimized = Vec::with_capacity(ssa.len());
    for (index, block) in ssa.iter().enumerate() {
        let (instructions, terminator) = lower_block(block, index, &ssa, &by_address, &lowerer)?;
        optimized.push(OptimizedBlock {
            guest_address: block.guest_address,
            instructions,
            terminator,
        });
    }

    FUNCTIONS_COMPILED.fetch_add(1, Ordering::Relaxed);
    BLOCKS.fetch_add(ssa.len() as u64, Ordering::Relaxed);
    SSA_VALUES.fetch_add(u64::from(value_count), Ordering::Relaxed);
    INSTRUCTIONS_BEFORE.fetch_add(original_instructions as u64, Ordering::Relaxed);
    INSTRUCTIONS_AFTER.fetch_add(after, Ordering::Relaxed);
    SCCP_ELIMINATED.fetch_add(sccp_eliminated, Ordering::Relaxed);
    GVN_ELIMINATED.fetch_add(gvn_eliminated, Ordering::Relaxed);
    DCE_ELIMINATED.fetch_add(dce_eliminated, Ordering::Relaxed);
    LICM_HOISTED.fetch_add(licm_hoisted, Ordering::Relaxed);
    LOAD_FORWARDED.fetch_add(load_forwarded, Ordering::Relaxed);
    STORE_ELIMINATED.fetch_add(store_eliminated, Ordering::Relaxed);
    REGISTER_SPILLS.fetch_add(spills, Ordering::Relaxed);

    let function_metrics = Tier2Metrics {
        functions_compiled: 1,
        functions_fallback: 0,
        blocks: ssa.len() as u64,
        ssa_values: u64::from(value_count),
        instructions_before: original_instructions as u64,
        instructions_after: after,
        sccp_eliminated,
        gvn_eliminated,
        dce_eliminated,
        licm_hoisted,
        load_forwarded,
        store_eliminated,
        register_spills: spills,
        fallback_reasons: BTreeMap::new(),
    };
    Ok(OptimizationResult {
        blocks: optimized,
        metrics: function_metrics,
        original_instructions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{CpuState, MemoryImage};
    use crate::jit::{CompilationTier, JitRuntime, jit_execution_available};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn mem(address: u64, _width: usize) -> MemoryOperand {
        MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(address),
        }
    }

    fn mov(dst: Register, value: u64) -> IrInstruction {
        IrInstruction::MovImm { dst, value }
    }

    fn add_imm(dst: Register, value: u64, width: usize) -> IrInstruction {
        IrInstruction::AddImm { dst, value, width }
    }

    fn jmp(target: u64) -> IrInstruction {
        IrInstruction::Jump { target }
    }

    fn jne(target: u64, fallthrough: u64) -> IrInstruction {
        IrInstruction::JumpIf {
            condition: ConditionCode::NotEqual,
            target,
            fallthrough,
        }
    }

    fn je(target: u64, fallthrough: u64) -> IrInstruction {
        IrInstruction::JumpIf {
            condition: ConditionCode::Equal,
            target,
            fallthrough,
        }
    }

    fn store(address: u64, src: Register) -> IrInstruction {
        IrInstruction::StoreMemory {
            src,
            address: mem(address, 8),
            width: 8,
        }
    }

    fn load(address: u64, dst: Register) -> IrInstruction {
        IrInstruction::LoadMemory {
            dst,
            address: mem(address, 8),
            width: 8,
        }
    }

    fn cmp(target: Register, value: u64) -> IrInstruction {
        IrInstruction::Compare {
            lhs: CompareOperand::Register(target),
            rhs: CompareOperand::ImmediateU64(value),
            width: 8,
        }
    }

    fn run_interpreter(
        blocks: &[FunctionBlock],
        entry: u64,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) {
        let map: HashMap<u64, &Vec<IrInstruction>> = blocks
            .iter()
            .map(|block| (block.guest_address, &block.instructions))
            .collect();
        state.rip = entry;
        for _ in 0..4096 {
            let Some(ir) = map.get(&state.rip) else {
                return;
            };
            crate::cpu::execute_ir(state, memory, ir).expect("Tier-0 interpretation");
        }
        panic!("Tier-0 program did not terminate");
    }

    fn run_tier2(
        blocks: &[FunctionBlock],
        entry: u64,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> crate::jit::JitExitReason {
        assert!(
            jit_execution_available(),
            "this test requires executable JIT memory"
        );
        let mut runtime = JitRuntime::new(GuestArch::X64);
        let compiled = runtime
            .get_or_compile_function_tier2(blocks, GuestArch::X64)
            .expect("Tier-2 function compile")
            .expect("supported function must promote");
        assert_eq!(
            compiled.compile_tier,
            CompilationTier::Tier2,
            "supported function must compile at Tier-2"
        );
        let compiled = compiled.clone();
        crate::jit::JIT_SAFEPOINT_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
        state.rip = entry;
        unsafe { runtime.execute_block(&compiled, state, memory) }
    }

    #[test]
    fn jit_ssa_tier2_vs_tier0_arithmetic_branch_loop_no_mismatch() {
        let _guard = lock();
        let blocks = vec![
            FunctionBlock::new(
                0x1000,
                vec![mov(Register::Rax, 0), mov(Register::Rcx, 5), jmp(0x1010)],
            ),
            FunctionBlock::new(
                0x1010,
                vec![
                    IrInstruction::AddOperand {
                        dst: Register::Rax,
                        src: CompareOperand::Register(Register::Rcx),
                        width: 8,
                    },
                    IrInstruction::SubImm {
                        dst: Register::Rcx,
                        value: 1,
                        width: 8,
                    },
                    cmp(Register::Rcx, 0),
                    jne(0x1010, 0x1020),
                ],
            ),
            FunctionBlock::new(0x1020, vec![store(0x3000, Register::Rax), jmp(0x9999)]),
        ];
        let mut tier0_state = CpuState::new(GuestArch::X64);
        let mut tier0_memory = MemoryImage::default();
        tier0_memory.map_bytes(0x3000, &[0u8; 0x40]);
        run_interpreter(&blocks, 0x1000, &mut tier0_state, &mut tier0_memory);

        let mut tier2_state = CpuState::new(GuestArch::X64);
        let mut tier2_memory = MemoryImage::default();
        tier2_memory.map_bytes(0x3000, &[0u8; 0x40]);
        let reason = run_tier2(&blocks, 0x1000, &mut tier2_state, &mut tier2_memory);
        assert_eq!(reason, crate::jit::JitExitReason::Jump { target: 0x9999 });

        assert_eq!(tier0_state.get(Register::Rax), 15);
        assert_eq!(
            tier2_state.get(Register::Rax),
            tier0_state.get(Register::Rax)
        );
        assert_eq!(
            tier2_memory.read_u64(0x3000).unwrap(),
            tier0_memory.read_u64(0x3000).unwrap()
        );
        assert_eq!(tier2_state.get(Register::Rcx), 0);
    }

    #[test]
    fn jit_ssa_tier2_vs_tier0_load_store_alu_flags_no_mismatch() {
        let _guard = lock();
        let blocks = vec![
            FunctionBlock::new(
                0x1000,
                vec![
                    mov(Register::Rax, 7),
                    store(0x3000, Register::Rax),
                    load(0x3000, Register::Rbx),
                    add_imm(Register::Rbx, 1, 8),
                    store(0x3008, Register::Rbx),
                    je(0x1010, 0x1020),
                ],
            ),
            FunctionBlock::new(0x1010, vec![mov(Register::Rcx, 1), jmp(0x1030)]),
            FunctionBlock::new(0x1020, vec![mov(Register::Rcx, 0), jmp(0x1030)]),
            FunctionBlock::new(0x1030, vec![store(0x3010, Register::Rcx), jmp(0x9999)]),
        ];
        let mut tier0_state = CpuState::new(GuestArch::X64);
        let mut tier0_memory = MemoryImage::default();
        tier0_memory.map_bytes(0x3000, &[0u8; 0x40]);
        run_interpreter(&blocks, 0x1000, &mut tier0_state, &mut tier0_memory);

        let mut tier2_state = CpuState::new(GuestArch::X64);
        let mut tier2_memory = MemoryImage::default();
        tier2_memory.map_bytes(0x3000, &[0u8; 0x40]);
        let reason = run_tier2(&blocks, 0x1000, &mut tier2_state, &mut tier2_memory);
        assert_eq!(reason, crate::jit::JitExitReason::Jump { target: 0x9999 });

        assert_eq!(tier2_state.get(Register::Rbx), 8);
        assert_eq!(tier2_state.get(Register::Rcx), 0);
        assert_eq!(tier2_memory.read_u64(0x3010).unwrap(), 0);
        assert_eq!(tier2_memory.read_u64(0x3008).unwrap(), 8);
        assert_eq!(
            tier2_memory.read_u64(0x3000).unwrap(),
            tier0_memory.read_u64(0x3000).unwrap()
        );
    }

    #[test]
    fn jit_ssa_incoming_spill_registers_are_not_clobbered_no_mismatch() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![
                IrInstruction::MovReg {
                    dst: Register::Rax,
                    src: Register::R13,
                    width: 8,
                },
                IrInstruction::MovReg {
                    dst: Register::Rbx,
                    src: Register::R14,
                    width: 8,
                },
                IrInstruction::MovReg {
                    dst: Register::Rcx,
                    src: Register::R15,
                    width: 8,
                },
                jmp(0x9999),
            ],
        )];
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::R13, 111);
        state.set(Register::R14, 222);
        state.set(Register::R15, 333);
        let mut memory = MemoryImage::default();
        let _ = run_tier2(&blocks, 0x1000, &mut state, &mut memory);
        assert_eq!(state.get(Register::R13), 111);
        assert_eq!(state.get(Register::R14), 222);
        assert_eq!(state.get(Register::R15), 333);
        assert_eq!(state.get(Register::Rax), 111);
        assert_eq!(state.get(Register::Rbx), 222);
        assert_eq!(state.get(Register::Rcx), 333);
    }

    #[test]
    fn jit_ssa_spilled_registers_round_trip_no_mismatch() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![
                mov(Register::R13, 5),
                add_imm(Register::R13, 7, 8),
                IrInstruction::MovReg {
                    dst: Register::R14,
                    src: Register::R13,
                    width: 8,
                },
                add_imm(Register::R14, 100, 8),
                IrInstruction::MovReg {
                    dst: Register::R15,
                    src: Register::R14,
                    width: 8,
                },
                add_imm(Register::R15, 1000, 8),
                jmp(0x9999),
            ],
        )];
        let optimized = optimize_function(&blocks, GuestArch::X64).expect("supported function");
        assert!(
            optimized.metrics.register_spills >= 3,
            "R13/R14/R15 must be spill-allocated, got {}",
            optimized.metrics.register_spills
        );

        let mut tier0_state = CpuState::new(GuestArch::X64);
        let mut tier0_memory = MemoryImage::default();
        run_interpreter(&blocks, 0x1000, &mut tier0_state, &mut tier0_memory);
        let mut tier2_state = CpuState::new(GuestArch::X64);
        let mut tier2_memory = MemoryImage::default();
        let _ = run_tier2(&blocks, 0x1000, &mut tier2_state, &mut tier2_memory);

        assert_eq!(tier0_state.get(Register::R13), 12);
        assert_eq!(tier0_state.get(Register::R14), 112);
        assert_eq!(tier0_state.get(Register::R15), 1112);
        assert_eq!(tier2_state.get(Register::R13), 12);
        assert_eq!(tier2_state.get(Register::R14), 112);
        assert_eq!(tier2_state.get(Register::R15), 1112);
    }

    #[test]
    fn jit_ssa_sccp_overflow_constant_chain_exact_count() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![
                mov(Register::Rax, 2),
                add_imm(Register::Rax, 3, 8),
                add_imm(Register::Rax, 4, 8),
                IrInstruction::MovReg {
                    dst: Register::Rbx,
                    src: Register::Rax,
                    width: 8,
                },
                jmp(0x9999),
            ],
        )];
        let result = optimize_function(&blocks, GuestArch::X64).expect("supported function");
        assert_eq!(result.metrics.sccp_eliminated, 4);
        assert!(result.metrics.dce_eliminated >= 1);
        let flat: Vec<IrInstruction> = result
            .blocks
            .into_iter()
            .flat_map(|block| block.instructions)
            .collect();
        assert!(
            flat.iter().any(|insn| matches!(
                insn,
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 9
                }
            )),
            "final RAX definition must survive as a literal"
        );
    }

    #[test]
    fn jit_ssa_gvn_keeps_duplicate_after_register_overwrite_no_stale_mismatch() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![
                mov(Register::Rax, 1),
                add_imm(Register::Rax, 1, 8),
                mov(Register::Rax, 1),
                jmp(0x9999),
            ],
        )];
        let result = optimize_function(&blocks, GuestArch::X64).expect("supported function");
        assert_eq!(result.metrics.gvn_eliminated, 0);
        let flat: Vec<IrInstruction> = result
            .blocks
            .into_iter()
            .flat_map(|block| block.instructions)
            .collect();
        assert!(
            flat.iter().any(|insn| matches!(
                insn,
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 1
                }
            )),
            "the final write of 1 must survive an intervening overwrite"
        );
    }

    #[test]
    fn jit_ssa_gvn_rewrites_cross_register_duplicate_to_exact_copy() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![mov(Register::Rax, 5), mov(Register::Rcx, 5), jmp(0x9999)],
        )];
        let result = optimize_function(&blocks, GuestArch::X64).expect("supported function");
        assert_eq!(result.metrics.gvn_eliminated, 1);
        let flat: Vec<IrInstruction> = result
            .blocks
            .into_iter()
            .flat_map(|block| block.instructions)
            .collect();
        assert!(
            flat.iter().any(|insn| matches!(
                insn,
                IrInstruction::MovReg {
                    dst: Register::Rcx,
                    src: Register::Rax,
                    width: 8
                }
            )),
            "cross-register CSE must emit a real copy, not drop the definition"
        );
    }

    #[test]
    fn jit_ssa_dce_removes_only_overwritten_exact_count() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![mov(Register::Rax, 1), mov(Register::Rax, 2), jmp(0x9999)],
        )];
        let result = optimize_function(&blocks, GuestArch::X64).expect("supported function");
        // Two removals: the overwritten RAX literal and the entry Rax value it
        // supersedes (which emits no code but is dead SSA state).
        assert_eq!(result.metrics.dce_eliminated, 2);
        let flat: Vec<IrInstruction> = result
            .blocks
            .into_iter()
            .flat_map(|block| block.instructions)
            .collect();
        assert!(
            flat.iter().any(|insn| matches!(
                insn,
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 2
                }
            )),
            "the last architectural definition must be kept"
        );
        assert!(
            !flat.iter().any(|insn| matches!(
                insn,
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 1
                }
            )),
            "the overwritten definition must be eliminated"
        );
    }

    #[test]
    fn jit_ssa_licm_hoists_exact_invariant_boundary_count() {
        let _guard = lock();
        let blocks = vec![
            FunctionBlock::new(0x1000, vec![mov(Register::Rcx, 3), jmp(0x1010)]),
            FunctionBlock::new(
                0x1010,
                vec![
                    mov(Register::Rdx, 7),
                    IrInstruction::SubImm {
                        dst: Register::Rcx,
                        value: 1,
                        width: 8,
                    },
                    cmp(Register::Rcx, 0),
                    jne(0x1010, 0x1020),
                ],
            ),
            FunctionBlock::new(0x1020, vec![jmp(0x9999)]),
        ];
        let result = optimize_function(&blocks, GuestArch::X64).expect("supported loop");
        assert_eq!(result.metrics.licm_hoisted, 1);
        let entry = &result.blocks[0];
        assert!(
            entry.instructions.iter().any(|insn| matches!(
                insn,
                IrInstruction::MovImm {
                    dst: Register::Rdx,
                    value: 7
                }
            )),
            "invariant RDX initialization must be hoisted into the preheader"
        );
    }

    #[test]
    fn jit_ssa_licm_hoisted_value_survives_back_edge_no_mismatch() {
        let _guard = lock();
        let blocks = vec![
            FunctionBlock::new(0x1000, vec![mov(Register::Rcx, 4), jmp(0x1010)]),
            FunctionBlock::new(
                0x1010,
                vec![
                    mov(Register::Rdx, 7),
                    IrInstruction::SubImm {
                        dst: Register::Rcx,
                        value: 1,
                        width: 8,
                    },
                    cmp(Register::Rcx, 0),
                    jne(0x1010, 0x1020),
                ],
            ),
            FunctionBlock::new(
                0x1020,
                vec![
                    IrInstruction::MovReg {
                        dst: Register::Rax,
                        src: Register::Rdx,
                        width: 8,
                    },
                    jmp(0x9999),
                ],
            ),
        ];
        let optimized = optimize_function(&blocks, GuestArch::X64).expect("loop");
        assert_eq!(optimized.metrics.licm_hoisted, 1);
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        let _ = run_tier2(&blocks, 0x1000, &mut state, &mut memory);
        assert_eq!(state.get(Register::Rax), 7);
        assert_eq!(state.get(Register::Rdx), 7);
    }

    #[test]
    fn jit_ssa_load_store_forwarding_keeps_destination_no_mismatch() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![
                mov(Register::Rax, 9),
                store(0x3000, Register::Rax),
                store(0x3000, Register::Rax),
                load(0x3000, Register::Rbx),
                jmp(0x9999),
            ],
        )];
        let result = optimize_function(&blocks, GuestArch::X64).expect("supported function");
        assert_eq!(result.metrics.store_eliminated, 1);
        assert_eq!(result.metrics.load_forwarded, 1);
        let flat: Vec<IrInstruction> = result
            .blocks
            .into_iter()
            .flat_map(|block| block.instructions)
            .collect();
        assert!(
            flat.iter().any(|insn| matches!(
                insn,
                IrInstruction::MovReg {
                    dst: Register::Rbx,
                    src: Register::Rax,
                    width: 8
                } | IrInstruction::MovImm {
                    dst: Register::Rbx,
                    value: 9
                }
            )),
            "forwarded load must still define RBX"
        );
    }

    #[test]
    fn jit_ssa_rejects_cpuid_with_exact_reason() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![mov(Register::Rax, 1), IrInstruction::Cpuid],
        )];
        let error = optimize_function(&blocks, GuestArch::X64).expect_err("CPUID is unsupported");
        assert_eq!(error.reason, "unsupported opcode: Cpuid");
    }

    #[test]
    fn jit_ssa_rejects_rip_relative_memory_with_exact_reason() {
        let _guard = lock();
        let blocks = vec![FunctionBlock::new(
            0x1000,
            vec![IrInstruction::LoadMemory {
                dst: Register::Rax,
                address: MemoryOperand {
                    base: None,
                    index: None,
                    scale: 1,
                    displacement: 4,
                    rip_relative: true,
                    rip_base: 0x1000,
                    segment: None,
                    address_size_32: false,
                    absolute_address: None,
                },
                width: 8,
            }],
        )];
        let error = optimize_function(&blocks, GuestArch::X64)
            .expect_err("RIP-relative memory is unsupported");
        assert_eq!(error.reason, "rip-relative memory");
    }
}
