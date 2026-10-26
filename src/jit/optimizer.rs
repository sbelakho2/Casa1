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

/// True when the first flag-related instruction in `block` reads flags (so a
/// predecessor must materialise them into `CpuState`).  A block that writes
/// flags first (CMP/TEST) does not need them on entry.
pub(super) fn block_reads_flags_before_write(block: &crate::jit_ssa::OptimizedBlock) -> bool {
    for insn in &block.instructions {
        match insn {
            IrInstruction::Compare { .. } | IrInstruction::Test { .. } => return false,
            IrInstruction::JumpIf { .. }
            | IrInstruction::Setcc { .. }
            | IrInstruction::SetccMemory { .. }
            | IrInstruction::Cmov { .. }
            | IrInstruction::AdcImm { .. }
            | IrInstruction::AdcOperand { .. }
            | IrInstruction::SbbImm { .. }
            | IrInstruction::SbbOperand { .. }
            | IrInstruction::PushFlags { .. }
            | IrInstruction::Lahf => return true,
            _ => {}
        }
    }
    // No flag writer in this block: the incoming flags are still guest-visible
    // at its exit, so a predecessor must have materialised them.
    true
}

pub(super) fn edge_reads_flags(
    target: u64,
    blocks: &[crate::jit_ssa::OptimizedBlock],
    by_address: &std::collections::HashMap<u64, usize>,
) -> bool {
    match by_address.get(&target) {
        Some(index) => block_reads_flags_before_write(&blocks[*index]),
        None => true,
    }
}

/// Return the index of a trailing CMP/TEST that feeds a terminating `Jcc`
/// with only spill bookkeeping after it.
pub(super) fn find_native_compare(block: &crate::jit_ssa::OptimizedBlock) -> Option<usize> {
    let condition = match &block.terminator {
        crate::jit_ssa::OptimizedTerminator::JumpIf { condition, .. } => *condition,
        _ => return None,
    };
    // Parity needs PF, which ARM NZCV does not carry: keep the helper path.
    arm_condition_for(condition)?;
    let mut candidate = None;
    for (index, insn) in block.instructions.iter().enumerate() {
        match insn {
            IrInstruction::Compare { width: 8, .. } | IrInstruction::Test { width: 8, .. } => {
                candidate = Some(index);
            }
            IrInstruction::SpillLoad { .. } | IrInstruction::SpillStore { .. } => {}
            _ => candidate = None,
        }
    }
    candidate.filter(|index| {
        block.instructions[index + 1..].iter().all(|insn| {
            matches!(
                insn,
                IrInstruction::SpillLoad { .. } | IrInstruction::SpillStore { .. }
            )
        })
    })
}

// ---------------------------------------------------------------------------
// Tiered Compilation
// ---------------------------------------------------------------------------

/// Compilation tier for the tiered JIT compiler.
///
/// Blocks start at Tier0 (fast compile, minimal optimization). As they get
/// hotter they are promoted to Tier1 (full optimization with register
/// allocation) and eventually Tier2 (aggressive optimization with inlining
/// and loop unrolling).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum CompilationTier {
    /// Fast compilation, minimal optimization — direct 1:1 IR-to-native.
    #[default]
    Tier0,
    /// Full optimization with register allocation, constant folding, dead
    /// code elimination.
    Tier1,
    /// Aggressive optimization with block inlining and loop unrolling.
    Tier2,
}

/// Manages tiered compilation by tracking execution counts and promoting
/// blocks to higher optimization tiers when they cross configured thresholds.
///
/// # Performance Impact
/// Tiered compilation reduces startup latency by compiling blocks quickly at
/// Tier0, then investing compile time in hot blocks at higher tiers where the
/// improved code quality pays off over many executions.
pub struct TieredCompiler {
    /// Execution count thresholds for tier promotion:
    /// `[Tier0→Tier1 threshold, Tier1→Tier2 threshold, unused]`.
    pub tier_thresholds: [u32; 3],
    /// Execution counts per block address.
    pub execution_counts: BTreeMap<u64, u32>,
    /// Current compilation tier per block address.
    pub current_tiers: BTreeMap<u64, CompilationTier>,
}

impl Default for TieredCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl TieredCompiler {
    /// Create a new `TieredCompiler` with default thresholds.
    ///
    /// Tier0→Tier1 at 50 executions, Tier1→Tier2 at 500 executions.
    pub fn new() -> Self {
        Self {
            tier_thresholds: [50, 500, u32::MAX],
            execution_counts: BTreeMap::new(),
            current_tiers: BTreeMap::new(),
        }
    }

    /// Create a `TieredCompiler` with custom thresholds.
    pub fn with_thresholds(tier0_to_tier1: u32, tier1_to_tier2: u32) -> Self {
        Self {
            tier_thresholds: [tier0_to_tier1, tier1_to_tier2, u32::MAX],
            execution_counts: BTreeMap::new(),
            current_tiers: BTreeMap::new(),
        }
    }

    /// Record an execution of the block at `block_address`.
    ///
    /// Increments the execution counter and returns `Some(new_tier)` if the
    /// block should be promoted to a higher tier, or `None` if no promotion
    /// is warranted.
    pub fn record_execution(&mut self, block_address: u64) -> Option<CompilationTier> {
        let count = self.execution_counts.entry(block_address).or_insert(0);
        *count += 1;

        let current_tier = self
            .current_tiers
            .get(&block_address)
            .copied()
            .unwrap_or(CompilationTier::Tier0);

        let new_tier = match current_tier {
            CompilationTier::Tier0 if *count >= self.tier_thresholds[0] => {
                Some(CompilationTier::Tier1)
            }
            CompilationTier::Tier1 if *count >= self.tier_thresholds[1] => {
                Some(CompilationTier::Tier2)
            }
            _ => None,
        };

        if let Some(tier) = new_tier {
            self.current_tiers.insert(block_address, tier);
        }

        new_tier
    }

    /// Get the current tier for a block.
    pub fn get_tier(&self, block_address: u64) -> CompilationTier {
        self.current_tiers
            .get(&block_address)
            .copied()
            .unwrap_or(CompilationTier::Tier0)
    }

    /// Get the execution count for a block.
    pub fn get_count(&self, block_address: u64) -> u32 {
        self.execution_counts
            .get(&block_address)
            .copied()
            .unwrap_or(0)
    }

    /// Reset tier data for a specific block (e.g., after invalidation).
    pub fn reset_block(&mut self, block_address: u64) {
        self.execution_counts.remove(&block_address);
        self.current_tiers.remove(&block_address);
    }
}

/// Internal enum for tracking known register values during constant folding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum KnownValue {
    Immediate(u64),
    RegisterCopy(Register),
    #[allow(dead_code)]
    KnownHighLow {
        high: u64,
        low: u64,
    },
}

// ---------------------------------------------------------------------------
// Adaptive Instruction Budget
// ---------------------------------------------------------------------------

/// Dynamically adjusts the number of instructions compiled per JIT block based
/// on measured execution time.
///
/// # Performance Impact
/// Prevents JIT blocks from growing too large (which increases compile time
/// and reduces instruction-cache locality) or too small (which increases
/// dispatcher overhead). The adaptive budget converges on a block size that
/// balances compile time against execution throughput.
#[derive(Debug)]
pub struct AdaptiveBudget {
    /// Starting instruction budget per block.
    pub base_budget: u32,
    /// Current instruction budget.
    pub current_budget: u32,
    /// Minimum allowed budget.
    pub min_budget: u32,
    /// Maximum allowed budget.
    pub max_budget: u32,
    /// Target block execution time in microseconds.
    pub target_time_us: u64,
    /// Last measured execution time in microseconds.
    pub last_execution_time_us: u64,
    /// How aggressively to adjust (0.0–1.0, higher = more aggressive).
    pub adjustment_factor: f64,
}

impl AdaptiveBudget {
    /// Create a new adaptive budget controller.
    ///
    /// - `base`: Starting instruction budget per block.
    /// - `min`: Minimum allowed budget.
    /// - `max`: Maximum allowed budget.
    /// - `target_us`: Target block execution time in microseconds.
    pub fn new(base: u32, min: u32, max: u32, target_us: u64) -> Self {
        Self {
            base_budget: base,
            current_budget: base,
            min_budget: min,
            max_budget: max,
            target_time_us: target_us,
            last_execution_time_us: 0,
            adjustment_factor: 0.5,
        }
    }

    /// Record a block execution time and adjust the budget accordingly.
    ///
    /// If execution time exceeds `target * 1.5`, the budget is reduced to
    /// make blocks smaller. If execution time is below `target * 0.5`, the
    /// budget is increased to allow more instructions per block.
    pub fn record_execution(&mut self, time_us: u64) {
        self.last_execution_time_us = time_us;

        let target = self.target_time_us as f64;
        let measured = time_us as f64;
        let factor = self.adjustment_factor;

        if measured > target * 1.5 {
            // Too slow — reduce budget
            let reduction =
                ((measured / target - 1.0) * factor * self.current_budget as f64) as u32;
            let reduction = reduction.max(1);
            self.current_budget =
                (self.current_budget.saturating_sub(reduction)).max(self.min_budget);
        } else if measured < target * 0.5 {
            // Too fast — increase budget
            let increase = ((1.0 - measured / target) * factor * self.current_budget as f64) as u32;
            let increase = increase.max(1);
            self.current_budget =
                (self.current_budget.saturating_add(increase)).min(self.max_budget);
        }
    }

    /// Get the current instruction budget.
    pub fn get_budget(&self) -> u32 {
        self.current_budget
    }

    /// Reset the budget to the base value.
    pub fn reset(&mut self) {
        self.current_budget = self.base_budget;
        self.last_execution_time_us = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// Optimizer Configuration
// ---------------------------------------------------------------------------

/// Configuration for the JIT optimizer passes.
///
/// Controls constant folding and loop unrolling behavior with sensible
/// defaults suitable for most workloads.
#[derive(Debug, Clone)]
pub struct OptimizerConfig {
    /// Enable constant folding (Tier1+). Default: true.
    pub enable_constant_folding: bool,
    /// Enable loop unrolling (Tier2 only). Default: true.
    pub enable_loop_unrolling: bool,
    /// Maximum unroll factor (loop body duplications). Default: 2.
    pub max_unroll_factor: usize,
    /// Test mode: enables verification checks. Default: false.
    pub test_mode: bool,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            enable_constant_folding: true,
            enable_loop_unrolling: true,
            max_unroll_factor: 2,
            test_mode: false,
        }
    }
}

impl OptimizerConfig {
    /// Create a new optimizer configuration with the given parameters.
    pub fn new(
        enable_constant_folding: bool,
        enable_loop_unrolling: bool,
        max_unroll_factor: usize,
    ) -> Self {
        Self {
            enable_constant_folding,
            enable_loop_unrolling,
            max_unroll_factor,
            test_mode: false,
        }
    }

    /// Enable test mode for verifying optimization results.
    pub fn with_test_mode(mut self) -> Self {
        self.test_mode = true;
        self
    }

    /// Create a config that disables all optimizations (for Tier0).
    pub fn disabled() -> Self {
        Self {
            enable_constant_folding: false,
            enable_loop_unrolling: false,
            max_unroll_factor: 1,
            test_mode: false,
        }
    }

    /// Create a config for Tier1 (constant folding only).
    pub fn tier1() -> Self {
        Self {
            enable_constant_folding: true,
            enable_loop_unrolling: false,
            max_unroll_factor: 1,
            test_mode: false,
        }
    }

    /// Create a config for Tier2 (constant folding + loop unrolling).
    pub fn tier2() -> Self {
        Self::default()
    }
}
