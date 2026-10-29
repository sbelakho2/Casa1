//! Performance optimization for Casa1.
//!
//! Implements block chaining, lazy JIT compilation, memory access translation
//! cache, parallel shader compilation, Metal command batching, GPU upload
//! streaming, and frame pacing for AAA game performance targeting 60 FPS.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ===========================================================================
// Owner-barrier / API-dispatch KPI ingestion
// ===========================================================================

/// Environment variable naming the JSON document written by the runner at
/// exit.  The perf harness never reads runtime memory directly; it only
/// consumes this stable on-disk contract.
pub const DISPATCH_STATS_ENV: &str = "CASA1_DISPATCH_STATS";

/// Schema version of the dispatch-stats document.
pub const DISPATCH_STATS_SCHEMA: u64 = 1;

/// Why an owner-barrier KPI cannot be reported.  Every variant carries the
/// exact, user-visible reason; no ratio is ever synthesized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchStatsUnavailable {
    /// The runner was not asked to write the document.
    NotRequested,
    /// The configured document does not exist.
    Absent(PathBuf),
    /// The document exists but could not be read.
    Unreadable { path: PathBuf, detail: String },
    /// The document is not valid JSON or is not a JSON object.
    Malformed { path: PathBuf, detail: String },
    /// The document declares a schema this harness does not understand.
    UnsupportedSchema { path: PathBuf, schema: u64 },
    /// A required field is absent or has the wrong JSON type.
    MissingField { path: PathBuf, field: &'static str },
    /// A field is present but semantically invalid.
    InvalidField {
        path: PathBuf,
        field: &'static str,
        detail: String,
    },
    /// The document is valid but recorded no host-thunk dispatches.
    ZeroDispatches { path: PathBuf },
}

impl DispatchStatsUnavailable {
    /// Exact human-readable reason used in both the KPI document and the gate
    /// report.
    pub fn reason(&self) -> String {
        match self {
            Self::NotRequested => format!(
                "{DISPATCH_STATS_ENV} is not set; owner-barrier dispatch statistics are unavailable"
            ),
            Self::Absent(path) => {
                format!("dispatch statistics file {} does not exist", path.display())
            }
            Self::Unreadable { path, detail } => format!(
                "dispatch statistics file {} is unreadable: {detail}",
                path.display()
            ),
            Self::Malformed { path, detail } => format!(
                "dispatch statistics file {} is malformed: {detail}",
                path.display()
            ),
            Self::UnsupportedSchema { path, schema } => format!(
                "dispatch statistics file {} uses unsupported schema {schema} (expected {DISPATCH_STATS_SCHEMA})",
                path.display()
            ),
            Self::MissingField { path, field } => format!(
                "dispatch statistics file {} is partial: required field `{field}` is missing or not an unsigned integer",
                path.display()
            ),
            Self::InvalidField {
                path,
                field,
                detail,
            } => format!(
                "dispatch statistics file {} has invalid `{field}`: {detail}",
                path.display()
            ),
            Self::ZeroDispatches { path } => format!(
                "dispatch statistics file {} recorded zero host-thunk dispatches; owner-barrier ratio is undefined",
                path.display()
            ),
        }
    }
}

/// One category's dispatch accounting from the runtime snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchCategoryStats {
    pub dispatched: u64,
    pub fallbacks: u64,
}

/// Parsed owner-barrier statistics document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchStats {
    pub parallel_dispatched: u64,
    pub barrier_calls: u64,
    pub stateless_dispatched: u64,
    pub read_mostly_dispatched: u64,
    pub owner_only_barriers: u64,
    pub fallback_barriers: u64,
    pub categories: BTreeMap<String, DispatchCategoryStats>,
    pub barrier_reasons: BTreeMap<String, u64>,
    pub guest_instructions: Option<u64>,
    pub wall_ns: Option<u64>,
}

impl DispatchStats {
    pub fn total_dispatches(&self) -> u64 {
        self.parallel_dispatched.saturating_add(self.barrier_calls)
    }

    /// Fraction of host-thunk dispatches that crossed the owner barrier.
    pub fn owner_barrier_ratio(&self) -> Option<f64> {
        let total = self.total_dispatches();
        (total > 0).then(|| self.barrier_calls as f64 / total as f64)
    }

    /// Fraction of host-thunk dispatches serviced on a worker.
    pub fn parallel_dispatch_ratio(&self) -> Option<f64> {
        let total = self.total_dispatches();
        (total > 0).then(|| self.parallel_dispatched as f64 / total as f64)
    }

    /// Wall time spent per 1000 retired guest instructions.
    pub fn time_per_1000_guest_instructions_ns(&self) -> Option<f64> {
        match (self.wall_ns, self.guest_instructions) {
            (Some(wall_ns), Some(instructions)) if wall_ns > 0 && instructions > 0 => {
                Some(wall_ns as f64 * 1_000.0 / instructions as f64)
            }
            _ => None,
        }
    }

    /// Stable JSON representation, shared by the runner writer and the
    /// harness reader.
    pub fn to_json(&self) -> serde_json::Value {
        let categories = self
            .categories
            .iter()
            .map(|(name, stats)| {
                (
                    name.clone(),
                    serde_json::json!({
                        "dispatched": stats.dispatched,
                        "fallbacks": stats.fallbacks,
                    }),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();
        serde_json::json!({
            "schema": DISPATCH_STATS_SCHEMA,
            "source": "casa1-api-dispatch",
            "parallel_dispatched": self.parallel_dispatched,
            "barrier_calls": self.barrier_calls,
            "stateless_dispatched": self.stateless_dispatched,
            "read_mostly_dispatched": self.read_mostly_dispatched,
            "owner_only_barriers": self.owner_only_barriers,
            "fallback_barriers": self.fallback_barriers,
            "owner_barrier_ratio": self.owner_barrier_ratio(),
            "parallel_dispatch_ratio": self.parallel_dispatch_ratio(),
            "categories": categories,
            "barrier_reasons": self.barrier_reasons,
            "guest_instructions": self.guest_instructions,
            "wall_ns": self.wall_ns,
            "time_per_1000_guest_instructions_ns": self
                .time_per_1000_guest_instructions_ns(),
        })
    }

    fn from_runtime_snapshot(
        snapshot: &crate::runtime::ApiDispatchSnapshot,
        guest_instructions: u64,
        wall_ns: u64,
    ) -> Self {
        let mut categories = BTreeMap::new();
        for (category, dispatched, fallbacks) in &snapshot.categories {
            categories.insert(
                category.as_str().to_string(),
                DispatchCategoryStats {
                    dispatched: *dispatched,
                    fallbacks: *fallbacks,
                },
            );
        }
        let mut barrier_reasons = BTreeMap::new();
        for (reason, count) in &snapshot.fallbacks {
            barrier_reasons.insert(reason.as_str().to_string(), *count);
        }
        Self {
            parallel_dispatched: snapshot.totals.parallel_dispatched,
            barrier_calls: snapshot.totals.barrier_calls,
            stateless_dispatched: snapshot.totals.stateless_dispatched,
            read_mostly_dispatched: snapshot.totals.read_mostly_dispatched,
            owner_only_barriers: snapshot.totals.owner_only_barriers,
            fallback_barriers: snapshot.totals.fallback_barriers,
            categories,
            barrier_reasons,
            guest_instructions: (guest_instructions > 0).then_some(guest_instructions),
            wall_ns: (wall_ns > 0).then_some(wall_ns),
        }
    }
}

/// Result of reading the dispatch-stats contract: either a parsed document or
/// the exact reason it is unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchStatsReport {
    pub stats: Option<DispatchStats>,
    pub unavailable: Option<DispatchStatsUnavailable>,
}

impl DispatchStatsReport {
    /// Read [`DISPATCH_STATS_ENV`].  An unset variable is an explicit
    /// not-requested result, not a fabricated zero.
    pub fn from_env() -> Self {
        match std::env::var_os(DISPATCH_STATS_ENV) {
            Some(path) if !path.is_empty() => Self::from_path(Path::new(&path)),
            _ => Self {
                stats: None,
                unavailable: Some(DispatchStatsUnavailable::NotRequested),
            },
        }
    }

    /// Read and validate a dispatch-stats document.
    pub fn from_path(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Self {
                    stats: None,
                    unavailable: Some(DispatchStatsUnavailable::Absent(path.to_path_buf())),
                };
            }
            Err(error) => {
                return Self {
                    stats: None,
                    unavailable: Some(DispatchStatsUnavailable::Unreadable {
                        path: path.to_path_buf(),
                        detail: error.to_string(),
                    }),
                };
            }
        };
        match Self::from_json(path, &text) {
            Ok(stats) => Self {
                stats: Some(stats),
                unavailable: None,
            },
            Err(reason) => Self {
                stats: None,
                unavailable: Some(reason),
            },
        }
    }

    fn from_json(path: &Path, text: &str) -> Result<DispatchStats, DispatchStatsUnavailable> {
        let document: serde_json::Value =
            serde_json::from_str(text).map_err(|error| DispatchStatsUnavailable::Malformed {
                path: path.to_path_buf(),
                detail: error.to_string(),
            })?;
        let object = document
            .as_object()
            .ok_or_else(|| DispatchStatsUnavailable::Malformed {
                path: path.to_path_buf(),
                detail: "top-level JSON value is not an object".to_string(),
            })?;
        let schema = object
            .get("schema")
            .and_then(serde_json::Value::as_u64)
            .ok_or(DispatchStatsUnavailable::MissingField {
                path: path.to_path_buf(),
                field: "schema",
            })?;
        if schema != DISPATCH_STATS_SCHEMA {
            return Err(DispatchStatsUnavailable::UnsupportedSchema {
                path: path.to_path_buf(),
                schema,
            });
        }
        let parallel_dispatched = required_u64(object, path, "parallel_dispatched")?;
        let barrier_calls = required_u64(object, path, "barrier_calls")?;
        let stateless_dispatched = optional_u64(object, path, "stateless_dispatched")?;
        let read_mostly_dispatched = optional_u64(object, path, "read_mostly_dispatched")?;
        let owner_only_barriers = optional_u64(object, path, "owner_only_barriers")?;
        let fallback_barriers = optional_u64(object, path, "fallback_barriers")?;

        let mut categories = BTreeMap::new();
        if let Some(value) = object.get("categories") {
            let map = value
                .as_object()
                .ok_or_else(|| DispatchStatsUnavailable::InvalidField {
                    path: path.to_path_buf(),
                    field: "categories",
                    detail: "expected an object keyed by category".to_string(),
                })?;
            for (name, category) in map {
                let category =
                    category
                        .as_object()
                        .ok_or_else(|| DispatchStatsUnavailable::InvalidField {
                            path: path.to_path_buf(),
                            field: "categories",
                            detail: format!("category `{name}` is not an object"),
                        })?;
                categories.insert(
                    name.clone(),
                    DispatchCategoryStats {
                        dispatched: required_u64(category, path, "dispatched")?,
                        fallbacks: required_u64(category, path, "fallbacks")?,
                    },
                );
            }
        }
        let mut barrier_reasons = BTreeMap::new();
        if let Some(value) = object.get("barrier_reasons") {
            let map = value
                .as_object()
                .ok_or_else(|| DispatchStatsUnavailable::InvalidField {
                    path: path.to_path_buf(),
                    field: "barrier_reasons",
                    detail: "expected an object keyed by fallback reason".to_string(),
                })?;
            for (name, count) in map {
                let count =
                    count
                        .as_u64()
                        .ok_or_else(|| DispatchStatsUnavailable::InvalidField {
                            path: path.to_path_buf(),
                            field: "barrier_reasons",
                            detail: format!("reason `{name}` is not an unsigned integer"),
                        })?;
                barrier_reasons.insert(name.clone(), count);
            }
        }
        let guest_instructions = optional_optional_u64(object, path, "guest_instructions")?;
        let wall_ns = optional_optional_u64(object, path, "wall_ns")?;
        let stats = DispatchStats {
            parallel_dispatched,
            barrier_calls,
            stateless_dispatched,
            read_mostly_dispatched,
            owner_only_barriers,
            fallback_barriers,
            categories,
            barrier_reasons,
            guest_instructions,
            wall_ns,
        };
        if stats.total_dispatches() == 0 {
            return Err(DispatchStatsUnavailable::ZeroDispatches {
                path: path.to_path_buf(),
            });
        }
        Ok(stats)
    }

    /// KPI entries for the benchmark document.  An unavailable document
    /// produces `available: false` entries with the exact reason.
    pub fn to_json_metrics(&self) -> BTreeMap<String, serde_json::Value> {
        let mut metrics = BTreeMap::new();
        let source = "runner CASA1_DISPATCH_STATS ApiDispatchSnapshot";
        let unavailable_reason = self.unavailable.as_ref().map(|reason| reason.reason());
        for (key, value, unit) in [
            (
                "owner_barrier_ratio",
                self.stats
                    .as_ref()
                    .and_then(DispatchStats::owner_barrier_ratio),
                "owner-barrier dispatches/(parallel+barrier)",
            ),
            (
                "time_per_1000_guest_instructions_ns",
                self.stats
                    .as_ref()
                    .and_then(DispatchStats::time_per_1000_guest_instructions_ns),
                "ns/1000 guest instructions",
            ),
        ] {
            match value {
                Some(value) if value.is_finite() => {
                    metrics.insert(
                        key.to_string(),
                        serde_json::json!({
                            "available": true,
                            "value": value,
                            "unit": unit,
                            "direction": "lower",
                            "source": source,
                        }),
                    );
                }
                _ => {
                    let reason = match (&self.stats, key) {
                        (Some(stats), "owner_barrier_ratio")
                            if stats.total_dispatches() == 0 =>
                        {
                            "dispatch statistics recorded zero host-thunk dispatches; owner-barrier ratio is undefined".to_string()
                        }
                        (Some(stats), "time_per_1000_guest_instructions_ns")
                            if stats.guest_instructions.unwrap_or(0) == 0
                                || stats.wall_ns.unwrap_or(0) == 0 =>
                        {
                            "dispatch statistics did not record both wall time and guest instructions; time per 1000 guest instructions is unavailable".to_string()
                        }
                        _ => unavailable_reason
                            .clone()
                            .unwrap_or_else(|| "dispatch statistic is unavailable".to_string()),
                    };
                    metrics.insert(
                        key.to_string(),
                        serde_json::json!({
                            "available": false,
                            "reason": reason,
                            "source": source,
                        }),
                    );
                }
            }
        }
        metrics
    }

    /// Stable JSON block for the KPI/perf report.  Unavailable reports carry
    /// the exact reason instead of a zero ratio.
    pub fn to_json(&self) -> serde_json::Value {
        match &self.stats {
            Some(stats) => {
                let mut value = stats.to_json();
                if let Some(object) = value.as_object_mut() {
                    object.insert("available".to_string(), serde_json::Value::Bool(true));
                }
                value
            }
            None => serde_json::json!({
                "schema": DISPATCH_STATS_SCHEMA,
                "available": false,
                "reason": self
                    .unavailable
                    .as_ref()
                    .map(DispatchStatsUnavailable::reason)
                    .unwrap_or_else(|| "dispatch statistics are unavailable".to_string()),
                "owner_barrier_ratio": serde_json::Value::Null,
                "barrier_reasons": {},
                "time_per_1000_guest_instructions_ns": serde_json::Value::Null,
            }),
        }
    }

    /// Human-readable lines for the perf harness output.
    pub fn human_lines(&self) -> Vec<String> {
        let Some(stats) = &self.stats else {
            return vec![format!(
                "unavailable: {}",
                self.unavailable
                    .as_ref()
                    .map(DispatchStatsUnavailable::reason)
                    .unwrap_or_else(|| "dispatch statistics are unavailable".to_string())
            )];
        };
        let ratio = stats.owner_barrier_ratio().map_or_else(
            || "unavailable (zero dispatches)".to_string(),
            |ratio| format!("{ratio:.6}"),
        );
        let time = stats.time_per_1000_guest_instructions_ns().map_or_else(
            || "unavailable (no guest-instruction sample)".to_string(),
            |value| format!("{value:.3} ns"),
        );
        let reasons = stats
            .barrier_reasons
            .iter()
            .map(|(reason, count)| format!("{reason}:{count}"))
            .collect::<Vec<_>>()
            .join(",");
        vec![
            format!(
                "parallel={} barrier={} owner_barrier_ratio={ratio}",
                stats.parallel_dispatched, stats.barrier_calls
            ),
            format!("barrier_reasons=[{reasons}]"),
            format!("time_per_1000_guest_instructions={time}"),
        ]
    }
}

fn required_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &Path,
    field: &'static str,
) -> Result<u64, DispatchStatsUnavailable> {
    object.get(field).and_then(serde_json::Value::as_u64).ok_or(
        DispatchStatsUnavailable::MissingField {
            path: path.to_path_buf(),
            field,
        },
    )
}

fn optional_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &Path,
    field: &'static str,
) -> Result<u64, DispatchStatsUnavailable> {
    match object.get(field) {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| DispatchStatsUnavailable::InvalidField {
                path: path.to_path_buf(),
                field,
                detail: "expected an unsigned integer".to_string(),
            }),
    }
}

fn optional_optional_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &Path,
    field: &'static str,
) -> Result<Option<u64>, DispatchStatsUnavailable> {
    match object.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => {
            value
                .as_u64()
                .map(Some)
                .ok_or_else(|| DispatchStatsUnavailable::InvalidField {
                    path: path.to_path_buf(),
                    field,
                    detail: "expected an unsigned integer or null".to_string(),
                })
        }
    }
}

/// Runner-side writer: when [`DISPATCH_STATS_ENV`] names a file, serialize the
/// runtime's own dispatch snapshot at exit.  This function never invents
/// counters; a zero-dispatch run writes a real zero document and the harness
/// reports the ratio as undefined.
pub(crate) fn write_dispatch_stats_if_requested(
    shared: &crate::runtime::ProcessShared,
    guest_instructions: u64,
    wall_ns: u64,
) {
    let Some(path) = std::env::var_os(DISPATCH_STATS_ENV) else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let snapshot = shared.api_dispatch_snapshot();
    let stats = DispatchStats::from_runtime_snapshot(&snapshot, guest_instructions, wall_ns);
    if let Ok(text) = serde_json::to_string_pretty(&stats.to_json()) {
        let _ = std::fs::write(PathBuf::from(path), text);
    }
}

/// Why a native-relative ratio cannot be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRatioUnavailable {
    Casa1Unavailable,
    NativeUnavailable,
    Casa1ZeroTime,
    NativeZeroTime,
}

impl NativeRatioUnavailable {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Casa1Unavailable => {
                "Casa1 guest workload is unavailable; native-relative ratio refused"
            }
            Self::NativeUnavailable => {
                "native reference workload is unavailable; native-relative ratio refused"
            }
            Self::Casa1ZeroTime => {
                "Casa1 guest workload measured zero wall time; native-relative ratio refused"
            }
            Self::NativeZeroTime => {
                "native reference measured zero wall time; native-relative ratio refused"
            }
        }
    }
}

/// `casa1_time / native_time` for the native-relative lane.  Both sides must
/// be available and non-zero; otherwise the ratio is refused with an exact
/// reason instead of dividing by zero or substituting a placeholder.
pub fn native_relative_ratio(
    casa1_available: bool,
    casa1_wall_ns: u64,
    native_available: bool,
    native_wall_ns: u64,
) -> Result<f64, NativeRatioUnavailable> {
    if !casa1_available {
        return Err(NativeRatioUnavailable::Casa1Unavailable);
    }
    if !native_available {
        return Err(NativeRatioUnavailable::NativeUnavailable);
    }
    if casa1_wall_ns == 0 {
        return Err(NativeRatioUnavailable::Casa1ZeroTime);
    }
    if native_wall_ns == 0 {
        return Err(NativeRatioUnavailable::NativeZeroTime);
    }
    Ok(casa1_wall_ns as f64 / native_wall_ns as f64)
}

// ===========================================================================
// Block Chaining
// ===========================================================================

/// A translated block in the JIT cache.
#[derive(Debug, Clone)]
pub struct TranslatedBlock {
    /// Guest address of the block entry.
    pub guest_address: u64,
    /// Host address of the translated code.
    pub host_address: u64,
    /// Size of the translated code in bytes.
    pub code_size: usize,
    /// Number of times this block has been executed.
    pub execution_count: u64,
    /// Guest address of the likely successor block (for chaining).
    pub fallthrough_target: Option<u64>,
    /// Whether this block has been patched with a chain to its successor.
    pub is_chained: bool,
    /// Instruction count in this block.
    pub instruction_count: usize,
}

/// Block chain link: connects two translated blocks.
#[derive(Debug, Clone)]
pub struct BlockChain {
    pub from_address: u64,
    pub to_address: u64,
    pub patch_offset: usize,
    pub is_active: bool,
}

/// Manages block chaining for the JIT compiler.
///
/// Block chaining eliminates the interpreter dispatch overhead between
/// translated blocks by patching the exit of one block to jump directly
/// to the entry of the next block.
pub struct BlockChainingCache {
    blocks: HashMap<u64, TranslatedBlock>,
    chains: Vec<BlockChain>,
    total_chains_active: u64,
    total_chains_broken: u64,
}

impl BlockChainingCache {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            chains: Vec::new(),
            total_chains_active: 0,
            total_chains_broken: 0,
        }
    }

    /// Register a translated block.
    pub fn register_block(
        &mut self,
        guest_address: u64,
        host_address: u64,
        code_size: usize,
        instruction_count: usize,
    ) {
        self.blocks.insert(
            guest_address,
            TranslatedBlock {
                guest_address,
                host_address,
                code_size,
                execution_count: 0,
                fallthrough_target: None,
                is_chained: false,
                instruction_count,
            },
        );
    }

    /// Record a block execution and attempt chaining.
    pub fn record_execution(&mut self, guest_address: u64, next_address: u64) -> AppResult<()> {
        // First, read the current state
        let (is_chained, current_target) = {
            let block = self.blocks.get(&guest_address).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("block at {guest_address:#x} not found"),
                )
            })?;
            (block.is_chained, block.fallthrough_target)
        };

        // Break chain if target changed and currently chained
        if current_target != Some(next_address) && is_chained {
            self.break_chain(guest_address);
        }

        // Update the block
        let block = self.blocks.get_mut(&guest_address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("block at {guest_address:#x} not found"),
            )
        })?;
        block.execution_count += 1;
        block.fallthrough_target = Some(next_address);

        Ok(())
    }

    /// Try to chain a block to its fallthrough target.
    ///
    /// Returns true if chaining was successful.
    pub fn try_chain(&mut self, guest_address: u64) -> bool {
        let block = match self.blocks.get(&guest_address) {
            // Already chained: never push a duplicate chain entry.
            Some(block) if !block.is_chained => block,
            _ => return false,
        };
        let target_address = match block.fallthrough_target {
            Some(addr) => addr,
            None => return false,
        };

        // Check if target block exists
        if !self.blocks.contains_key(&target_address) {
            return false;
        }

        // Check if execution count is high enough (hot path)
        if block.execution_count < 10 {
            return false;
        }

        // Create chain
        let patch_offset = self.compute_patch_offset(guest_address, target_address);
        let chain = BlockChain {
            from_address: guest_address,
            to_address: target_address,
            patch_offset,
            is_active: true,
        };
        self.chains.push(chain);
        self.total_chains_active += 1;

        if let Some(block) = self.blocks.get_mut(&guest_address) {
            block.is_chained = true;
        }

        true
    }

    /// Break an existing chain from a block.
    ///
    /// Inactive chains are pruned immediately so the `chains` vector stays
    /// bounded and breaks stay cheap.
    pub fn break_chain(&mut self, from_address: u64) {
        self.chains.retain(|chain| {
            if chain.from_address == from_address && chain.is_active {
                self.total_chains_broken += 1;
                false
            } else {
                true
            }
        });
        if let Some(block) = self.blocks.get_mut(&from_address) {
            block.is_chained = false;
        }
    }

    /// Get a block by guest address.
    pub fn get_block(&self, guest_address: u64) -> Option<&TranslatedBlock> {
        self.blocks.get(&guest_address)
    }

    /// Get the total number of registered blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get the number of active chains.
    pub fn active_chain_count(&self) -> usize {
        self.chains.iter().filter(|c| c.is_active).count()
    }

    /// Get the total chains created.
    pub fn total_chains_created(&self) -> u64 {
        self.total_chains_active
    }

    /// Get the total chains broken.
    pub fn total_chains_broken(&self) -> u64 {
        self.total_chains_broken
    }

    /// Get hot blocks (execution count above threshold).
    pub fn hot_blocks(&self, threshold: u64) -> Vec<&TranslatedBlock> {
        self.blocks
            .values()
            .filter(|b| b.execution_count >= threshold)
            .collect()
    }

    /// Compute the patch offset from one block to its target.
    ///
    /// Returns the difference between the end of `from_address`'s code and the
    /// start of `patch_target`'s code. Falls back to 0 if either block is not found.
    pub fn compute_patch_offset(&self, from_address: u64, patch_target: u64) -> usize {
        if let Some(target_block) = self.blocks.get(&patch_target) {
            if let Some(from_block) = self.blocks.get(&from_address) {
                // The patch offset is the distance from the end of the current block
                // to the start of the target block's host code.
                let from_end = from_block
                    .host_address
                    .saturating_add(from_block.code_size as u64);
                if from_end <= target_block.host_address {
                    (target_block.host_address - from_end) as usize
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Invalidate all blocks and chains (e.g., on self-modifying code).
    pub fn invalidate_all(&mut self) {
        self.blocks.clear();
        self.chains.clear();
    }

    /// Invalidate blocks in a specific address range.
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        let to_remove: Vec<u64> = self
            .blocks
            .keys()
            .filter(|&&addr| addr >= start && addr < end)
            .copied()
            .collect();

        for addr in &to_remove {
            self.break_chain(*addr);
        }
        // Deactivate and prune chains whose *target* block was invalidated
        // even when the source block survived the range, so no chain points
        // at removed code.
        let in_range = |addr: u64| addr >= start && addr < end;
        self.chains.retain(|chain| {
            if chain.is_active && (in_range(chain.from_address) || in_range(chain.to_address)) {
                self.total_chains_broken += 1;
                false
            } else {
                true
            }
        });

        for addr in to_remove {
            self.blocks.remove(&addr);
        }
    }
}

impl Default for BlockChainingCache {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Lazy JIT Compilation
// ===========================================================================

/// Compilation tier for lazy JIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilationTier {
    /// Not yet compiled — will be interpreted.
    Uncompiled,
    /// Compiled with minimal optimization (tier 1).
    Baseline,
    /// Compiled with full optimization (tier 2).
    Optimized,
}

/// Profile data for a guest code block.
#[derive(Debug, Clone)]
pub struct BlockProfile {
    pub guest_address: u64,
    pub execution_count: u64,
    pub tier: CompilationTier,
    pub last_compiled: Option<Instant>,
    pub compile_time_us: u64,
    pub instruction_count: usize,
}

/// Lazy JIT compiler with profile-guided tiered compilation.
///
/// Blocks start uncompiled (interpreted). After exceeding the hot threshold,
/// they are compiled at the baseline tier. After exceeding the optimization
/// threshold, they are recompiled at the optimized tier.
pub struct LazyJitProfiler {
    profiles: HashMap<u64, BlockProfile>,
    /// Execution count threshold for baseline compilation.
    hot_threshold: u64,
    /// Execution count threshold for optimized compilation.
    optimize_threshold: u64,
    /// Total time spent compiling (microseconds).
    total_compile_time_us: AtomicU64,
    /// Number of blocks compiled.
    total_compiled: AtomicU32,
}

impl LazyJitProfiler {
    pub fn new(hot_threshold: u64, optimize_threshold: u64) -> Self {
        Self {
            profiles: HashMap::new(),
            hot_threshold,
            optimize_threshold,
            total_compile_time_us: AtomicU64::new(0),
            total_compiled: AtomicU32::new(0),
        }
    }

    /// Record a block execution. Returns the recommended compilation tier.
    pub fn record_execution(
        &mut self,
        guest_address: u64,
        instruction_count: usize,
    ) -> CompilationTier {
        let profile = self
            .profiles
            .entry(guest_address)
            .or_insert_with(|| BlockProfile {
                guest_address,
                execution_count: 0,
                tier: CompilationTier::Uncompiled,
                last_compiled: None,
                compile_time_us: 0,
                instruction_count,
            });

        profile.execution_count += 1;

        if profile.execution_count >= self.optimize_threshold {
            CompilationTier::Optimized
        } else if profile.execution_count >= self.hot_threshold {
            CompilationTier::Baseline
        } else {
            CompilationTier::Uncompiled
        }
    }

    /// Mark a block as compiled at a given tier.
    pub fn mark_compiled(
        &mut self,
        guest_address: u64,
        tier: CompilationTier,
        compile_time_us: u64,
    ) {
        self.total_compile_time_us
            .fetch_add(compile_time_us, Ordering::Relaxed);
        self.total_compiled.fetch_add(1, Ordering::Relaxed);
        if let Some(profile) = self.profiles.get_mut(&guest_address) {
            profile.tier = tier;
            profile.last_compiled = Some(Instant::now());
            profile.compile_time_us += compile_time_us;
        }
    }

    /// Get the profile for a block.
    pub fn get_profile(&self, guest_address: u64) -> Option<&BlockProfile> {
        self.profiles.get(&guest_address)
    }

    /// Get the compilation tier for a block.
    pub fn get_tier(&self, guest_address: u64) -> CompilationTier {
        self.profiles
            .get(&guest_address)
            .map(|p| p.tier)
            .unwrap_or(CompilationTier::Uncompiled)
    }

    /// Get the total number of profiled blocks.
    pub fn profiled_count(&self) -> usize {
        self.profiles.len()
    }

    /// Get the number of blocks at each tier.
    pub fn tier_counts(&self) -> (usize, usize, usize) {
        let mut uncompiled = 0;
        let mut baseline = 0;
        let mut optimized = 0;
        for profile in self.profiles.values() {
            match profile.tier {
                CompilationTier::Uncompiled => uncompiled += 1,
                CompilationTier::Baseline => baseline += 1,
                CompilationTier::Optimized => optimized += 1,
            }
        }
        (uncompiled, baseline, optimized)
    }

    /// Get the total compile time in microseconds.
    pub fn total_compile_time_us(&self) -> u64 {
        self.total_compile_time_us.load(Ordering::Relaxed)
    }

    /// Get the total number of compiled blocks.
    pub fn total_compiled(&self) -> u32 {
        self.total_compiled.load(Ordering::Relaxed)
    }
}

// ===========================================================================
// Memory Access Translation Cache
// ===========================================================================

/// A cached guest-to-host address translation.
#[derive(Debug, Clone)]
pub struct AddressTranslation {
    pub guest_address: u64,
    pub host_address: u64,
    pub size: usize,
    pub protection: u32,
    pub hits: u64,
    /// Access count for LRU eviction tracking.
    pub access_count: u64,
}

/// Cache for guest-to-host address translations.
///
/// Avoids repeated page table walks by caching the most recent translations.
/// Eviction uses a clock (second-chance) scan over a `VecDeque` of keys, so
/// inserts are amortized O(1) instead of rescanning every entry.
pub struct AddressTranslationCache {
    translations: HashMap<u64, AddressTranslation>,
    /// Clock/second-chance order of keys (front = next eviction candidate).
    order: VecDeque<u64>,
    /// Reference bits for the clock hand.
    referenced: HashMap<u64, bool>,
    /// Maximum cache entries before eviction.
    max_entries: usize,
    total_hits: AtomicU64,
    total_misses: AtomicU64,
}

impl AddressTranslationCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            translations: HashMap::new(),
            order: VecDeque::new(),
            referenced: HashMap::new(),
            max_entries,
            total_hits: AtomicU64::new(0),
            total_misses: AtomicU64::new(0),
        }
    }

    /// Look up a guest address in the cache.
    ///
    /// Sets the reference bit for clock eviction and increments the access
    /// counters. Single hash probe per lookup.
    pub fn lookup(&mut self, guest_address: u64) -> Option<&AddressTranslation> {
        if let Some(entry) = self.translations.get_mut(&guest_address) {
            entry.access_count += 1;
            entry.hits += 1;
            self.referenced.insert(guest_address, true);
            Some(entry)
        } else {
            None
        }
    }

    /// Insert a translation into the cache.
    ///
    /// Evicts via the clock hand when the cache is at capacity.
    pub fn insert(&mut self, guest_address: u64, host_address: u64, size: usize, protection: u32) {
        if self.translations.len() >= self.max_entries
            && !self.translations.contains_key(&guest_address)
        {
            self.evict_clock();
        }

        self.translations.insert(
            guest_address,
            AddressTranslation {
                guest_address,
                host_address,
                size,
                protection,
                hits: 0,
                access_count: 0,
            },
        );
        self.order.push_back(guest_address);
        self.referenced.insert(guest_address, true);
    }

    /// Second-chance (clock) eviction: walk the ring from the hand, clearing
    /// reference bits until an unreferenced entry is found and evicted.
    fn evict_clock(&mut self) {
        while self.translations.len() >= self.max_entries && !self.translations.is_empty() {
            let Some(key) = self.order.pop_front() else {
                break;
            };
            if !self.translations.contains_key(&key) {
                // Stale key whose translation was invalidated; clean up.
                self.referenced.remove(&key);
                continue;
            }
            if self.referenced.remove(&key).unwrap_or(false) {
                // Second chance: clear the reference bit and keep the entry.
                self.order.push_back(key);
            } else {
                self.translations.remove(&key);
                break;
            }
        }
    }

    /// Record a cache hit.
    pub fn record_hit(&self) {
        self.total_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_miss(&self) {
        self.total_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the cache hit rate (0.0 to 1.0).
    pub fn hit_rate(&self) -> f64 {
        let hits = self.total_hits.load(Ordering::Relaxed) as f64;
        let misses = self.total_misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total == 0.0 { 0.0 } else { hits / total }
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.translations.len()
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&mut self) {
        self.translations.clear();
        self.order.clear();
        self.referenced.clear();
    }

    /// Invalidate entries for a specific address range.
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        self.translations
            .retain(|_, t| t.guest_address < start || t.guest_address >= end);
        self.referenced.retain(|key, _| *key < start || *key >= end);
        // `order` may hold stale keys; the clock eviction skips them.
    }
}

// ===========================================================================
// Parallel Shader Compilation
// ===========================================================================

/// Status of a shader compilation job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShaderCompileStatus {
    Pending,
    Compiling,
    Completed,
    Failed(String),
}

/// A shader compilation job.
#[derive(Debug, Clone)]
pub struct ShaderCompileJob {
    pub id: u64,
    pub shader_hash: String,
    pub stage: String,
    pub entry_point: String,
    pub status: ShaderCompileStatus,
    pub submit_time: Instant,
    pub complete_time: Option<Instant>,
}

/// Manages parallel shader compilation.
///
/// Shader compilation is CPU-intensive and can be parallelized across
/// multiple threads. Jobs are submitted to a queue and processed in order.
/// Terminal (`Completed`/`Failed`) jobs are pruned beyond a bounded cap so
/// the job table cannot grow without limit over long sessions.
pub struct ParallelShaderCompiler {
    jobs: BTreeMap<u64, ShaderCompileJob>,
    next_job_id: AtomicU64,
    max_concurrent: usize,
    max_retained_jobs: usize,
    completed_count: AtomicU32,
    failed_count: AtomicU32,
}

impl ParallelShaderCompiler {
    /// Default cap on terminal jobs retained for inspection; older terminal
    /// jobs are pruned first (job ids increase monotonically).
    pub const DEFAULT_MAX_RETAINED_JOBS: usize = 256;

    pub fn new(max_concurrent: usize) -> Self {
        Self {
            jobs: BTreeMap::new(),
            next_job_id: AtomicU64::new(1),
            max_concurrent,
            max_retained_jobs: Self::DEFAULT_MAX_RETAINED_JOBS,
            completed_count: AtomicU32::new(0),
            failed_count: AtomicU32::new(0),
        }
    }

    /// Set the maximum number of terminal jobs retained for inspection.
    pub fn set_max_retained_jobs(&mut self, max_retained_jobs: usize) {
        self.max_retained_jobs = max_retained_jobs;
        self.prune_terminal_jobs();
    }

    /// Prune the oldest terminal jobs once the retained cap is exceeded.
    fn prune_terminal_jobs(&mut self) {
        let terminal_count = self
            .jobs
            .values()
            .filter(|job| {
                job.status != ShaderCompileStatus::Pending
                    && job.status != ShaderCompileStatus::Compiling
            })
            .count();
        let overflow = terminal_count.saturating_sub(self.max_retained_jobs);
        if overflow == 0 {
            return;
        }
        let mut pruned = 0usize;
        self.jobs.retain(|_, job| {
            let terminal = job.status != ShaderCompileStatus::Pending
                && job.status != ShaderCompileStatus::Compiling;
            if terminal && pruned < overflow {
                pruned += 1;
                false
            } else {
                true
            }
        });
    }

    /// Submit a shader compilation job.
    pub fn submit_job(&mut self, shader_hash: String, stage: String, entry_point: String) -> u64 {
        let id = self.next_job_id.fetch_add(1, Ordering::Relaxed);
        self.jobs.insert(
            id,
            ShaderCompileJob {
                id,
                shader_hash,
                stage,
                entry_point,
                status: ShaderCompileStatus::Pending,
                submit_time: Instant::now(),
                complete_time: None,
            },
        );
        self.prune_terminal_jobs();
        id
    }

    /// Mark a job as compiling.
    pub fn mark_compiling(&mut self, job_id: u64) -> AppResult<()> {
        let job = self.jobs.get_mut(&job_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("shader job {job_id} not found"),
            )
        })?;
        job.status = ShaderCompileStatus::Compiling;
        Ok(())
    }

    /// Mark a job as completed.
    pub fn mark_completed(&mut self, job_id: u64) -> AppResult<()> {
        let job = self.jobs.get_mut(&job_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("shader job {job_id} not found"),
            )
        })?;
        job.status = ShaderCompileStatus::Completed;
        job.complete_time = Some(Instant::now());
        self.completed_count.fetch_add(1, Ordering::Relaxed);
        self.prune_terminal_jobs();
        Ok(())
    }

    /// Mark a job as failed.
    pub fn mark_failed(&mut self, job_id: u64, error: String) -> AppResult<()> {
        let job = self.jobs.get_mut(&job_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("shader job {job_id} not found"),
            )
        })?;
        job.status = ShaderCompileStatus::Failed(error);
        job.complete_time = Some(Instant::now());
        self.failed_count.fetch_add(1, Ordering::Relaxed);
        self.prune_terminal_jobs();
        Ok(())
    }

    /// Get pending jobs that can be started (up to max_concurrent).
    pub fn pending_jobs(&self) -> Vec<&ShaderCompileJob> {
        let compiling_count = self
            .jobs
            .values()
            .filter(|j| j.status == ShaderCompileStatus::Compiling)
            .count();
        let available = self.max_concurrent.saturating_sub(compiling_count);

        self.jobs
            .values()
            .filter(|j| j.status == ShaderCompileStatus::Pending)
            .take(available)
            .collect()
    }

    /// Get a job by ID.
    pub fn get_job(&self, job_id: u64) -> Option<&ShaderCompileJob> {
        self.jobs.get(&job_id)
    }

    /// Get the total number of jobs.
    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    /// Get the number of completed jobs.
    pub fn completed_count(&self) -> u32 {
        self.completed_count.load(Ordering::Relaxed)
    }

    /// Get the number of failed jobs.
    pub fn failed_count(&self) -> u32 {
        self.failed_count.load(Ordering::Relaxed)
    }
}

// ===========================================================================
// Metal Command Batching
// ===========================================================================

/// A batched draw call group.
#[derive(Debug, Clone)]
pub struct DrawBatch {
    pub pipeline_state_id: u64,
    pub draw_calls: Vec<BatchedDrawCall>,
    pub total_vertices: u32,
    pub total_indices: u32,
}

impl DrawBatch {
    fn with_capacity(pipeline_state_id: u64, capacity: usize) -> Self {
        Self {
            pipeline_state_id,
            draw_calls: Vec::with_capacity(capacity),
            total_vertices: 0,
            total_indices: 0,
        }
    }
}

/// A single draw call within a batch.
#[derive(Debug, Clone)]
pub struct BatchedDrawCall {
    pub vertex_count: u32,
    pub index_count: u32,
    pub instance_count: u32,
    pub start_vertex: u32,
    pub base_index: u32,
}

/// Statistics for Metal command batching.
#[derive(Debug, Clone, Default)]
pub struct BatchingStats {
    pub total_draw_calls: u64,
    pub batched_draw_calls: u64,
    pub render_pass_breaks: u64,
    pub pipeline_changes: u64,
    pub vertices_drawn: u64,
    pub indices_drawn: u64,
}

/// Batches Metal draw calls to minimize render pass breaks and pipeline changes.
pub struct MetalCommandBatcher {
    current_pipeline: Option<u64>,
    current_batch: Option<DrawBatch>,
    completed_batches: Vec<DrawBatch>,
    stats: BatchingStats,
    max_batch_size: usize,
}

impl MetalCommandBatcher {
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            current_pipeline: None,
            current_batch: None,
            completed_batches: Vec::new(),
            stats: BatchingStats::default(),
            max_batch_size,
        }
    }

    /// Record a draw call. Automatically batches with the current pipeline state.
    pub fn record_draw(
        &mut self,
        pipeline_state_id: u64,
        vertex_count: u32,
        index_count: u32,
        instance_count: u32,
        start_vertex: u32,
        base_index: u32,
    ) {
        self.stats.total_draw_calls += 1;
        self.stats.vertices_drawn += vertex_count as u64 * instance_count as u64;
        self.stats.indices_drawn += index_count as u64 * instance_count as u64;

        // Check if we need to flush the current batch
        let pipeline_changed = self.current_pipeline != Some(pipeline_state_id);
        if pipeline_changed {
            self.flush_current_batch();
            self.stats.pipeline_changes += 1;
            self.current_pipeline = Some(pipeline_state_id);
        }

        // Add to current batch (pre-allocate to avoid repeated resizing)
        let batch = self.current_batch.get_or_insert_with(|| {
            DrawBatch::with_capacity(pipeline_state_id, self.max_batch_size)
        });

        batch.draw_calls.push(BatchedDrawCall {
            vertex_count,
            index_count,
            instance_count,
            start_vertex,
            base_index,
        });
        batch.total_vertices += vertex_count;
        batch.total_indices += index_count;
        self.stats.batched_draw_calls += 1;

        // Flush if batch is full
        if batch.draw_calls.len() >= self.max_batch_size {
            self.flush_current_batch();
        }
    }

    /// Flush the current batch, starting a new render pass.
    pub fn flush_current_batch(&mut self) {
        if let Some(batch) = self.current_batch.take() {
            if batch.draw_calls.is_empty() {
                return;
            }
            self.completed_batches.push(batch);
            self.stats.render_pass_breaks += 1;
        }
    }

    /// Get completed batches and reset.
    pub fn drain_batches(&mut self) -> Vec<DrawBatch> {
        self.flush_current_batch();
        std::mem::take(&mut self.completed_batches)
    }

    /// Get the batching statistics.
    pub fn stats(&self) -> &BatchingStats {
        &self.stats
    }

    /// Get the average batch size.
    pub fn average_batch_size(&self) -> f64 {
        if self.stats.render_pass_breaks == 0 {
            0.0
        } else {
            self.stats.batched_draw_calls as f64 / self.stats.render_pass_breaks as f64
        }
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = BatchingStats::default();
    }
}

// ===========================================================================
// GPU Upload Streaming
// ===========================================================================

/// A persistent mapped buffer for streaming data to the GPU.
#[derive(Debug, Clone)]
pub struct StreamingBuffer {
    pub id: u64,
    pub size: usize,
    pub frame_used: u64,
    pub write_offset: usize,
    pub total_uploaded: u64,
}

/// Manages persistent mapped buffers for GPU upload streaming.
///
/// Instead of creating new buffers for each frame's dynamic data, pre-allocate
/// a ring buffer and sub-allocate from it each frame.
pub struct GpuUploadStreamer {
    buffers: HashMap<u64, StreamingBuffer>,
    next_buffer_id: AtomicU64,
    current_frame: AtomicU64,
    ring_buffer_size: usize,
    total_bytes_uploaded: AtomicU64,
}

impl GpuUploadStreamer {
    pub fn new(ring_buffer_size: usize) -> Self {
        Self {
            buffers: HashMap::new(),
            next_buffer_id: AtomicU64::new(1),
            current_frame: AtomicU64::new(0),
            ring_buffer_size,
            total_bytes_uploaded: AtomicU64::new(0),
        }
    }

    /// Create a new streaming buffer.
    pub fn create_streaming_buffer(&mut self, size: usize) -> u64 {
        let id = self.next_buffer_id.fetch_add(1, Ordering::Relaxed);
        let frame = self.current_frame.load(Ordering::Relaxed);
        self.buffers.insert(
            id,
            StreamingBuffer {
                id,
                size,
                frame_used: frame,
                write_offset: 0,
                total_uploaded: 0,
            },
        );
        id
    }

    /// Allocate space from a streaming buffer for the current frame.
    ///
    /// The write cursor only wraps on a frame boundary: reusing offsets that
    /// are still in flight within the same frame would let later uploads
    /// overwrite live data. When the current frame's remaining space is
    /// insufficient, an error is returned instead of silently overlapping.
    pub fn allocate(&mut self, buffer_id: u64, size: usize) -> AppResult<usize> {
        let buffer = self.buffers.get_mut(&buffer_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("streaming buffer {buffer_id} not found"),
            )
        })?;

        let frame = self.current_frame.load(Ordering::Relaxed);

        // Reset write offset on new frame
        if buffer.frame_used != frame {
            buffer.write_offset = 0;
            buffer.frame_used = frame;
        }

        // The usable capacity is bounded by both the buffer's own size and
        // the ring pool it was allocated from.
        let capacity = buffer.size.min(self.ring_buffer_size);
        if size > capacity {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("streaming allocation {size} exceeds buffer capacity {capacity}"),
            ));
        }

        let end = match buffer.write_offset.checked_add(size) {
            Some(end) => end,
            None => {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("streaming allocation {size} overflows the write offset"),
                ));
            }
        };
        if end > capacity {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "streaming buffer {buffer_id}: {size} bytes at offset {} exceed frame capacity {capacity}; call advance_frame() before allocating more",
                    buffer.write_offset
                ),
            ));
        }

        let offset = buffer.write_offset;
        buffer.write_offset = end;
        buffer.total_uploaded += size as u64;
        self.total_bytes_uploaded
            .fetch_add(size as u64, Ordering::Relaxed);

        Ok(offset)
    }

    /// Advance to the next frame.
    pub fn advance_frame(&self) {
        self.current_frame.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the ring buffer size in bytes.
    pub fn ring_buffer_size(&self) -> usize {
        self.ring_buffer_size
    }

    /// Get the current frame number.
    pub fn current_frame(&self) -> u64 {
        self.current_frame.load(Ordering::Relaxed)
    }

    /// Get the total bytes uploaded.
    pub fn total_bytes_uploaded(&self) -> u64 {
        self.total_bytes_uploaded.load(Ordering::Relaxed)
    }

    /// Get the number of streaming buffers.
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// Destroy a streaming buffer.
    pub fn destroy_buffer(&mut self, buffer_id: u64) {
        self.buffers.remove(&buffer_id);
    }
}

// ===========================================================================
// Frame Pacing
// ===========================================================================

/// Frame pacing configuration.
#[derive(Debug, Clone)]
pub struct FramePacingConfig {
    /// Target FPS (e.g., 60).
    pub target_fps: u32,
    /// Whether vsync is enabled.
    pub vsync_enabled: bool,
    /// Maximum frame latency (1 = single buffer, 2 = double, 3 = triple).
    pub max_frame_latency: u32,
}

impl Default for FramePacingConfig {
    fn default() -> Self {
        Self {
            target_fps: 60,
            vsync_enabled: true,
            max_frame_latency: 2,
        }
    }
}

/// Frame timing statistics.
#[derive(Debug, Clone, Default)]
pub struct FrameTimingStats {
    pub frames_rendered: u64,
    pub frames_dropped: u64,
    pub total_frame_time_ms: f64,
    pub min_frame_time_ms: f64,
    pub max_frame_time_ms: f64,
    pub last_frame_time_ms: f64,
}

/// Manages frame pacing for smooth rendering.
///
/// Aligns frame presentation with vsync intervals and manages the swap
/// chain latency to achieve the target frame rate.
pub struct FramePacer {
    config: FramePacingConfig,
    stats: FrameTimingStats,
    last_frame_start: Option<Instant>,
    frame_history: VecDeque<f64>, // Last N frame times in ms
    max_history: usize,
}

impl FramePacer {
    pub fn new(config: FramePacingConfig) -> Self {
        Self {
            config,
            stats: FrameTimingStats {
                min_frame_time_ms: f64::MAX,
                max_frame_time_ms: 0.0,
                ..Default::default()
            },
            last_frame_start: None,
            frame_history: VecDeque::new(),
            max_history: 120,
        }
    }

    /// Begin a new frame. Returns the time since last frame start.
    pub fn begin_frame(&mut self) -> Duration {
        let now = Instant::now();
        let delta = self
            .last_frame_start
            .map(|last| now.duration_since(last))
            .unwrap_or(Duration::ZERO);
        self.last_frame_start = Some(now);
        delta
    }

    /// End the current frame and record timing.
    pub fn end_frame(&mut self) {
        if let Some(start) = self.last_frame_start {
            let elapsed = start.elapsed();
            let frame_time_ms = elapsed.as_secs_f64() * 1000.0;

            self.stats.frames_rendered += 1;
            self.stats.total_frame_time_ms += frame_time_ms;
            self.stats.last_frame_time_ms = frame_time_ms;
            self.stats.min_frame_time_ms = self.stats.min_frame_time_ms.min(frame_time_ms);
            self.stats.max_frame_time_ms = self.stats.max_frame_time_ms.max(frame_time_ms);

            self.frame_history.push_back(frame_time_ms);
            if self.frame_history.len() > self.max_history {
                self.frame_history.pop_front();
            }

            // Check if frame was too slow (dropped)
            let target_ms = 1000.0 / self.config.target_fps as f64;
            if frame_time_ms > target_ms * 1.5 {
                self.stats.frames_dropped += 1;
            }
        }
    }

    /// Calculate the sleep time needed to maintain target FPS.
    pub fn frame_remaining_time(&self) -> Duration {
        let target_ms = 1000.0 / self.config.target_fps as f64;
        if let Some(start) = self.last_frame_start {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            let remaining_ms = target_ms - elapsed_ms;
            if remaining_ms > 0.0 {
                Duration::from_secs_f64(remaining_ms / 1000.0)
            } else {
                Duration::ZERO
            }
        } else {
            Duration::ZERO
        }
    }

    /// Get the current average FPS.
    pub fn average_fps(&self) -> f64 {
        if self.stats.frames_rendered == 0 {
            return 0.0;
        }
        let avg_frame_time = self.stats.total_frame_time_ms / self.stats.frames_rendered as f64;
        if avg_frame_time > 0.0 {
            1000.0 / avg_frame_time
        } else {
            0.0
        }
    }

    /// Get the 1% low FPS (worst 1% of frames).
    pub fn one_percent_low_fps(&self) -> f64 {
        if self.frame_history.is_empty() {
            return 0.0;
        }
        let mut times: Vec<f64> = self.frame_history.iter().copied().collect();
        times.sort_by(|a, b| b.partial_cmp(a).unwrap()); // Descending
        let count = (times.len() as f64 * 0.01).max(1.0) as usize;
        let worst: f64 = times[..count].iter().sum();
        1000.0 / (worst / count as f64)
    }

    /// Get the frame timing statistics.
    pub fn stats(&self) -> &FrameTimingStats {
        &self.stats
    }

    /// Get the frame pacing configuration.
    pub fn config(&self) -> &FramePacingConfig {
        &self.config
    }

    /// Update the frame pacing configuration.
    pub fn set_config(&mut self, config: FramePacingConfig) {
        self.config = config;
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = FrameTimingStats {
            min_frame_time_ms: f64::MAX,
            max_frame_time_ms: 0.0,
            ..Default::default()
        };
        self.frame_history.clear();
        self.last_frame_start = None;
    }
}

// ===========================================================================
// Phase 7: Async File I/O
// ===========================================================================

/// A pending async read request.
#[derive(Debug, Clone)]
pub struct PendingRead {
    /// File path to read from.
    pub path: PathBuf,
    /// Byte offset within the file.
    pub offset: u64,
    /// Number of bytes to read.
    pub size: usize,
}

/// A completed async read result.
#[derive(Debug, Clone)]
pub struct CompletedRead {
    /// Data read from the file.
    pub data: Vec<u8>,
    /// Time taken for the read in microseconds.
    pub elapsed_us: u64,
}

/// Manages asynchronous file read operations.
///
/// # Performance Impact
/// Synchronous file I/O blocks the calling thread, wasting CPU cycles while
/// waiting for disk. By submitting reads asynchronously, the main emulation
/// thread can continue executing guest code while I/O happens in the
/// background, reducing frame stalls during asset loading.
pub struct AsyncFileReader {
    /// Pending read requests keyed by request ID.
    pub pending_reads: BTreeMap<u64, PendingRead>,
    /// Completed read results keyed by request ID.
    pub completed_reads: BTreeMap<u64, CompletedRead>,
    /// Next unique request ID.
    pub next_request_id: u64,
    /// Thread handles for in-flight async reads.
    handles: HashMap<u64, std::thread::JoinHandle<CompletedRead>>,
}

impl AsyncFileReader {
    /// Create a new async file reader.
    pub fn new() -> Self {
        Self {
            pending_reads: BTreeMap::new(),
            completed_reads: BTreeMap::new(),
            next_request_id: 1,
            handles: HashMap::new(),
        }
    }

    /// Submit an asynchronous read request.
    ///
    /// Returns the unique request ID that can be used to poll for completion.
    /// The read is performed on a background thread, allowing the caller to
    /// continue execution while I/O completes.
    pub fn submit_read(&mut self, path: PathBuf, offset: u64, size: usize) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;

        self.pending_reads.insert(
            id,
            PendingRead {
                path: path.clone(),
                offset,
                size,
            },
        );

        let handle = std::thread::spawn(move || {
            use std::io::{Read, Seek, SeekFrom};
            let start = Instant::now();
            // Read only the requested range instead of slurping the whole
            // file: `std::fs::read` would make memory and I/O proportional
            // to the file size, defeating the offset/size API.
            let data = match std::fs::File::open(&path) {
                Ok(mut file) => match file.seek(SeekFrom::Start(offset)) {
                    Ok(_) => {
                        let mut data = Vec::with_capacity(size);
                        match file.take(size as u64).read_to_end(&mut data) {
                            Ok(_) => data,
                            Err(_) => Vec::new(),
                        }
                    }
                    Err(_) => Vec::new(),
                },
                Err(_) => Vec::new(),
            };
            let elapsed_us = start.elapsed().as_micros() as u64;

            CompletedRead { data, elapsed_us }
        });

        self.handles.insert(id, handle);
        id
    }

    /// Poll for completed reads.
    ///
    /// Returns all completed reads as `(request_id, data)` pairs and removes
    /// them from the completed queue.
    pub fn poll_completed(&mut self) -> Vec<(u64, Vec<u8>)> {
        let ids: Vec<u64> = self.completed_reads.keys().copied().collect();
        let mut results = Vec::new();
        for id in ids {
            if let Some(completed) = self.completed_reads.remove(&id) {
                results.push((id, completed.data));
            }
        }
        results
    }

    /// Wait for a specific read request to complete.
    ///
    /// Blocks until the background thread completes the read and returns
    /// the data. The `timeout_ms` parameter is preserved for API compatibility.
    pub fn wait_for(&mut self, request_id: u64, _timeout_ms: u64) -> AppResult<Vec<u8>> {
        // If the result is already available from a previous join, return it
        if let Some(completed) = self.completed_reads.remove(&request_id) {
            return Ok(completed.data);
        }

        // Join the background thread if it's still running
        if let Some(handle) = self.handles.remove(&request_id) {
            match handle.join() {
                Ok(completed) => {
                    let data = completed.data.clone();
                    self.completed_reads.insert(request_id, completed);
                    Ok(data)
                }
                Err(_) => Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("async read {request_id}: thread panicked"),
                )),
            }
        } else {
            Err(AppError::new(
                ReasonCode::RcWin32Timeout,
                format!("async read {request_id} not found"),
            ))
        }
    }
}

impl Default for AsyncFileReader {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Phase 7: File Caching
// ===========================================================================

/// A cached file entry.
#[derive(Debug, Clone)]
pub struct FileCacheEntry {
    /// Cached file data.
    pub data: Vec<u8>,
    /// Timestamp of last access (monotonic counter).
    pub last_access: u64,
    /// Number of times this entry has been accessed.
    pub access_count: u64,
}

/// Caches frequently accessed file data in memory.
///
/// # Performance Impact
/// Game engines often read the same files repeatedly (configuration, shaders,
/// texture headers). Caching eliminates redundant disk I/O and filesystem
/// overhead, reducing latency for hot-path file accesses from milliseconds
/// to nanoseconds.
pub struct FileCache {
    /// Cached entries keyed by file path.
    pub entries: BTreeMap<String, FileCacheEntry>,
    /// Ordered index over `(last_access, path)` so eviction can pop the
    /// least-recently-used entry in O(log n) instead of rescanning the map.
    lru_index: BTreeMap<(u64, String), ()>,
    /// Maximum total cache size in bytes.
    pub max_size_bytes: usize,
    /// Currently used bytes.
    pub used_bytes: usize,
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
    /// Monotonic access counter for LRU tracking.
    access_counter: u64,
}

impl FileCache {
    /// Create a new file cache with the given maximum size in bytes.
    pub fn new(max_size_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            lru_index: BTreeMap::new(),
            max_size_bytes,
            used_bytes: 0,
            hits: 0,
            misses: 0,
            access_counter: 0,
        }
    }

    /// Get cached file data by path.
    ///
    /// Returns `Some(data)` on cache hit, `None` on miss.
    pub fn get(&mut self, path: &str) -> Option<&[u8]> {
        self.access_counter += 1;
        if let Some(entry) = self.entries.get_mut(path) {
            self.lru_index
                .remove(&(entry.last_access, path.to_string()));
            entry.last_access = self.access_counter;
            entry.access_count += 1;
            self.lru_index
                .insert((entry.last_access, path.to_string()), ());
            self.hits += 1;
            Some(&entry.data)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert file data into the cache.
    ///
    /// If the cache is full, LRU entries are evicted until there is enough
    /// space. Returns an error if the data is larger than the entire cache.
    pub fn insert(&mut self, path: &str, data: Vec<u8>) -> AppResult<()> {
        let data_len = data.len();
        if data_len > self.max_size_bytes {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!(
                    "file cache: data size {data_len} exceeds max cache size {}",
                    self.max_size_bytes
                ),
            ));
        }

        // Remove old entry if present
        if let Some(old) = self.entries.remove(path) {
            self.used_bytes = self.used_bytes.saturating_sub(old.data.len());
            self.lru_index.remove(&(old.last_access, path.to_string()));
        }

        // Evict LRU entries until we have space
        while self.used_bytes.saturating_add(data_len) > self.max_size_bytes {
            let Some(((_, key), _)) = self.lru_index.pop_first() else {
                break;
            };
            if let Some(old) = self.entries.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(old.data.len());
            }
        }

        self.access_counter += 1;
        self.used_bytes += data_len;
        self.lru_index
            .insert((self.access_counter, path.to_string()), ());
        self.entries.insert(
            path.to_string(),
            FileCacheEntry {
                data,
                last_access: self.access_counter,
                access_count: 0,
            },
        );

        Ok(())
    }

    /// Invalidate a specific cached file.
    pub fn invalidate(&mut self, path: &str) {
        if let Some(old) = self.entries.remove(path) {
            self.used_bytes = self.used_bytes.saturating_sub(old.data.len());
            self.lru_index.remove(&(old.last_access, path.to_string()));
        }
    }

    /// Invalidate all cached files.
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
        self.lru_index.clear();
        self.used_bytes = 0;
    }

    /// Get cache statistics: (hits, misses, hit_rate).
    pub fn stats(&self) -> (u64, u64, f64) {
        let total = self.hits + self.misses;
        let rate = if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        };
        (self.hits, self.misses, rate)
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ===========================================================================
// Phase 7: Path Resolution Caching
// ===========================================================================

/// Caches resolved filesystem paths to avoid repeated string operations.
///
/// # Performance Impact
/// Path resolution involves string manipulation, component joining, and
/// potentially filesystem stat calls. By caching resolved paths, we avoid
/// redundant string allocations and filesystem queries for frequently
/// accessed paths.
pub struct PathResolutionCache {
    /// Resolved paths: guest_path → host_path.
    pub cache: BTreeMap<String, PathBuf>,
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
}

impl PathResolutionCache {
    /// Create a new path resolution cache.
    pub fn new() -> Self {
        Self {
            cache: BTreeMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Resolve a guest path, using the cache when possible.
    ///
    /// On a cache hit, returns the cached host path directly. On a miss,
    /// calls the resolver function and caches the result.
    pub fn resolve<F>(&mut self, guest_path: &str, resolver: F) -> AppResult<PathBuf>
    where
        F: FnOnce(&str) -> AppResult<PathBuf>,
    {
        if let Some(resolved) = self.cache.get(guest_path) {
            self.hits += 1;
            return Ok(resolved.clone());
        }

        self.misses += 1;
        let resolved = resolver(guest_path)?;
        self.cache.insert(guest_path.to_string(), resolved.clone());
        Ok(resolved)
    }

    /// Invalidate a specific cached path.
    pub fn invalidate(&mut self, guest_path: &str) {
        self.cache.remove(guest_path);
    }

    /// Invalidate all cached paths matching a prefix.
    pub fn invalidate_prefix(&mut self, prefix: &str) {
        let keys_to_remove: Vec<String> = self
            .cache
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        for key in keys_to_remove {
            self.cache.remove(&key);
        }
    }

    /// Get cache statistics: (hits, misses, hit_rate).
    pub fn stats(&self) -> (u64, u64, f64) {
        let total = self.hits + self.misses;
        let rate = if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        };
        (self.hits, self.misses, rate)
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.cache.len()
    }
}

impl Default for PathResolutionCache {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Phase 7: Memory-Mapped File Support
// ===========================================================================

/// A memory-mapped file for efficient large file reads.
///
/// # Performance Impact
/// For large files (textures, meshes, audio), `mmap` avoids copying data
/// from kernel space to user space. The kernel maps file pages directly
/// into the process address space, enabling zero-copy reads and lazy
/// page-in that reduces peak memory usage.
pub struct MmappedFile {
    /// File path.
    pub path: PathBuf,
    /// Size of the mapped region in bytes.
    pub size: usize,
    /// Pointer to the mapped memory. Private: callers must go through the
    /// bounds-checked [`Self::read`], so the pointer can never be copied out
    /// and dereferenced after `close()`/`drop()` has munmapped it.
    ptr: *mut u8,
    /// Whether the file is currently mapped.
    pub mapped: bool,
}

// Safety: `MmappedFile` is safe to send and share across threads as long as
// callers only use the bounds-checked `read`/`close` API. The raw pointer is
// private (no way to alias it out), reads take `&self`, and `close` takes
// `&mut self`, so no concurrent mutation of the mapping is possible.
unsafe impl Send for MmappedFile {}
unsafe impl Sync for MmappedFile {}

impl MmappedFile {
    /// Open a file and memory-map it.
    ///
    /// The entire file is mapped into the process address space. Pages are
    /// loaded on demand (lazy page-in).
    pub fn open(path: &Path) -> AppResult<Self> {
        let file = std::fs::File::open(path).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("mmap: failed to open {}", path.display()),
                &e,
            )
        })?;

        let metadata = file.metadata().map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("mmap: failed to stat {}", path.display()),
                &e,
            )
        })?;

        let size = metadata.len() as usize;

        if size == 0 {
            return Ok(Self {
                path: path.to_path_buf(),
                size: 0,
                ptr: std::ptr::null_mut(),
                mapped: false,
            });
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("mmap: failed to mmap {}", path.display()),
            ));
        }

        Ok(Self {
            path: path.to_path_buf(),
            size,
            ptr: ptr as *mut u8,
            mapped: true,
        })
    }

    /// Read bytes from the mapped memory at the given offset.
    ///
    /// Copies `buf.len()` bytes starting at `offset` from the mapped region
    /// into the provided buffer.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> AppResult<()> {
        if !self.mapped || self.ptr.is_null() {
            return Err(AppError::new(ReasonCode::RcIo, "mmap: file is not mapped"));
        }

        if offset.saturating_add(buf.len()) > self.size {
            return Err(AppError::new(
                ReasonCode::RcMemoryAccessViolation,
                format!(
                    "mmap: read at offset {offset} + {} exceeds file size {}",
                    buf.len(),
                    self.size
                ),
            ));
        }

        unsafe {
            std::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len());
        }

        Ok(())
    }

    /// Close the memory mapping.
    ///
    /// Unmaps the file and resets the internal state. Must be called before
    /// drop to release the mapping explicitly (though Drop also handles it).
    pub fn close(&mut self) {
        if self.mapped && !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
            }
            self.ptr = std::ptr::null_mut();
            self.mapped = false;
        }
    }
}

impl Drop for MmappedFile {
    fn drop(&mut self) {
        self.close();
    }
}

// ===========================================================================
// End-to-end GPU/present performance measurement (audit P1 #5)
// ===========================================================================

/// Why a real timestamp-backed metric cannot be reported. Every variant has an
/// exact, user-visible reason; a metric is never replaced by a CPU-side
/// bookkeeping estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TimingUnavailable {
    /// No Metal device exists on this host.
    NoMetalDevice,
    /// The command buffer completed without `GPUStartTime`/`GPUEndTime`.
    MissingGpuTimestamp,
    /// The host does not expose command-buffer GPU timestamps.
    UnsupportedGpuTimestamp,
    /// `CAMetalLayer.nextDrawable` returned no drawable (headless present).
    NoDrawable,
    /// No macOS window-server display session exists, so a windowed
    /// `CAMetalLayer` cannot present.
    NoDisplaySession,
    /// The drawable reported `presentedTime == 0` (not displayed).
    MissingPresentTimestamp,
    /// The drawable's presented handler never fired before the run loop
    /// stopped, so no presentation timestamp could be observed.
    PresentHandlerNeverFired,
    /// `NSApplication` or its run loop could not be started, so windowed
    /// presentation cannot be observed.
    NoAppRunLoop,
    /// No input-event timestamp was correlated with the measured frame.
    MissingInputTimestamp,
    /// Fewer than two real present/GPU-completion timestamps were recorded.
    NoFrameTimeSamples,
    /// No shader compilation requests were recorded.
    NoShaderCompileSamples,
    /// No guest-instruction throughput sample was recorded.
    NoGuestWork,
    /// The host CPU clock could not be sampled.
    MissingHostCpuTime,
}

impl TimingUnavailable {
    pub fn reason(self) -> &'static str {
        match self {
            TimingUnavailable::NoMetalDevice => {
                "no Metal device is available; GPU and drawable timestamps cannot be captured"
            }
            TimingUnavailable::MissingGpuTimestamp => {
                "Metal command buffer completed without GPUStartTime/GPUEndTime timestamps"
            }
            TimingUnavailable::UnsupportedGpuTimestamp => {
                "the Metal device does not expose command-buffer GPU timestamps"
            }
            TimingUnavailable::NoDrawable => {
                "CAMetalLayer.nextDrawable returned no drawable (headless presentation); \
                 drawable presentedTime is unavailable"
            }
            TimingUnavailable::NoDisplaySession => {
                "no macOS window-server display session is available; a windowed CAMetalLayer \
                 cannot present and presentedTime is unavailable"
            }
            TimingUnavailable::MissingPresentTimestamp => {
                "CAMetalLayer drawable reported presentedTime=0; no display presentation occurred"
            }
            TimingUnavailable::PresentHandlerNeverFired => {
                "CAMetalLayer drawable presented handler never fired before the NSApplication \
                 run loop stopped; no display presentation was observed"
            }
            TimingUnavailable::NoAppRunLoop => {
                "the macOS NSApplication run loop could not be started; windowed presentation \
                 timestamps cannot be observed"
            }
            TimingUnavailable::MissingInputTimestamp => {
                "no input-event timestamp was correlated with the measured frames"
            }
            TimingUnavailable::NoFrameTimeSamples => {
                "fewer than two real present or GPU-completion timestamps were recorded"
            }
            TimingUnavailable::NoShaderCompileSamples => {
                "no shader compilation requests were recorded"
            }
            TimingUnavailable::NoGuestWork => "no guest-instruction throughput sample was recorded",
            TimingUnavailable::MissingHostCpuTime => {
                "the host process CPU clock could not be sampled"
            }
        }
    }
}

/// Nearest-rank percentile over an already-sorted sample slice.
///
/// Returns `None` for an empty slice. Fractions `<= 0` select the minimum and
/// fractions `>= 1` select the maximum, so callers cannot index out of bounds
/// with a synthetic p999 on a one-sample window.
pub fn percentile_ns(sorted: &[u64], fraction: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    if !fraction.is_finite() || fraction <= 0.0 {
        return sorted.first().copied();
    }
    if fraction >= 1.0 {
        return sorted.last().copied();
    }
    let rank = (fraction * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.saturating_sub(1).min(sorted.len() - 1)])
}

/// Exact order-statistic summary for one latency distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PercentileStats {
    pub sample_count: usize,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
}

impl PercentileStats {
    pub fn from_ns(samples: &[u64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Some(Self {
            sample_count: sorted.len(),
            p50_ns: percentile_ns(&sorted, 0.50)?,
            p95_ns: percentile_ns(&sorted, 0.95)?,
            p99_ns: percentile_ns(&sorted, 0.99)?,
            p999_ns: percentile_ns(&sorted, 0.999)?,
        })
    }

    pub fn p50_us(&self) -> f64 {
        self.p50_ns as f64 / 1_000.0
    }

    pub fn p95_us(&self) -> f64 {
        self.p95_ns as f64 / 1_000.0
    }

    pub fn p99_us(&self) -> f64 {
        self.p99_ns as f64 / 1_000.0
    }

    pub fn p999_us(&self) -> f64 {
        self.p999_ns as f64 / 1_000.0
    }
}

/// FPS implied by the mean of the slowest `fraction` samples.
pub fn low_fps(samples_ns: &[u64], fraction: f64) -> Option<f64> {
    if samples_ns.is_empty() {
        return None;
    }
    let mut sorted = samples_ns.to_vec();
    sorted.sort_unstable_by(|left, right| right.cmp(left));
    let count = ((sorted.len() as f64 * fraction).ceil() as usize)
        .max(1)
        .min(sorted.len());
    let worst: u128 = sorted[..count].iter().map(|value| *value as u128).sum();
    let average_ns = worst as f64 / count as f64;
    if average_ns <= 0.0 || !average_ns.is_finite() {
        None
    } else {
        Some(1_000_000_000.0 / average_ns)
    }
}

/// Correlates CoreAnimation media timestamps (GPU/present) with the
/// monotonic instants used for input and submit events.
#[derive(Debug, Clone, Copy)]
pub struct MediaClock {
    origin: Instant,
    origin_seconds: f64,
}

impl MediaClock {
    /// Anchor the two clocks at one point in time. Returns `None` when the
    /// host has no CoreAnimation clock (non-Metal hosts).
    pub fn capture() -> Option<Self> {
        Self::from_parts(Instant::now(), crate::metal_backend::media_now_seconds())
    }

    pub fn from_parts(origin: Instant, origin_seconds: f64) -> Option<Self> {
        if !origin_seconds.is_finite() || origin_seconds <= 0.0 {
            return None;
        }
        Some(Self {
            origin,
            origin_seconds,
        })
    }

    /// Current monotonic timestamp on this clock's timeline.
    pub fn now_ns(&self) -> u64 {
        self.seconds_to_ns(crate::metal_backend::media_now_seconds())
            .unwrap_or(0)
    }

    /// Convert a CoreAnimation media timestamp into the monotonic timeline.
    /// Timestamps older than the anchor or outside the representable range
    /// are rejected instead of wrapping.
    pub fn seconds_to_ns(&self, seconds: f64) -> Option<u64> {
        if !seconds.is_finite() {
            return None;
        }
        let delta = seconds - self.origin_seconds;
        let delta_ns = (delta * 1_000_000_000.0).round();
        if !delta_ns.is_finite() || delta_ns < 0.0 || delta_ns > u64::MAX as f64 {
            return None;
        }
        let offset = self
            .origin
            .checked_add(Duration::from_nanos(delta_ns as u64))?;
        Some(offset.duration_since(self.origin).as_nanos() as u64)
    }
}

/// One measured frame. Every duration is derived from a real timestamp; the
/// accessors return `None` rather than substituting a wall-clock estimate when
/// a timestamp is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameSample {
    pub sequence: u64,
    pub input_ns: Option<u64>,
    pub submit_start_ns: u64,
    pub submit_end_ns: u64,
    pub gpu_start_ns: Option<u64>,
    pub gpu_end_ns: Option<u64>,
    pub present_ns: Option<u64>,
    pub guest_instructions: u64,
    pub host_cpu_ns: u64,
    pub shader_compile_stall: bool,
}

impl FrameSample {
    pub fn new(
        sequence: u64,
        input_ns: Option<u64>,
        submit_start_ns: u64,
        submit_end_ns: u64,
    ) -> Self {
        Self {
            sequence,
            input_ns,
            submit_start_ns,
            submit_end_ns,
            gpu_start_ns: None,
            gpu_end_ns: None,
            present_ns: None,
            guest_instructions: 0,
            host_cpu_ns: 0,
            shader_compile_stall: false,
        }
    }

    pub fn with_gpu_timestamps(mut self, start_ns: u64, end_ns: u64) -> Self {
        self.gpu_start_ns = Some(start_ns);
        self.gpu_end_ns = Some(end_ns);
        self
    }

    pub fn with_present_timestamp(mut self, present_ns: u64) -> Self {
        self.present_ns = Some(present_ns);
        self
    }

    pub fn with_guest_instructions(mut self, instructions: u64) -> Self {
        self.guest_instructions = instructions;
        self
    }

    pub fn with_host_cpu_ns(mut self, host_cpu_ns: u64) -> Self {
        self.host_cpu_ns = host_cpu_ns;
        self
    }

    pub fn with_shader_compile_stall(mut self, stalled: bool) -> Self {
        self.shader_compile_stall = stalled;
        self
    }

    /// Real CPU submit duration (`submit_end - submit_start`).
    pub fn cpu_submit_ns(&self) -> Option<u64> {
        self.submit_end_ns.checked_sub(self.submit_start_ns)
    }

    /// Real GPU execution duration (`GPUEndTime - GPUStartTime`).
    pub fn gpu_time_ns(&self) -> Option<u64> {
        match (self.gpu_start_ns, self.gpu_end_ns) {
            (Some(start), Some(end)) => end.checked_sub(start),
            _ => None,
        }
    }

    pub fn input_to_present_ns(&self) -> Option<u64> {
        match (self.input_ns, self.present_ns) {
            (Some(input), Some(present)) => present.checked_sub(input),
            _ => None,
        }
    }

    pub fn input_to_gpu_completion_ns(&self) -> Option<u64> {
        match (self.input_ns, self.gpu_end_ns) {
            (Some(input), Some(end)) => end.checked_sub(input),
            _ => None,
        }
    }

    pub fn present_to_gpu_end_ns(&self) -> Option<i64> {
        match (self.present_ns, self.gpu_end_ns) {
            (Some(present), Some(end)) => i64::try_from(end)
                .ok()
                .zip(i64::try_from(present).ok())
                .map(|(end, present)| end - present),
            _ => None,
        }
    }

    /// Timeline marker used for frame-time intervals: a real presentation
    /// timestamp when the drawable was displayed, otherwise a real GPU
    /// completion timestamp.
    pub fn frame_marker_ns(&self) -> Option<u64> {
        self.present_ns.or(self.gpu_end_ns)
    }
}

/// Real host process CPU time in nanoseconds (`CLOCK_PROCESS_CPUTIME_ID`).
pub fn process_cpu_time_ns() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut timestamp = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes only to the provided timespec.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut timestamp) };
        if result == 0 {
            (timestamp.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(timestamp.tv_nsec as u64)
        } else {
            0
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// Aggregated real-sample metrics for GPU/present measurement.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct GpuPresentSummary {
    pub sample_count: usize,
    pub gpu_sample_count: usize,
    pub present_sample_count: usize,
    pub gpu_unavailable: Option<TimingUnavailable>,
    pub present_unavailable: Option<TimingUnavailable>,
    pub frame_time: Option<PercentileStats>,
    pub frame_time_unavailable: Option<TimingUnavailable>,
    pub gpu_time: Option<PercentileStats>,
    pub cpu_submit: Option<PercentileStats>,
    pub input_to_present: Option<PercentileStats>,
    pub input_to_present_unavailable: Option<TimingUnavailable>,
    pub input_to_gpu_completion: Option<PercentileStats>,
    pub input_to_gpu_unavailable: Option<TimingUnavailable>,
    pub host_cpu_time: Option<PercentileStats>,
    pub host_cpu_unavailable: Option<TimingUnavailable>,
    pub frame_time_1pct_low_fps: Option<f64>,
    pub frame_time_0p1pct_low_fps: Option<f64>,
    pub gpu_idle_gap_us: Option<f64>,
    pub shader_compile_requests: u64,
    pub shader_compile_stalls: u64,
    pub shader_compile_stall_rate: Option<f64>,
    pub shader_compile_unavailable: Option<TimingUnavailable>,
    pub guest_instructions: u64,
    pub guest_wall_ns: u64,
    pub guest_instructions_per_sec: Option<f64>,
    pub guest_work_unavailable: Option<TimingUnavailable>,
}

impl GpuPresentSummary {
    /// Machine-readable KPI entries. Unavailable entries carry the exact
    /// fallback reason and never contain a fabricated number.
    pub fn to_json_metrics(&self) -> BTreeMap<String, serde_json::Value> {
        let mut metrics = BTreeMap::new();
        let gpu_source = "Metal command buffer GPUStartTime/GPUEndTime";
        let present_source = "CAMetalLayer drawable presentedTime correlated with the input event";
        let frame_source =
            "real present/GPU-completion timeline between consecutive measured frames";

        macro_rules! insert {
            ($key:expr, $value:expr, $unit:expr, $direction:expr, $source:expr $(,)?) => {{
                if let Some(value) = $value.filter(|value: &f64| value.is_finite()) {
                    metrics.insert(
                        $key.to_string(),
                        serde_json::json!({
                            "available": true,
                            "value": value,
                            "unit": $unit,
                            "direction": $direction,
                            "source": $source,
                        }),
                    );
                }
            }};
        }
        macro_rules! unavailable {
            ($key:expr, $reason:expr $(,)?) => {{
                metrics.insert(
                    $key.to_string(),
                    serde_json::json!({
                        "available": false,
                        "reason": $reason.reason(),
                        "source": "real Metal GPU/present timestamps",
                    }),
                );
            }};
        }

        match self.frame_time {
            Some(stats) => {
                for (key, value) in [
                    ("gpu_frame_time_p50_us", stats.p50_us()),
                    ("gpu_frame_time_p95_us", stats.p95_us()),
                    ("gpu_frame_time_p99_us", stats.p99_us()),
                    ("gpu_frame_time_p999_us", stats.p999_us()),
                ] {
                    insert!(key, Some(value), "us", "lower", frame_source);
                }
            }
            None => {
                for key in [
                    "gpu_frame_time_p50_us",
                    "gpu_frame_time_p95_us",
                    "gpu_frame_time_p99_us",
                    "gpu_frame_time_p999_us",
                ] {
                    unavailable!(
                        key,
                        self.frame_time_unavailable
                            .unwrap_or(TimingUnavailable::NoFrameTimeSamples),
                    );
                }
            }
        }
        for (key, value, reason) in [
            (
                "gpu_frame_time_1pct_low_fps",
                self.frame_time_1pct_low_fps,
                TimingUnavailable::NoFrameTimeSamples,
            ),
            (
                "gpu_frame_time_0p1pct_low_fps",
                self.frame_time_0p1pct_low_fps,
                TimingUnavailable::NoFrameTimeSamples,
            ),
        ] {
            match value {
                Some(value) => insert!(key, Some(value), "fps", "higher", frame_source),
                None => unavailable!(key, self.frame_time_unavailable.unwrap_or(reason)),
            }
        }
        match self.gpu_time {
            Some(stats) => {
                for (key, value) in [
                    ("gpu_time_p50_us", stats.p50_us()),
                    ("gpu_time_p99_us", stats.p99_us()),
                ] {
                    insert!(key, Some(value), "us", "lower", gpu_source);
                }
            }
            None => {
                for key in ["gpu_time_p50_us", "gpu_time_p99_us"] {
                    unavailable!(
                        key,
                        self.gpu_unavailable
                            .unwrap_or(TimingUnavailable::MissingGpuTimestamp),
                    );
                }
            }
        }
        match self.cpu_submit {
            Some(stats) => {
                insert!(
                    "cpu_submit_p50_us",
                    Some(stats.p50_us()),
                    "us",
                    "lower",
                    "CPU command encoding + commit (submit_start/submit_end)",
                );
                insert!(
                    "cpu_submit_p99_us",
                    Some(stats.p99_us()),
                    "us",
                    "lower",
                    "CPU command encoding + commit (submit_start/submit_end)",
                );
            }
            None => {
                for key in ["cpu_submit_p50_us", "cpu_submit_p99_us"] {
                    unavailable!(key, TimingUnavailable::NoFrameTimeSamples);
                }
            }
        }
        match self.input_to_present {
            Some(stats) => {
                for (key, value) in [
                    ("input_to_present_p50_us", stats.p50_us()),
                    ("input_to_present_p99_us", stats.p99_us()),
                ] {
                    insert!(key, Some(value), "us", "lower", present_source);
                }
            }
            None => {
                for key in ["input_to_present_p50_us", "input_to_present_p99_us"] {
                    unavailable!(
                        key,
                        self.input_to_present_unavailable
                            .unwrap_or(TimingUnavailable::MissingPresentTimestamp),
                    );
                }
            }
        }
        match self.input_to_gpu_completion {
            Some(stats) => {
                for (key, value) in [
                    ("input_to_gpu_completion_p50_us", stats.p50_us()),
                    ("input_to_gpu_completion_p99_us", stats.p99_us()),
                ] {
                    insert!(
                        key,
                        Some(value),
                        "us",
                        "lower",
                        "input event to real Metal GPUEndTime",
                    );
                }
            }
            None => {
                for key in [
                    "input_to_gpu_completion_p50_us",
                    "input_to_gpu_completion_p99_us",
                ] {
                    unavailable!(
                        key,
                        self.input_to_gpu_unavailable
                            .unwrap_or(TimingUnavailable::MissingInputTimestamp),
                    );
                }
            }
        }
        match self.host_cpu_time {
            Some(stats) => insert!(
                "host_cpu_time_p50_us",
                Some(stats.p50_us()),
                "us",
                "lower",
                "CLOCK_PROCESS_CPUTIME_ID around measured frames",
            ),
            None => unavailable!(
                "host_cpu_time_p50_us",
                self.host_cpu_unavailable
                    .unwrap_or(TimingUnavailable::MissingHostCpuTime),
            ),
        }
        match self.shader_compile_stall_rate {
            Some(value) => insert!(
                "shader_compile_stall_rate_measured",
                Some(value),
                "stalls/request",
                "lower",
                "shader compilation requests recorded during the measurement window",
            ),
            None => unavailable!(
                "shader_compile_stall_rate_measured",
                self.shader_compile_unavailable
                    .unwrap_or(TimingUnavailable::NoShaderCompileSamples),
            ),
        }
        match self.guest_instructions_per_sec {
            Some(value) => insert!(
                "guest_instructions_per_sec",
                Some(value),
                "guest instructions/s",
                "higher",
                "guest instructions retired / measured wall time",
            ),
            None => unavailable!(
                "guest_instructions_per_sec",
                self.guest_work_unavailable
                    .unwrap_or(TimingUnavailable::NoGuestWork),
            ),
        }
        match self.gpu_idle_gap_us {
            Some(value) => insert!(
                "gpu_idle_gap_us",
                Some(value),
                "us",
                "lower",
                "next GPUStartTime - previous GPUEndTime",
            ),
            None => unavailable!(
                "gpu_idle_gap_us",
                self.gpu_unavailable
                    .unwrap_or(TimingUnavailable::NoFrameTimeSamples),
            ),
        }
        metrics
    }
}

/// Collector for end-to-end frame samples. Aggregation uses only real
/// timestamps; when a timestamp source is absent the corresponding metric is
/// reported unavailable with an exact reason.
#[derive(Debug, Default, Clone)]
pub struct GpuPresentRecorder {
    samples: Vec<FrameSample>,
    gpu_unavailable: Option<TimingUnavailable>,
    present_unavailable: Option<TimingUnavailable>,
    shader_compile_requests: u64,
    shader_compile_stalls: u64,
    guest_instructions: u64,
    guest_wall_ns: u64,
}

impl GpuPresentRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_gpu_unavailable(&mut self, reason: TimingUnavailable) {
        if self.gpu_unavailable.is_none() {
            self.gpu_unavailable = Some(reason);
        }
    }

    pub fn mark_present_unavailable(&mut self, reason: TimingUnavailable) {
        if self.present_unavailable.is_none() {
            self.present_unavailable = Some(reason);
        }
    }

    pub fn record(&mut self, sample: FrameSample) {
        self.samples.push(sample);
    }

    pub fn record_shader_compile(&mut self, stalled: bool) {
        self.shader_compile_requests += 1;
        if stalled {
            self.shader_compile_stalls += 1;
        }
    }

    pub fn record_guest_work(&mut self, instructions: u64, wall_ns: u64) {
        self.guest_instructions = self.guest_instructions.saturating_add(instructions);
        self.guest_wall_ns = self.guest_wall_ns.saturating_add(wall_ns);
    }

    pub fn samples(&self) -> &[FrameSample] {
        &self.samples
    }

    pub fn summary(&self) -> GpuPresentSummary {
        let gpu_times: Vec<u64> = self
            .samples
            .iter()
            .filter_map(FrameSample::gpu_time_ns)
            .collect();
        let present_marks: Vec<u64> = self
            .samples
            .iter()
            .filter_map(|sample| sample.present_ns)
            .collect();
        let gpu_ends: Vec<u64> = self
            .samples
            .iter()
            .filter_map(|sample| sample.gpu_end_ns)
            .collect();
        let markers = if present_marks.len() >= 2 {
            present_marks.clone()
        } else {
            gpu_ends.clone()
        };
        let frame_intervals: Vec<u64> = markers
            .windows(2)
            .filter_map(|pair| pair[1].checked_sub(pair[0]))
            .filter(|interval| *interval > 0)
            .collect();
        let cpu_submit: Vec<u64> = self
            .samples
            .iter()
            .filter_map(FrameSample::cpu_submit_ns)
            .collect();
        let input_to_present: Vec<u64> = self
            .samples
            .iter()
            .filter_map(FrameSample::input_to_present_ns)
            .collect();
        let input_to_gpu_completion: Vec<u64> = self
            .samples
            .iter()
            .filter_map(FrameSample::input_to_gpu_completion_ns)
            .collect();
        let host_cpu_times: Vec<u64> = self
            .samples
            .iter()
            .map(|sample| sample.host_cpu_ns)
            .filter(|value| *value > 0)
            .collect();
        let gpu_idle_gaps: Vec<u64> = self
            .samples
            .windows(2)
            .filter_map(|pair| match (pair[0].gpu_end_ns, pair[1].gpu_start_ns) {
                (Some(end), Some(start)) => start.checked_sub(end),
                _ => None,
            })
            .filter(|gap| *gap > 0)
            .collect();
        let has_input = self.samples.iter().any(|sample| sample.input_ns.is_some());
        let gpu_unavailable = if gpu_times.is_empty() {
            Some(
                self.gpu_unavailable
                    .unwrap_or(TimingUnavailable::MissingGpuTimestamp),
            )
        } else {
            None
        };
        let present_unavailable = if present_marks.is_empty() {
            Some(
                self.present_unavailable
                    .unwrap_or(TimingUnavailable::MissingPresentTimestamp),
            )
        } else {
            None
        };
        let frame_time_unavailable = frame_intervals.is_empty().then(|| {
            present_unavailable
                .or(gpu_unavailable)
                .unwrap_or(TimingUnavailable::NoFrameTimeSamples)
        });
        let input_to_present_unavailable = input_to_present.is_empty().then_some({
            if let Some(reason) = present_unavailable {
                reason
            } else if !has_input {
                TimingUnavailable::MissingInputTimestamp
            } else {
                TimingUnavailable::MissingPresentTimestamp
            }
        });
        let input_to_gpu_unavailable = input_to_gpu_completion.is_empty().then_some({
            if let Some(reason) = gpu_unavailable {
                reason
            } else if !has_input {
                TimingUnavailable::MissingInputTimestamp
            } else {
                TimingUnavailable::MissingGpuTimestamp
            }
        });
        let host_cpu_unavailable = host_cpu_times
            .is_empty()
            .then_some(TimingUnavailable::MissingHostCpuTime);
        let shader_compile_unavailable = (self.shader_compile_requests == 0)
            .then_some(TimingUnavailable::NoShaderCompileSamples);
        let shader_compile_stall_rate = (self.shader_compile_requests > 0)
            .then(|| self.shader_compile_stalls as f64 / self.shader_compile_requests as f64);
        let guest_work_unavailable = (self.guest_wall_ns == 0 || self.guest_instructions == 0)
            .then_some(TimingUnavailable::NoGuestWork);
        let guest_instructions_per_sec = (self.guest_wall_ns > 0 && self.guest_instructions > 0)
            .then(|| self.guest_instructions as f64 * 1_000_000_000.0 / self.guest_wall_ns as f64);
        GpuPresentSummary {
            sample_count: self.samples.len(),
            gpu_sample_count: gpu_times.len(),
            present_sample_count: present_marks.len(),
            gpu_unavailable,
            present_unavailable,
            frame_time: PercentileStats::from_ns(&frame_intervals),
            frame_time_unavailable,
            gpu_time: PercentileStats::from_ns(&gpu_times),
            cpu_submit: PercentileStats::from_ns(&cpu_submit),
            input_to_present: PercentileStats::from_ns(&input_to_present),
            input_to_present_unavailable,
            input_to_gpu_completion: PercentileStats::from_ns(&input_to_gpu_completion),
            input_to_gpu_unavailable,
            host_cpu_time: PercentileStats::from_ns(&host_cpu_times),
            host_cpu_unavailable,
            frame_time_1pct_low_fps: low_fps(&frame_intervals, 0.01),
            frame_time_0p1pct_low_fps: low_fps(&frame_intervals, 0.001),
            gpu_idle_gap_us: PercentileStats::from_ns(&gpu_idle_gaps).map(|stats| stats.p50_us()),
            shader_compile_requests: self.shader_compile_requests,
            shader_compile_stalls: self.shader_compile_stalls,
            shader_compile_stall_rate,
            shader_compile_unavailable,
            guest_instructions: self.guest_instructions,
            guest_wall_ns: self.guest_wall_ns,
            guest_instructions_per_sec,
            guest_work_unavailable,
        }
    }
}

#[cfg(target_os = "macos")]
const GPU_BURN_SHADER: &str = r#"
#include <metal_stdlib>
using namespace metal;

kernel void casa1_perf_gpu_burn(device uint *out [[buffer(0)]],
                                uint id [[thread_position_in_grid]]) {
    uint value = id + 1u;
    for (uint i = 0; i < 96u; ++i) {
        value = value * 1664525u + 1013904223u;
    }
    out[id] = value;
}
"#;

/// Run a real Metal compute submission per frame and record its GPU
/// completion timestamps. When `CAMetalLayer` vends a drawable the drawable is
/// presented and its `presentedTime` is correlated with the input timestamp;
/// a headless layer records the exact `NoDrawable` fallback instead.
#[cfg(target_os = "macos")]
pub fn measure_gpu_present_into(
    recorder: &mut GpuPresentRecorder,
    frames: usize,
) -> Result<(), String> {
    measure_gpu_present_with_mode(recorder, frames, false)
}

/// Windowed present mode: create a real `NSWindow`, attach a real
/// `CAMetalLayer` to its content view, then run `[NSApp run]` and submit one
/// frame per `NSTimer` tick so CoreAnimation actually composites the layer and
/// its drawables report a real `presentedTime`.  When the host has no
/// window-server display session or no run loop can be started, the recorder
/// carries the exact [`TimingUnavailable::NoDisplaySession`] /
/// [`TimingUnavailable::NoAppRunLoop`] reason; no timestamp is synthesized.
#[cfg(target_os = "macos")]
pub fn measure_gpu_present_windowed_into(
    recorder: &mut GpuPresentRecorder,
    frames: usize,
) -> Result<(), String> {
    measure_gpu_present_with_mode(recorder, frames, true)
}

#[cfg(target_os = "macos")]
unsafe fn pump_app_events_for(milliseconds: u64) {
    use objc::{class, msg_send, sel, sel_impl};
    let app: *mut objc::runtime::Object =
        unsafe { msg_send![class!(NSApplication), sharedApplication] };
    if app.is_null() {
        return;
    }
    let mode_name = std::ffi::CString::new("NSDefaultRunLoopMode").expect("mode name");
    let mode: *mut objc::runtime::Object =
        unsafe { msg_send![class!(NSString), stringWithUTF8String: mode_name.as_ptr()] };
    let deadline: *mut objc::runtime::Object = unsafe {
        msg_send![
            class!(NSDate),
            dateWithTimeIntervalSinceNow: (milliseconds as f64) / 1000.0
        ]
    };
    // NSAnyEventMask is all bits set; dequeue one event per call until the
    // deadline, then return so the measurement loop can continue.
    loop {
        let event: *mut objc::runtime::Object = unsafe {
            msg_send![
                app,
                nextEventMatchingMask: u64::MAX
                untilDate: deadline
                inMode: mode
                dequeue: true
            ]
        };
        if event.is_null() {
            break;
        }
        unsafe {
            let _: () = msg_send![app, sendEvent: event];
        }
    }
}

/// Ticks spent after the last submitted frame so CoreAnimation can commit the
/// outstanding transactions and deliver the drawables' presented handlers.
#[cfg(target_os = "macos")]
const WINDOWED_SETTLE_TICKS: usize = 30;

/// One frame per timer tick, then a fixed settle window: never more than
/// `frames + settle_ticks` ticks, even when no presented handler ever fires.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowTickDecision {
    Submit,
    Settle,
    Stop,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowRunControl {
    frames: usize,
    settle_ticks: usize,
    submitted: usize,
    settled: usize,
    stopped: bool,
    timer_invalidated: bool,
    window_closed: bool,
}

#[cfg(target_os = "macos")]
impl WindowRunControl {
    fn new(frames: usize, settle_ticks: usize) -> Self {
        Self {
            frames,
            settle_ticks,
            submitted: 0,
            settled: 0,
            stopped: false,
            timer_invalidated: false,
            window_closed: false,
        }
    }

    fn decide(&self) -> WindowTickDecision {
        if self.stopped {
            WindowTickDecision::Stop
        } else if self.submitted < self.frames {
            WindowTickDecision::Submit
        } else if self.settled < self.settle_ticks {
            WindowTickDecision::Settle
        } else {
            WindowTickDecision::Stop
        }
    }

    fn note_submitted(&mut self) {
        self.submitted += 1;
    }

    fn note_settled(&mut self) {
        self.settled += 1;
    }

    /// Idempotent: a second stop request (double `[NSApp stop:]` or an error
    /// path racing the normal stop) reports `false` and performs no work.
    fn request_stop(&mut self) -> bool {
        if self.stopped {
            return false;
        }
        self.stopped = true;
        true
    }

    /// Idempotent timer invalidation.
    fn request_timer_invalidation(&mut self) -> bool {
        if self.timer_invalidated {
            return false;
        }
        self.timer_invalidated = true;
        true
    }

    /// Idempotent window close.
    fn request_window_close(&mut self) -> bool {
        if self.window_closed {
            return false;
        }
        self.window_closed = true;
        true
    }
}

/// A submitted frame whose presented handler has not been observed yet. The
/// drawable is retained so its presented handler and timestamp stay valid.
#[cfg(target_os = "macos")]
struct PendingWindowFrame {
    sample: FrameSample,
    probe: crate::metal_backend::DrawableTimingProbe,
    // The layer vends autoreleased drawables. Retain it until its presented
    // handler fires so the handler registration and timestamp stay valid
    // across run-loop autorelease pool drains.
    _drawable: RetainedDrawable,
}

/// A retained `CAMetalDrawable` that is released exactly once when the frame
/// is finalized.
#[cfg(target_os = "macos")]
struct RetainedDrawable(*mut objc::runtime::Object);

#[cfg(target_os = "macos")]
impl RetainedDrawable {
    fn retain(drawable: &metal::MetalDrawableRef) -> Self {
        use metal::foreign_types::ForeignTypeRef;
        let object = drawable.as_ptr() as *mut objc::runtime::Object;
        // SAFETY: `object` is a live MTLDrawable; retain balances the release
        // in `Drop` and keeps it alive until presentation is observed.
        let _: () = unsafe {
            use objc::{msg_send, sel, sel_impl};
            msg_send![object, retain]
        };
        Self(object)
    }
}

#[cfg(target_os = "macos")]
impl Drop for RetainedDrawable {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: `self.0` was retained in `retain` and is released once here.
        let _: () = unsafe {
            use objc::{msg_send, sel, sel_impl};
            msg_send![self.0, release]
        };
    }
}

/// Drives the windowed measurement from the `NSApplication` run loop. Every
/// field is touched only on the main thread, inside the timer block.
#[cfg(target_os = "macos")]
struct WindowFrameDriver {
    recorder: *mut GpuPresentRecorder,
    layer: metal::MetalLayer,
    queue: metal::CommandQueue,
    pipeline: metal::ComputePipelineState,
    output: metal::Buffer,
    clock: MediaClock,
    app: *mut objc::runtime::Object,
    window: *mut std::ffi::c_void,
    control: WindowRunControl,
    pending: Vec<PendingWindowFrame>,
    sequence: u64,
}

#[cfg(target_os = "macos")]
impl WindowFrameDriver {
    fn tick(&mut self, timer: *mut objc::runtime::Object) {
        let tick_start = std::time::Instant::now();
        // Harvest completed presentations before deciding what this tick
        // submits, so a drawable presented between ticks is never missed.
        self.harvest(false);
        match self.control.decide() {
            WindowTickDecision::Submit => {
                self.control.note_submitted();
                if let Err(reason) = self.submit_frame() {
                    self.recorder().mark_present_unavailable(reason);
                    self.control.request_stop();
                }
            }
            WindowTickDecision::Settle => {
                self.control.note_settled();
                // Every submitted frame has delivered (or failed to deliver)
                // its presented handler; no need to burn the remaining settle
                // window before stopping.
                if self.pending.is_empty() {
                    self.control.request_stop();
                }
            }
            WindowTickDecision::Stop => {
                self.control.request_stop();
            }
        }
        if std::env::var_os("CASA1_PERF_DEBUG_WINDOW").is_some() {
            eprintln!(
                "[perf-window] tick submitted={} settled={} pending={} stopped={} elapsed_ms={:.1}",
                self.control.submitted,
                self.control.settled,
                self.pending.len(),
                self.control.stopped,
                tick_start.elapsed().as_secs_f64() * 1000.0
            );
        }
        if matches!(self.control.decide(), WindowTickDecision::Stop) {
            self.control.request_stop();
            // Drain the frames submitted before the stop tick; anything still
            // unobserved gets the exact never-fired reason in `harvest`.
            self.harvest(true);
            self.stop_timer_and_app(timer);
        }
    }

    fn recorder(&mut self) -> &mut GpuPresentRecorder {
        // SAFETY: `recorder` points at the caller's recorder, which outlives
        // this driver (the driver is stack-allocated inside the measurement
        // call and never escapes the main thread).
        unsafe { &mut *self.recorder }
    }

    fn submit_frame(&mut self) -> Result<(), TimingUnavailable> {
        use crate::metal_backend::{DrawableTimingProbe, GpuTimestampReading, GpuTimingProbe};

        let host_cpu_start = process_cpu_time_ns();
        let input_ns = self.clock.now_ns();
        let submit_start_ns = self.clock.now_ns();
        let command_buffer = self.queue.new_command_buffer();
        let gpu_probe = GpuTimingProbe::attach(command_buffer);
        {
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.pipeline);
            encoder.set_buffer(0, Some(&self.output), 0);
            encoder.dispatch_threads(
                metal::MTLSize::new(4096, 1, 1),
                metal::MTLSize::new(64, 1, 1),
            );
            encoder.end_encoding();
        }
        // A windowed layer must vend a drawable; no drawable means the window
        // server never made this layer presentable.
        let drawable = self
            .layer
            .next_drawable()
            .ok_or(TimingUnavailable::NoDrawable)?;
        let retained_drawable = RetainedDrawable::retain(drawable);
        let drawable_probe = DrawableTimingProbe::attach(drawable);
        {
            let pass = metal::RenderPassDescriptor::new().to_owned();
            if let Some(attachment) = pass.color_attachments().object_at(0) {
                attachment.set_texture(Some(drawable.texture()));
                attachment.set_load_action(metal::MTLLoadAction::Clear);
                attachment.set_store_action(metal::MTLStoreAction::Store);
                attachment.set_clear_color(metal::MTLClearColor::new(0.05, 0.05, 0.08, 1.0));
            }
            let encoder = command_buffer.new_render_command_encoder(&pass);
            encoder.end_encoding();
            command_buffer.present_drawable(drawable);
        }
        command_buffer.commit();
        let submit_end_ns = self.clock.now_ns();
        command_buffer.wait_until_completed();
        let host_cpu_ns = process_cpu_time_ns().saturating_sub(host_cpu_start);
        let mut sample = FrameSample::new(
            self.sequence,
            Some(input_ns),
            submit_start_ns,
            submit_end_ns,
        )
        .with_host_cpu_ns(host_cpu_ns);
        self.sequence += 1;

        match gpu_probe.snapshot() {
            Some(GpuTimestampReading::Measured {
                start_seconds,
                end_seconds,
            }) => match (
                self.clock.seconds_to_ns(start_seconds),
                self.clock.seconds_to_ns(end_seconds),
            ) {
                (Some(start_ns), Some(end_ns)) if end_ns >= start_ns => {
                    sample = sample.with_gpu_timestamps(start_ns, end_ns);
                }
                _ => self
                    .recorder()
                    .mark_gpu_unavailable(TimingUnavailable::MissingGpuTimestamp),
            },
            Some(GpuTimestampReading::UnsupportedDevice) => self
                .recorder()
                .mark_gpu_unavailable(TimingUnavailable::UnsupportedGpuTimestamp),
            Some(GpuTimestampReading::MissingTimestamp { .. }) | None => self
                .recorder()
                .mark_gpu_unavailable(TimingUnavailable::MissingGpuTimestamp),
        }

        // CoreAnimation commits the layer in the current run-loop iteration;
        // flushing here makes the presented handler observable on this tick.
        unsafe {
            use objc::{class, msg_send, sel, sel_impl};
            let _: () = msg_send![class!(CATransaction), flush];
        }
        self.pending.push(PendingWindowFrame {
            sample,
            probe: drawable_probe,
            _drawable: retained_drawable,
        });
        Ok(())
    }

    fn harvest(&mut self, final_pass: bool) {
        use crate::metal_backend::PresentTimestampReading;

        let mut index = 0;
        while index < self.pending.len() {
            match self.pending[index].probe.snapshot() {
                Some(reading) => {
                    let pending = self.pending.remove(index);
                    let mut sample = pending.sample;
                    match reading {
                        PresentTimestampReading::Measured { presented_seconds } => {
                            match self.clock.seconds_to_ns(presented_seconds) {
                                Some(present_ns) => {
                                    sample = sample.with_present_timestamp(present_ns)
                                }
                                None => self.recorder().mark_present_unavailable(
                                    TimingUnavailable::MissingPresentTimestamp,
                                ),
                            }
                        }
                        PresentTimestampReading::UnsupportedDevice => self
                            .recorder()
                            .mark_present_unavailable(TimingUnavailable::UnsupportedGpuTimestamp),
                        PresentTimestampReading::MissingTimestamp => self
                            .recorder()
                            .mark_present_unavailable(TimingUnavailable::MissingPresentTimestamp),
                    }
                    self.recorder().record(sample);
                }
                None if final_pass => {
                    let pending = self.pending.remove(index);
                    self.recorder()
                        .mark_present_unavailable(TimingUnavailable::PresentHandlerNeverFired);
                    self.recorder().record(pending.sample);
                }
                None => index += 1,
            }
        }
    }

    fn stop_timer_and_app(&mut self, timer: *mut objc::runtime::Object) {
        use objc::{class, msg_send, sel, sel_impl};
        if self.control.request_timer_invalidation() && !timer.is_null() {
            // SAFETY: `timer` is the live NSTimer that invoked this tick.
            let _: () = unsafe { msg_send![timer, invalidate] };
        }
        if self.app.is_null() {
            return;
        }
        // SAFETY: `app` is the shared NSApplication singleton, and this runs on
        // the main thread that called `[NSApp run]`.
        unsafe {
            let _: () = msg_send![self.app, stop: std::ptr::null_mut::<objc::runtime::Object>()];
            // `stop:` only takes effect after the run loop wakes; post an
            // application-defined event so `[NSApp run]` returns immediately
            // instead of waiting for another timer/display event.
            let event: *mut objc::runtime::Object = msg_send![
                class!(NSEvent),
                otherEventWithType: 15i64
                location: crate::mac_window::NSPoint::new(0.0, 0.0)
                modifierFlags: 0u64
                timestamp: 0.0f64
                windowNumber: 0i64
                context: std::ptr::null_mut::<objc::runtime::Object>()
                subtype: 0i16
                data1: 0i64
                data2: 0i64
            ];
            if !event.is_null() {
                let _: () = msg_send![self.app, postEvent: event atStart: true];
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for WindowFrameDriver {
    fn drop(&mut self) {
        if self.control.request_window_close() && !self.window.is_null() {
            crate::mac_window::close_nswindow(self.window);
        }
    }
}

/// Run the windowed capture under a real `NSApplication` run loop. One frame is
/// submitted per `NSTimer` tick; the loop then settles for
/// [`WINDOWED_SETTLE_TICKS`] so CoreAnimation can deliver the presented
/// handlers, and stops with `[NSApp stop:]` plus a wake event.
#[cfg(target_os = "macos")]
fn run_windowed_capture(
    recorder: &mut GpuPresentRecorder,
    frames: usize,
    layer: metal::MetalLayer,
    queue: metal::CommandQueue,
    pipeline: metal::ComputePipelineState,
    output: metal::Buffer,
    clock: MediaClock,
    window: *mut std::ffi::c_void,
) -> Result<(), String> {
    use objc::{class, msg_send, sel, sel_impl};

    let app: *mut objc::runtime::Object =
        unsafe { msg_send![class!(NSApplication), sharedApplication] };
    if app.is_null() {
        recorder.mark_present_unavailable(TimingUnavailable::NoAppRunLoop);
        return Ok(());
    }

    let mut driver = WindowFrameDriver {
        recorder: recorder as *mut GpuPresentRecorder,
        layer,
        queue,
        pipeline,
        output,
        clock,
        app,
        window,
        control: WindowRunControl::new(frames, WINDOWED_SETTLE_TICKS),
        pending: Vec::with_capacity(frames),
        sequence: 0,
    };
    let driver_ptr: *mut WindowFrameDriver = &mut driver;
    let tick_block = block::ConcreteBlock::new(move |timer: *mut objc::runtime::Object| {
        // SAFETY: the block runs only on the main thread inside `[NSApp run]`;
        // `driver` lives on this stack frame until the run loop returns.
        let driver = unsafe { &mut *driver_ptr };
        driver.tick(timer);
    });
    let tick_block = tick_block.copy();
    let timer: *mut objc::runtime::Object = unsafe {
        msg_send![
            class!(NSTimer),
            scheduledTimerWithTimeInterval: 1.0f64 / 120.0f64
            repeats: true
            block: &*tick_block
        ]
    };
    if timer.is_null() {
        recorder.mark_present_unavailable(TimingUnavailable::NoAppRunLoop);
        return Ok(());
    }

    // Blocks here until the timer's final tick invalidates itself and stops
    // the application (or the run loop exits on its own).
    unsafe {
        let _: () = msg_send![app, run];
    }
    // SAFETY: the run loop has returned, so no tick can race this cleanup.
    unsafe {
        let _: () = msg_send![timer, invalidate];
    }
    if !driver.control.stopped {
        // The run loop returned without the measurement asking it to stop.
        // Record the exact reason instead of leaving a default fallback.
        recorder.mark_present_unavailable(TimingUnavailable::NoAppRunLoop);
    }
    driver.harvest(true);
    drop(tick_block);
    Ok(())
}

#[cfg(target_os = "macos")]
fn measure_gpu_present_with_mode(
    recorder: &mut GpuPresentRecorder,
    frames: usize,
    windowed: bool,
) -> Result<(), String> {
    use crate::metal_backend::{
        DrawableTimingProbe, GpuTimestampReading, GpuTimingProbe, MetalGpuBackend,
        PresentTimestampReading,
    };
    use core_graphics_types::geometry::CGSize;
    use metal::foreign_types::ForeignType;

    if frames == 0 {
        return Err("GPU present measurement needs at least one frame".to_string());
    }
    let mut backend = MetalGpuBackend::new().map_err(|error| error.message.clone())?;
    let library = backend
        .compile_shader(GPU_BURN_SHADER)
        .map_err(|error| error.message.clone())?;
    let pipeline_id = backend
        .create_compute_pipeline("casa1_perf_gpu_burn", library)
        .map_err(|error| error.message.clone())?;
    let pipeline = backend
        .get_compute_pipeline(pipeline_id)
        .ok_or_else(|| "GPU present measurement: compute pipeline missing".to_string())?
        .to_owned();
    let device = backend.device().metal_device_owned();
    let queue = backend.command_queue().to_owned();
    let output = device.new_buffer(
        (4096 * std::mem::size_of::<u32>()) as u64,
        metal::MTLResourceOptions::StorageModeShared,
    );
    let layer = metal::MetalLayer::new();
    layer.set_device(&device);
    layer.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
    layer.set_drawable_size(CGSize {
        width: 320.0,
        height: 240.0,
    });
    layer.set_framebuffer_only(false);
    // Presentation timestamps require display-synchronised presentation; a
    // non-synced (tearing) layer may present without a display timestamp.
    layer.set_display_sync_enabled(true);
    // A windowed capture needs a real window-server session.  Window creation
    // returns null when NSApp/the window server is unavailable (headless CI,
    // ssh session, or a non-.app process without forced creation).  The exact
    // reason is recorded and the GPU work still runs, but no present timestamp
    // is invented.
    // AppKit window creation must run on the main thread (the explicit
    // main-queue only advances while the host loop pumps it).  A background
    // caller gets the exact no-display-session fallback instead of blocking.
    let on_main_thread = unsafe { libc::pthread_main_np() } != 0;
    let window = if windowed && on_main_thread {
        let previous_force = crate::mac_window::force_window_creation();
        crate::mac_window::set_force_window_creation(true);
        let created = crate::mac_window::create_nswindow(
            "Casa1 perf present capture",
            320,
            240,
            320,
            240,
            0x00C0_0000, // WS_CAPTION: a titled NSWindow
            0,
        );
        crate::mac_window::set_force_window_creation(previous_force);
        if created.is_null() {
            recorder.mark_present_unavailable(TimingUnavailable::NoDisplaySession);
            std::ptr::null_mut()
        } else {
            let attached = crate::mac_window::attach_cametal_layer_to_window(
                created,
                layer.as_ptr() as *mut std::ffi::c_void,
                64,
                64,
            );
            if attached.is_null() {
                recorder.mark_present_unavailable(TimingUnavailable::NoDisplaySession);
                crate::mac_window::close_nswindow(created);
                std::ptr::null_mut()
            } else {
                crate::mac_window::show_nswindow(created, true);
                layer.set_display_sync_enabled(true);
                created
            }
        }
    } else {
        std::ptr::null_mut()
    };
    if windowed && !on_main_thread {
        recorder.mark_present_unavailable(TimingUnavailable::NoDisplaySession);
    }
    let window_presenting = windowed && !window.is_null();
    if window_presenting {
        // Attach the CAMetalLayer to the window's content view and order the
        // window front. A created-but-detached layer can vend drawables, but
        // its presentedTime stays zero because nothing is composited.
        use objc::{class, msg_send, sel, sel_impl};
        unsafe {
            let window_obj = window as *mut objc::runtime::Object;
            let content: *mut objc::runtime::Object = msg_send![window_obj, contentView];
            if !content.is_null() {
                // Layer-hosting order: install the custom CAMetalLayer before
                // asking AppKit to host a layer, otherwise AppKit keeps its
                // own backing layer and the metal layer is never composited.
                let _: () = msg_send![content, setLayer: layer.as_ptr()];
                let _: () = msg_send![content, setWantsLayer: true];
            }
            // An ordinary window can be fully occluded by the terminal/IDE, in
            // which case the drawable is never composited and presentedTime
            // stays zero. Raise the capture window above normal windows.
            let _: () = msg_send![window_obj, setLevel: 1000i64];
            let _: () = msg_send![window_obj, setHidesOnDeactivate: false];
            let _: () = msg_send![
                window_obj,
                makeKeyAndOrderFront: std::ptr::null_mut::<objc::runtime::Object>()
            ];
            let _: () = msg_send![window_obj, orderFrontRegardless];
            let app: *mut objc::runtime::Object =
                msg_send![class!(NSApplication), sharedApplication];
            if !app.is_null() {
                let _: () = msg_send![app, setActivationPolicy: 0i64];
                let _: () = msg_send![app, finishLaunching];
                let _: () = msg_send![app, activateIgnoringOtherApps: true];
                if std::env::var_os("CASA1_PERF_DEBUG_WINDOW").is_some() {
                    let visible: bool = msg_send![window_obj, isVisible];
                    let occlusion: i64 = msg_send![window_obj, occlusionState];
                    let screens: *mut objc::runtime::Object = msg_send![class!(NSScreen), screens];
                    let screen_count: u64 = msg_send![screens, count];
                    eprintln!(
                        "[perf-window] visible={visible} occlusion={occlusion} screens={screen_count}"
                    );
                }
            }
        }
    }
    if window_presenting {
        unsafe { pump_app_events_for(50) };
        if std::env::var_os("CASA1_PERF_DEBUG_WINDOW").is_some() {
            use objc::{msg_send, sel, sel_impl};
            unsafe {
                let window_obj = window as *mut objc::runtime::Object;
                let occlusion: i64 = msg_send![window_obj, occlusionState];
                let is_visible: bool = msg_send![window_obj, isVisible];
                let on_active_space: bool = msg_send![window_obj, isOnActiveSpace];
                eprintln!(
                    "[perf-window] after pump: visible={is_visible} occlusion={occlusion} active_space={on_active_space}"
                );
            }
        }
    }
    let clock = MediaClock::capture().ok_or_else(|| {
        TimingUnavailable::UnsupportedGpuTimestamp
            .reason()
            .to_string()
    })?;
    if window_presenting {
        // Windowed presentation only produces a real `presentedTime` when the
        // process actually runs an `NSApplication` run loop: CoreAnimation
        // commits the layer there. Drive one frame per timer tick, settle for
        // a few ticks, then stop the application from inside the run loop.
        run_windowed_capture(
            recorder, frames, layer, queue, pipeline, output, clock, window,
        )?;
        return Ok(());
    }
    // A headless CAMetalLayer can still vend a drawable whose presentedTime
    // stays zero, and acquiring drawables every frame then throttles the
    // submission to the compositor. Present only while a real presentation
    // timestamp is being produced; otherwise keep measuring unthrottled GPU
    // work and report the exact presentation fallback.
    let mut present_enabled = window_presenting || !windowed;

    for sequence in 0..frames as u64 {
        let host_cpu_start = process_cpu_time_ns();
        let input_ns = clock.now_ns();
        let submit_start_ns = clock.now_ns();
        let command_buffer = queue.new_command_buffer();
        let gpu_probe = GpuTimingProbe::attach(command_buffer);
        {
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&pipeline);
            encoder.set_buffer(0, Some(&output), 0);
            encoder.dispatch_threads(
                metal::MTLSize::new(4096, 1, 1),
                metal::MTLSize::new(64, 1, 1),
            );
            encoder.end_encoding();
        }
        let drawable = present_enabled.then(|| layer.next_drawable()).flatten();
        let drawable_probe = drawable.map(DrawableTimingProbe::attach);
        if let Some(drawable) = drawable {
            // Render something into the drawable. Presenting a never-written
            // texture can be optimized away by the compositor and leaves
            // presentedTime at zero; a real clear pass makes it a presented
            // frame.
            let pass = metal::RenderPassDescriptor::new().to_owned();
            if let Some(attachment) = pass.color_attachments().object_at(0) {
                attachment.set_texture(Some(drawable.texture()));
                attachment.set_load_action(metal::MTLLoadAction::Clear);
                attachment.set_store_action(metal::MTLStoreAction::Store);
                attachment.set_clear_color(metal::MTLClearColor::new(0.05, 0.05, 0.08, 1.0));
            }
            let encoder = command_buffer.new_render_command_encoder(&pass);
            encoder.end_encoding();
            command_buffer.present_drawable(drawable);
        }
        command_buffer.commit();
        let submit_end_ns = clock.now_ns();
        command_buffer.wait_until_completed();
        if window_presenting {
            // Let AppKit actually deliver the frame to the window server.
            // Pumping CFRunLoop alone does not dispatch NSApplication events,
            // so the drawable would never be composited and presentedTime
            // would stay zero.
            unsafe { pump_app_events_for(5) };
        }
        if let Some(probe) = &drawable_probe {
            for _ in 0..2 {
                if probe.snapshot().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let host_cpu_ns = process_cpu_time_ns().saturating_sub(host_cpu_start);
        let mut sample = FrameSample::new(sequence, Some(input_ns), submit_start_ns, submit_end_ns)
            .with_host_cpu_ns(host_cpu_ns);

        match gpu_probe.snapshot() {
            Some(GpuTimestampReading::Measured {
                start_seconds,
                end_seconds,
            }) => match (
                clock.seconds_to_ns(start_seconds),
                clock.seconds_to_ns(end_seconds),
            ) {
                (Some(start_ns), Some(end_ns)) if end_ns >= start_ns => {
                    sample = sample.with_gpu_timestamps(start_ns, end_ns);
                }
                _ => recorder.mark_gpu_unavailable(TimingUnavailable::MissingGpuTimestamp),
            },
            Some(GpuTimestampReading::UnsupportedDevice) => {
                recorder.mark_gpu_unavailable(TimingUnavailable::UnsupportedGpuTimestamp);
            }
            Some(GpuTimestampReading::MissingTimestamp { .. }) | None => {
                recorder.mark_gpu_unavailable(TimingUnavailable::MissingGpuTimestamp);
            }
        }

        match drawable_probe {
            None => {
                recorder.mark_present_unavailable(TimingUnavailable::NoDrawable);
                present_enabled = false;
            }
            Some(probe) => match probe.snapshot() {
                Some(PresentTimestampReading::Measured { presented_seconds }) => match clock
                    .seconds_to_ns(presented_seconds)
                {
                    Some(present_ns) => {
                        sample = sample.with_present_timestamp(present_ns);
                    }
                    None => {
                        recorder
                            .mark_present_unavailable(TimingUnavailable::MissingPresentTimestamp);
                        present_enabled = false;
                    }
                },
                Some(PresentTimestampReading::UnsupportedDevice) => {
                    recorder.mark_present_unavailable(TimingUnavailable::UnsupportedGpuTimestamp);
                    present_enabled = false;
                }
                Some(PresentTimestampReading::MissingTimestamp) | None => {
                    recorder.mark_present_unavailable(TimingUnavailable::MissingPresentTimestamp);
                    present_enabled = false;
                }
            },
        }

        recorder.record(sample);
    }
    if !window.is_null() {
        crate::mac_window::close_nswindow(window);
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn measure_gpu_present_into(
    _recorder: &mut GpuPresentRecorder,
    _frames: usize,
) -> Result<(), String> {
    Err(TimingUnavailable::NoMetalDevice.reason().to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn measure_gpu_present_windowed_into(
    _recorder: &mut GpuPresentRecorder,
    _frames: usize,
) -> Result<(), String> {
    Err(TimingUnavailable::NoMetalDevice.reason().to_string())
}

/// Every KPI key emitted by [`GpuPresentSummary::to_json_metrics`]. The
/// performance gate uses this list to report one exact fallback reason for
/// all timestamp-backed metrics when the host cannot measure them.
pub const GPU_PRESENT_METRIC_KEYS: &[&str] = &[
    "gpu_frame_time_p50_us",
    "gpu_frame_time_p95_us",
    "gpu_frame_time_p99_us",
    "gpu_frame_time_p999_us",
    "gpu_frame_time_1pct_low_fps",
    "gpu_frame_time_0p1pct_low_fps",
    "gpu_time_p50_us",
    "gpu_time_p99_us",
    "cpu_submit_p50_us",
    "cpu_submit_p99_us",
    "input_to_present_p50_us",
    "input_to_present_p99_us",
    "input_to_gpu_completion_p50_us",
    "input_to_gpu_completion_p99_us",
    "host_cpu_time_p50_us",
    "shader_compile_stall_rate_measured",
    "guest_instructions_per_sec",
    "gpu_idle_gap_us",
];

/// Convenience wrapper returning a summary from a fresh headless measurement.
pub fn measure_gpu_present(frames: usize) -> Result<GpuPresentSummary, String> {
    let mut recorder = GpuPresentRecorder::new();
    measure_gpu_present_into(&mut recorder, frames)?;
    Ok(recorder.summary())
}

/// Convenience wrapper returning a summary from a fresh windowed measurement.
pub fn measure_gpu_present_windowed(frames: usize) -> Result<GpuPresentSummary, String> {
    let mut recorder = GpuPresentRecorder::new();
    measure_gpu_present_windowed_into(&mut recorder, frames)?;
    Ok(recorder.summary())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Block Chaining Tests ---

    #[test]
    fn block_chaining_no_chain_for_cold_block() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);

        for _ in 0..5 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }

        let chained = cache.try_chain(0x1000);
        assert!(!chained);
        assert_eq!(cache.active_chain_count(), 0);
    }

    #[test]
    fn block_chaining_does_not_create_duplicate_chains() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);

        for _ in 0..10 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }
        assert!(cache.try_chain(0x1000));
        // Repeated attempts must not push duplicate chain entries.
        assert!(!cache.try_chain(0x1000));
        assert!(!cache.try_chain(0x1000));
        assert_eq!(cache.active_chain_count(), 1);
        assert_eq!(cache.total_chains_created(), 1);
    }

    #[test]
    fn block_chaining_invalidate_range() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);
        cache.register_block(0x3000, 0x4000, 48, 8);

        cache.invalidate_range(0x1500, 0x2500);
        assert_eq!(cache.block_count(), 2); // 0x1000 and 0x3000 remain
    }

    // --- Lazy JIT Tests ---

    // --- Address Translation Cache Tests ---

    #[test]
    fn address_translation_cache_eviction() {
        let mut cache = AddressTranslationCache::new(3);
        cache.insert(0x1000, 0x2000, 4096, 0);
        cache.insert(0x2000, 0x3000, 4096, 0);
        cache.insert(0x3000, 0x4000, 4096, 0);
        assert_eq!(cache.entry_count(), 3);

        cache.insert(0x4000, 0x5000, 4096, 0);
        assert_eq!(cache.entry_count(), 3); // One was evicted
    }

    #[test]
    fn address_translation_cache_invalidate_range() {
        let mut cache = AddressTranslationCache::new(100);
        cache.insert(0x1000, 0x2000, 4096, 0);
        cache.insert(0x2000, 0x3000, 4096, 0);
        cache.insert(0x3000, 0x4000, 4096, 0);

        cache.invalidate_range(0x1500, 0x2500);
        assert_eq!(cache.entry_count(), 2); // 0x1000 and 0x3000 remain
    }

    // --- Parallel Shader Compilation Tests ---

    #[test]
    fn shader_compiler_failed_job() {
        let mut compiler = ParallelShaderCompiler::new(4);
        let id = compiler.submit_job(
            "def456".to_string(),
            "fragment".to_string(),
            "main".to_string(),
        );

        compiler.mark_compiling(id).unwrap();
        compiler
            .mark_failed(id, "syntax error".to_string())
            .unwrap();

        assert_eq!(compiler.failed_count(), 1);
        let job = compiler.get_job(id).unwrap();
        assert!(matches!(job.status, ShaderCompileStatus::Failed(_)));
    }

    #[test]
    fn block_chaining_invalidate_range_breaks_target_chains() {
        let mut cache = BlockChainingCache::new();
        cache.register_block(0x1000, 0x2000, 64, 10);
        cache.register_block(0x2000, 0x3000, 32, 5);
        cache.register_block(0x3000, 0x4000, 48, 8);

        for _ in 0..10 {
            cache.record_execution(0x1000, 0x2000).unwrap();
        }
        for _ in 0..10 {
            cache.record_execution(0x2000, 0x3000).unwrap();
        }
        cache.try_chain(0x1000); // 0x1000 -> 0x2000
        cache.try_chain(0x2000); // 0x2000 -> 0x3000
        assert_eq!(cache.active_chain_count(), 2);

        // Invalidate the target of the 0x1000 chain; the chain must be
        // deactivated even though the source block survives.
        cache.invalidate_range(0x2000, 0x3000);
        assert_eq!(cache.active_chain_count(), 0);
        assert_eq!(cache.block_count(), 2); // 0x1000 and 0x3000 remain
    }

    // --- Metal Command Batching Tests ---

    // --- GPU Upload Streaming Tests ---

    #[test]
    fn upload_streamer_wrap_around() {
        let mut streamer = GpuUploadStreamer::new(1024);
        let buf = streamer.create_streaming_buffer(1024);

        streamer.allocate(buf, 512).unwrap();
        streamer.allocate(buf, 512).unwrap();

        // Buffer is full; allocating more within the same frame must fail
        // instead of silently reusing offsets that are still in flight.
        assert!(streamer.allocate(buf, 256).is_err());

        // After advancing to a new frame the ring wraps to the start.
        streamer.advance_frame();
        let offset = streamer.allocate(buf, 256).unwrap();
        assert_eq!(offset, 0);
    }

    #[test]
    fn upload_streamer_allocation_larger_than_buffer() {
        let mut streamer = GpuUploadStreamer::new(4096);
        let buf = streamer.create_streaming_buffer(1024);

        assert!(streamer.allocate(buf, 2048).is_err());
    }

    #[test]
    fn upload_streamer_respects_ring_capacity() {
        let mut streamer = GpuUploadStreamer::new(4096);
        let buf = streamer.create_streaming_buffer(8192);

        // The buffer claims more than the ring pool it came from; the ring
        // size caps allocations.
        assert!(streamer.allocate(buf, 8192).is_err());
        assert_eq!(streamer.allocate(buf, 3000).unwrap(), 0);
    }

    // --- Frame Pacing Tests ---

    // --- Phase 7: File Cache Tests ---

    #[test]
    fn file_cache_eviction() {
        let mut cache = FileCache::new(20); // Very small cache

        cache.insert("a.txt", vec![0u8; 10]).unwrap();
        cache.insert("b.txt", vec![0u8; 10]).unwrap();
        assert_eq!(cache.entry_count(), 2);

        // Insert a third file — should evict the LRU (a.txt)
        cache.insert("c.txt", vec![0u8; 10]).unwrap();
        assert_eq!(cache.entry_count(), 2);
        assert!(
            cache.get("a.txt").is_none(),
            "a.txt should have been evicted"
        );
        assert!(cache.get("b.txt").is_some(), "b.txt should still be cached");
        assert!(cache.get("c.txt").is_some(), "c.txt should be cached");
    }

    #[test]
    fn file_cache_invalidate() {
        let mut cache = FileCache::new(1024);
        cache.insert("test.txt", vec![1, 2, 3]).unwrap();
        assert!(cache.get("test.txt").is_some());

        cache.invalidate("test.txt");
        assert!(cache.get("test.txt").is_none());
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn file_cache_too_large() {
        let mut cache = FileCache::new(10);
        let result = cache.insert("big.txt", vec![0u8; 100]);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // --- Phase 7: Path Resolution Cache Tests ---

    #[test]
    fn path_resolution_cache_invalidate_prefix() {
        let mut cache = PathResolutionCache::new();

        cache
            .resolve("C:\\Windows\\a.txt", |p| Ok(PathBuf::from(p)))
            .unwrap();
        cache
            .resolve("C:\\Windows\\b.txt", |p| Ok(PathBuf::from(p)))
            .unwrap();
        cache
            .resolve("C:\\Game\\c.txt", |p| Ok(PathBuf::from(p)))
            .unwrap();

        assert_eq!(cache.entry_count(), 3);

        cache.invalidate_prefix("C:\\Windows");
        assert_eq!(cache.entry_count(), 1);
        assert!(cache.cache.contains_key("C:\\Game\\c.txt"));
    }

    // --- Phase 7: Async File Reader Tests ---

    #[test]
    fn async_file_reader_wait_timeout() {
        let mut reader = AsyncFileReader::new();
        // Request for non-existent ID should timeout
        let result = reader.wait_for(99999, 10);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // --- Phase 7: Memory-Mapped File Tests ---

    #[test]
    fn mmapped_file_out_of_bounds() {
        let dir = std::env::temp_dir();
        let path = dir.join("casa1_test_mmap_oob.bin");
        std::fs::write(&path, b"short").unwrap();

        let mf = MmappedFile::open(&path).unwrap();
        let mut buf = [0u8; 100];
        let result = mf.read(0, &mut buf);
        assert!(result.is_err(), "expected Err, got {result:?}");

        drop(mf);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mmapped_file_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("casa1_test_mmap_empty.bin");
        std::fs::write(&path, "").unwrap();

        let mf = MmappedFile::open(&path).unwrap();
        assert!(!mf.mapped);
        assert_eq!(mf.size, 0);

        drop(mf);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mmapped_file_nonexistent() {
        let path = std::path::PathBuf::from("/tmp/casa1_nonexistent_mmap_test_12345");
        let result = MmappedFile::open(&path);
        assert!(result.is_err(), "expected Err for nonexistent mmap file");
    }

    // --- End-to-end GPU/present measurement (audit P1 #5) ---

    #[test]
    fn percentile_ns_rejects_empty_and_pins_single_outlier_boundaries() {
        assert_eq!(percentile_ns(&[], 0.50), None);
        assert_eq!(percentile_ns(&[7], 0.0), Some(7));
        assert_eq!(percentile_ns(&[7], 0.50), Some(7));
        assert_eq!(percentile_ns(&[7], 0.999), Some(7));
        assert_eq!(percentile_ns(&[7], 1.0), Some(7));

        let sorted = [1_u64, 2, 3, 1000];
        assert_eq!(percentile_ns(&sorted, 0.50), Some(2));
        assert_eq!(percentile_ns(&sorted, 0.99), Some(1000));
        assert_eq!(percentile_ns(&sorted, 0.999), Some(1000));
        assert_eq!(percentile_ns(&sorted, f64::NAN), Some(1));
        assert_eq!(percentile_ns(&sorted, -1.0), Some(1));
        assert_eq!(percentile_ns(&sorted, 2.0), Some(1000));
    }

    #[test]
    fn percentile_stats_from_ns_rejects_empty_and_pins_outlier_percentiles() {
        assert_eq!(PercentileStats::from_ns(&[]), None);

        let stats = PercentileStats::from_ns(&[1, 2, 3, 4, 1000]).expect("one or more samples");
        assert_eq!(stats.sample_count, 5);
        assert_eq!(stats.p50_ns, 3);
        assert_eq!(stats.p95_ns, 1000);
        assert_eq!(stats.p99_ns, 1000);
        assert_eq!(stats.p999_ns, 1000);
        assert_eq!(stats.p50_us(), 0.003);
        assert_eq!(stats.p999_us(), 1.0);
    }

    #[test]
    fn low_fps_rejects_empty_and_pins_worst_outlier_average() {
        assert_eq!(low_fps(&[], 0.01), None);
        assert_eq!(low_fps(&[0, 0], 0.01), None);

        let samples = [1_000_000_u64, 1_000_000, 1_000_000, 10_000_000];
        assert_eq!(low_fps(&samples, 0.25), Some(100.0));
        assert_eq!(low_fps(&samples, 0.0001), Some(100.0));
    }

    #[test]
    fn timing_unavailable_fallback_reasons_are_exact() {
        assert_eq!(
            TimingUnavailable::NoMetalDevice.reason(),
            "no Metal device is available; GPU and drawable timestamps cannot be captured"
        );
        assert_eq!(
            TimingUnavailable::MissingGpuTimestamp.reason(),
            "Metal command buffer completed without GPUStartTime/GPUEndTime timestamps"
        );
        assert_eq!(
            TimingUnavailable::UnsupportedGpuTimestamp.reason(),
            "the Metal device does not expose command-buffer GPU timestamps"
        );
        assert_eq!(
            TimingUnavailable::NoDrawable.reason(),
            "CAMetalLayer.nextDrawable returned no drawable (headless presentation); \
             drawable presentedTime is unavailable"
        );
        assert_eq!(
            TimingUnavailable::MissingPresentTimestamp.reason(),
            "CAMetalLayer drawable reported presentedTime=0; no display presentation occurred"
        );
        assert_eq!(
            TimingUnavailable::MissingInputTimestamp.reason(),
            "no input-event timestamp was correlated with the measured frames"
        );
        assert_eq!(
            TimingUnavailable::NoFrameTimeSamples.reason(),
            "fewer than two real present or GPU-completion timestamps were recorded"
        );
    }

    #[test]
    fn gpu_timing_conversion_rejects_non_finite_and_pins_known_seconds() {
        let clock = MediaClock::from_parts(Instant::now(), 100.0).expect("synthetic media clock");
        assert_eq!(clock.seconds_to_ns(100.002), Some(2_000_000));
        assert_eq!(clock.seconds_to_ns(100.0), Some(0));
        assert_eq!(clock.seconds_to_ns(99.999), None);
        assert_eq!(clock.seconds_to_ns(f64::NAN), None);
        assert!(MediaClock::from_parts(Instant::now(), 0.0).is_none());

        let sample = FrameSample::new(1, Some(100), 200, 260).with_gpu_timestamps(1_000, 2_500);
        assert_eq!(sample.cpu_submit_ns(), Some(60));
        assert_eq!(sample.gpu_time_ns(), Some(1_500));
    }

    #[test]
    fn present_timestamp_correlation_rejects_missing_input_and_pins_exact_durations() {
        let sample = FrameSample::new(7, Some(1_000), 1_100, 1_200)
            .with_gpu_timestamps(1_400, 1_900)
            .with_present_timestamp(1_500);
        assert_eq!(sample.cpu_submit_ns(), Some(100));
        assert_eq!(sample.gpu_time_ns(), Some(500));
        assert_eq!(sample.input_to_present_ns(), Some(500));
        assert_eq!(sample.input_to_gpu_completion_ns(), Some(900));
        assert_eq!(sample.present_to_gpu_end_ns(), Some(400));
        assert_eq!(sample.frame_marker_ns(), Some(1_500));

        let without_present =
            FrameSample::new(8, Some(1_000), 1_100, 1_200).with_gpu_timestamps(1_400, 1_900);
        assert_eq!(without_present.input_to_present_ns(), None);
        assert_eq!(without_present.frame_marker_ns(), Some(1_900));

        let without_input = FrameSample::new(9, None, 1_100, 1_200)
            .with_gpu_timestamps(1_400, 1_900)
            .with_present_timestamp(1_500);
        assert_eq!(without_input.input_to_present_ns(), None);
        assert_eq!(without_input.input_to_gpu_completion_ns(), None);
    }

    #[test]
    fn gpu_present_recorder_requires_real_samples_and_reports_exact_fallback() {
        let summary = GpuPresentRecorder::new().summary();
        assert_eq!(summary.sample_count, 0);
        assert_eq!(
            summary.gpu_unavailable,
            Some(TimingUnavailable::MissingGpuTimestamp)
        );
        assert_eq!(
            summary.present_unavailable,
            Some(TimingUnavailable::MissingPresentTimestamp)
        );
        assert_eq!(summary.gpu_time, None);
        assert_eq!(summary.frame_time, None);
        let metrics = summary.to_json_metrics();
        assert_eq!(
            metrics["gpu_time_p50_us"]["available"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            metrics["gpu_time_p50_us"]["reason"],
            serde_json::Value::String(TimingUnavailable::MissingGpuTimestamp.reason().to_string())
        );

        let mut unsupported = GpuPresentRecorder::new();
        unsupported.mark_gpu_unavailable(TimingUnavailable::UnsupportedGpuTimestamp);
        unsupported.mark_present_unavailable(TimingUnavailable::NoDrawable);
        let summary = unsupported.summary();
        assert_eq!(
            summary.gpu_unavailable,
            Some(TimingUnavailable::UnsupportedGpuTimestamp)
        );
        assert_eq!(
            summary.present_unavailable,
            Some(TimingUnavailable::NoDrawable)
        );
        let metrics = summary.to_json_metrics();
        assert_eq!(
            metrics["input_to_present_p50_us"]["reason"],
            serde_json::Value::String(TimingUnavailable::NoDrawable.reason().to_string())
        );
    }

    #[test]
    fn gpu_present_summary_rejects_bookkeeping_and_pins_real_percentiles_and_lows() {
        let mut recorder = GpuPresentRecorder::new();
        recorder.record(
            FrameSample::new(1, Some(500), 100, 200)
                .with_gpu_timestamps(1_000, 2_000)
                .with_present_timestamp(3_000)
                .with_host_cpu_ns(50),
        );
        recorder.record(
            FrameSample::new(2, Some(600), 300, 400)
                .with_gpu_timestamps(5_000, 9_000)
                .with_present_timestamp(7_000)
                .with_host_cpu_ns(60),
        );
        recorder.record(
            FrameSample::new(3, Some(700), 500, 600)
                .with_gpu_timestamps(10_000, 11_000)
                .with_present_timestamp(12_000)
                .with_host_cpu_ns(70),
        );
        let summary = recorder.summary();
        assert_eq!(summary.sample_count, 3);
        assert_eq!(summary.gpu_sample_count, 3);
        assert_eq!(summary.present_sample_count, 3);
        assert_eq!(summary.frame_time.expect("frame time").p50_ns, 4_000);
        assert_eq!(summary.gpu_time.expect("gpu time").p50_ns, 1_000);
        assert_eq!(summary.gpu_time.expect("gpu time").p99_ns, 4_000);
        assert_eq!(summary.cpu_submit.expect("submit").p50_ns, 100);
        assert_eq!(
            summary.input_to_present.expect("input->present").p50_ns,
            6_400
        );
        assert_eq!(
            summary
                .input_to_gpu_completion
                .expect("input->gpu end")
                .p99_ns,
            10_300
        );
        assert_eq!(summary.host_cpu_time.expect("host cpu").p50_ns, 60);
        assert_eq!(summary.frame_time_1pct_low_fps, Some(200_000.0));
        assert_eq!(summary.frame_time_0p1pct_low_fps, Some(200_000.0));
        assert_eq!(summary.gpu_idle_gap_us, Some(1.0));

        let metrics = summary.to_json_metrics();
        assert_eq!(metrics["gpu_frame_time_p50_us"]["value"], 4.0);
        assert_eq!(metrics["gpu_time_p99_us"]["value"], 4.0);
        assert_eq!(metrics["cpu_submit_p50_us"]["value"], 0.1);
        assert_eq!(metrics["input_to_present_p50_us"]["value"], 6.4);
        assert_eq!(metrics["input_to_present_p99_us"]["value"], 11.3);
        assert_eq!(metrics["input_to_gpu_completion_p99_us"]["value"], 10.3);
        assert_eq!(metrics["host_cpu_time_p50_us"]["value"], 0.06);
        assert_eq!(metrics["gpu_idle_gap_us"]["value"], 1.0);
    }

    #[test]
    fn gpu_present_recorder_reports_missing_input_shader_and_guest_metrics_exactly() {
        let mut recorder = GpuPresentRecorder::new();
        recorder.record(
            FrameSample::new(1, None, 100, 200)
                .with_gpu_timestamps(1_000, 2_000)
                .with_present_timestamp(2_500),
        );
        let summary = recorder.summary();
        assert_eq!(
            summary.input_to_present_unavailable,
            Some(TimingUnavailable::MissingInputTimestamp)
        );
        assert_eq!(
            summary.shader_compile_unavailable,
            Some(TimingUnavailable::NoShaderCompileSamples)
        );
        assert_eq!(
            summary.guest_work_unavailable,
            Some(TimingUnavailable::NoGuestWork)
        );
        let metrics = summary.to_json_metrics();
        assert_eq!(
            metrics["input_to_present_p50_us"]["reason"],
            serde_json::Value::String(
                TimingUnavailable::MissingInputTimestamp
                    .reason()
                    .to_string()
            )
        );
        assert_eq!(
            metrics["shader_compile_stall_rate_measured"]["reason"],
            serde_json::Value::String(
                TimingUnavailable::NoShaderCompileSamples
                    .reason()
                    .to_string()
            )
        );
        assert_eq!(
            metrics["guest_instructions_per_sec"]["reason"],
            serde_json::Value::String(TimingUnavailable::NoGuestWork.reason().to_string())
        );

        recorder.record_shader_compile(false);
        recorder.record_shader_compile(true);
        recorder.record_guest_work(1_000, 2_000_000);
        let summary = recorder.summary();
        assert_eq!(summary.shader_compile_requests, 2);
        assert_eq!(summary.shader_compile_stalls, 1);
        assert_eq!(summary.shader_compile_stall_rate, Some(0.5));
        assert_eq!(summary.guest_instructions_per_sec, Some(500_000.0));
    }

    #[test]
    fn dispatch_stats_missing_partial_malformed_and_zero_documents_report_exact_reasons() {
        let directory = std::env::temp_dir().join(format!(
            "casa1-dispatch-stats-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::create_dir_all(&directory).expect("create dispatch stats temp dir");
        let missing = directory.join("absent.json");
        let report = DispatchStatsReport::from_path(&missing);
        assert_eq!(report.stats, None);
        assert_eq!(
            report.unavailable,
            Some(DispatchStatsUnavailable::Absent(missing.clone()))
        );
        assert_eq!(
            report
                .unavailable
                .as_ref()
                .map(DispatchStatsUnavailable::reason),
            Some(format!(
                "dispatch statistics file {} does not exist",
                missing.display()
            ))
        );

        let partial = directory.join("partial.json");
        std::fs::write(&partial, r#"{"schema":1,"parallel_dispatched":7}"#)
            .expect("write partial dispatch stats");
        let report = DispatchStatsReport::from_path(&partial);
        assert_eq!(
            report.unavailable,
            Some(DispatchStatsUnavailable::MissingField {
                path: partial.clone(),
                field: "barrier_calls"
            })
        );
        assert_eq!(
            report
                .unavailable
                .as_ref()
                .map(DispatchStatsUnavailable::reason),
            Some(format!(
                "dispatch statistics file {} is partial: required field `barrier_calls` is missing or not an unsigned integer",
                partial.display()
            ))
        );

        let malformed = directory.join("malformed.json");
        std::fs::write(&malformed, "!").expect("write malformed dispatch stats");
        let report = DispatchStatsReport::from_path(&malformed);
        assert_eq!(
            report
                .unavailable
                .as_ref()
                .map(DispatchStatsUnavailable::reason),
            Some(format!(
                "dispatch statistics file {} is malformed: expected value at line 1 column 1",
                malformed.display()
            ))
        );

        let zero = directory.join("zero.json");
        std::fs::write(
            &zero,
            r#"{"schema":1,"parallel_dispatched":0,"barrier_calls":0}"#,
        )
        .expect("write zero dispatch stats");
        let report = DispatchStatsReport::from_path(&zero);
        assert_eq!(
            report.unavailable,
            Some(DispatchStatsUnavailable::ZeroDispatches { path: zero.clone() })
        );
        let metrics = report.to_json_metrics();
        assert_eq!(
            metrics["owner_barrier_ratio"]["available"],
            serde_json::Value::Bool(false)
        );
        assert_eq!(
            metrics["owner_barrier_ratio"]["reason"],
            serde_json::Value::String(format!(
                "dispatch statistics file {} recorded zero host-thunk dispatches; owner-barrier ratio is undefined",
                zero.display()
            ))
        );

        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn dispatch_stats_ratio_boundary_math_is_exact() {
        let directory = std::env::temp_dir().join(format!(
            "casa1-dispatch-ratio-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::create_dir_all(&directory).expect("create dispatch ratio temp dir");
        let path = directory.join("stats.json");
        std::fs::write(
            &path,
            r#"{
                "schema": 1,
                "parallel_dispatched": 3,
                "barrier_calls": 1,
                "stateless_dispatched": 2,
                "read_mostly_dispatched": 1,
                "owner_only_barriers": 1,
                "fallback_barriers": 0,
                "categories": {"kernel32": {"dispatched": 3, "fallbacks": 1}},
                "barrier_reasons": {"owner-only": 1},
                "guest_instructions": 500,
                "wall_ns": 1000000
            }"#,
        )
        .expect("write dispatch ratio stats");
        let report = DispatchStatsReport::from_path(&path);
        let stats = report.stats.as_ref().expect("stats available");
        assert_eq!(stats.total_dispatches(), 4);
        assert_eq!(stats.owner_barrier_ratio(), Some(0.25));
        assert_eq!(stats.parallel_dispatch_ratio(), Some(0.75));
        assert_eq!(
            stats.time_per_1000_guest_instructions_ns(),
            Some(2_000_000.0)
        );
        let metrics = report.to_json_metrics();
        assert_eq!(metrics["owner_barrier_ratio"]["value"], 0.25);
        assert_eq!(
            metrics["time_per_1000_guest_instructions_ns"]["value"],
            2_000_000.0
        );
        assert_eq!(report.human_lines()[1], "barrier_reasons=[owner-only:1]");

        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn dispatch_stats_zero_snapshot_writer_never_fabricates_a_ratio() {
        let shared = crate::runtime::ProcessShared::default();
        let snapshot = shared.api_dispatch_snapshot();
        let stats = DispatchStats::from_runtime_snapshot(&snapshot, 1_000, 5_000);
        assert_eq!(stats.parallel_dispatched, 0);
        assert_eq!(stats.barrier_calls, 0);
        assert_eq!(stats.owner_barrier_ratio(), None);
        assert_eq!(stats.time_per_1000_guest_instructions_ns(), Some(5_000.0));
        let document = stats.to_json();
        assert_eq!(document["owner_barrier_ratio"], serde_json::Value::Null);
        let text = serde_json::to_string(&document).expect("serialize dispatch stats");
        assert_eq!(
            DispatchStatsReport::from_json(Path::new("snapshot.json"), &text),
            Err(DispatchStatsUnavailable::ZeroDispatches {
                path: PathBuf::from("snapshot.json")
            })
        );
    }

    #[test]
    fn native_relative_ratio_refuses_zero_and_missing_sides() {
        assert_eq!(
            native_relative_ratio(false, 100, true, 10),
            Err(NativeRatioUnavailable::Casa1Unavailable)
        );
        assert_eq!(
            native_relative_ratio(true, 100, false, 10),
            Err(NativeRatioUnavailable::NativeUnavailable)
        );
        assert_eq!(
            native_relative_ratio(true, 0, true, 10),
            Err(NativeRatioUnavailable::Casa1ZeroTime)
        );
        assert_eq!(
            native_relative_ratio(true, 100, true, 0),
            Err(NativeRatioUnavailable::NativeZeroTime)
        );
        assert_eq!(native_relative_ratio(true, 100, true, 10), Ok(10.0));
        assert_eq!(
            NativeRatioUnavailable::NativeZeroTime.reason(),
            "native reference measured zero wall time; native-relative ratio refused"
        );
    }

    #[test]
    fn windowed_present_missing_display_session_reports_exact_reason() {
        let mut recorder = GpuPresentRecorder::new();
        recorder.mark_present_unavailable(TimingUnavailable::NoDisplaySession);
        let summary = recorder.summary();
        assert_eq!(
            summary.present_unavailable,
            Some(TimingUnavailable::NoDisplaySession)
        );
        assert_eq!(
            summary.to_json_metrics()["input_to_present_p50_us"]["reason"],
            serde_json::Value::String(TimingUnavailable::NoDisplaySession.reason().to_string())
        );
        assert_eq!(
            TimingUnavailable::NoDisplaySession.reason(),
            "no macOS window-server display session is available; a windowed CAMetalLayer cannot present and presentedTime is unavailable"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn windowed_present_zero_frames_rejects_with_exact_error() {
        assert_eq!(
            measure_gpu_present_windowed(0).expect_err("zero frames must be rejected"),
            "GPU present measurement needs at least one frame"
        );
    }

    #[test]
    fn windowed_present_missing_display_fallback_never_fabricates_present() {
        let mut recorder = GpuPresentRecorder::new();
        recorder.mark_present_unavailable(TimingUnavailable::NoDisplaySession);
        recorder.record(FrameSample::new(0, Some(10), 20, 30));
        let summary = recorder.summary();
        assert_eq!(summary.present_sample_count, 0);
        assert_eq!(summary.input_to_present, None);
        assert_eq!(
            summary.present_unavailable,
            Some(TimingUnavailable::NoDisplaySession)
        );
        assert_eq!(
            summary.input_to_present_unavailable,
            Some(TimingUnavailable::NoDisplaySession)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn windowed_present_stop_before_first_frame_aborts_without_submit() {
        let mut control = WindowRunControl::new(5, WINDOWED_SETTLE_TICKS);
        assert_eq!(control.decide(), WindowTickDecision::Submit);
        assert!(control.request_stop());
        assert_eq!(control.decide(), WindowTickDecision::Stop);
        assert_eq!(control.submitted, 0);
        assert!(!control.request_stop());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn windowed_present_timer_invalidated_once_on_error() {
        let mut control = WindowRunControl::new(3, WINDOWED_SETTLE_TICKS);
        assert_eq!(control.request_timer_invalidation(), true);
        assert_eq!(control.request_timer_invalidation(), false);
        assert_eq!(control.request_stop(), true);
        assert_eq!(control.request_stop(), false);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn windowed_present_handler_missing_times_out_with_exact_reason() {
        let mut control = WindowRunControl::new(2, WINDOWED_SETTLE_TICKS);
        let mut ticks = 0usize;
        loop {
            match control.decide() {
                WindowTickDecision::Submit => control.note_submitted(),
                WindowTickDecision::Settle => control.note_settled(),
                WindowTickDecision::Stop => break,
            }
            ticks += 1;
            assert!(
                ticks <= 2 + WINDOWED_SETTLE_TICKS,
                "presented handler timeout must be bounded"
            );
        }
        assert_eq!(control.submitted, 2);
        assert_eq!(control.settled, WINDOWED_SETTLE_TICKS);
        assert_eq!(control.decide(), WindowTickDecision::Stop);
        assert_eq!(
            TimingUnavailable::PresentHandlerNeverFired.reason(),
            "CAMetalLayer drawable presented handler never fired before the NSApplication \
             run loop stopped; no display presentation was observed"
        );
        let mut recorder = GpuPresentRecorder::new();
        recorder.mark_present_unavailable(TimingUnavailable::PresentHandlerNeverFired);
        recorder.record(FrameSample::new(0, Some(10), 20, 30));
        let summary = recorder.summary();
        assert_eq!(
            summary.present_unavailable,
            Some(TimingUnavailable::PresentHandlerNeverFired)
        );
        assert_eq!(summary.present_sample_count, 0);
    }

    #[test]
    fn windowed_present_no_run_loop_unavailable_reason_is_exact() {
        assert_eq!(
            TimingUnavailable::NoAppRunLoop.reason(),
            "the macOS NSApplication run loop could not be started; windowed presentation \
             timestamps cannot be observed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn windowed_present_double_stop_and_close_are_idempotent() {
        let mut control = WindowRunControl::new(1, 1);
        assert_eq!(control.request_stop(), true);
        assert_eq!(control.request_stop(), false);
        assert_eq!(control.request_window_close(), true);
        assert_eq!(control.request_window_close(), false);
    }

    #[test]
    fn percentile_math_handles_invalid_fractions_and_duplicate_boundaries() {
        assert_eq!(percentile_ns(&[5, 5, 5], f64::NEG_INFINITY), Some(5));
        assert_eq!(percentile_ns(&[5, 5, 5], f64::INFINITY), Some(5));
        assert_eq!(percentile_ns(&[1, 2, 3, 4], 1.0), Some(4));
        assert_eq!(percentile_ns(&[1, 2, 3, 4], 0.75), Some(3));
        assert_eq!(low_fps(&[1_000_000], f64::NAN), Some(1000.0));
        assert_eq!(low_fps(&[1_000_000, 2_000_000], 0.0), Some(500.0));
        assert_eq!(
            low_fps(&[1_000_000, 2_000_000], 2.0),
            Some(666.6666666666666)
        );
        assert_eq!(low_fps(&[0, 0], f64::NAN), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn measure_gpu_present_rejects_zero_frames_with_exact_error() {
        assert_eq!(
            measure_gpu_present(0).expect_err("zero frames must be rejected"),
            "GPU present measurement needs at least one frame"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn measure_gpu_present_captures_real_timestamps_or_exact_fallback() {
        match measure_gpu_present(4) {
            Ok(summary) => {
                if summary.gpu_sample_count > 0 {
                    let gpu = summary
                        .gpu_time
                        .expect("real GPU timestamps produce GPU time");
                    assert_eq!(gpu.sample_count, summary.gpu_sample_count);
                    assert_eq!(gpu.p50_ns > 0, true);
                } else {
                    assert_eq!(
                        summary.gpu_unavailable,
                        Some(TimingUnavailable::MissingGpuTimestamp)
                    );
                }
                if summary.present_sample_count == 0 {
                    let reason = summary
                        .present_unavailable
                        .expect("missing presentation must carry a reason");
                    assert!(
                        matches!(
                            reason,
                            TimingUnavailable::NoDrawable
                                | TimingUnavailable::MissingPresentTimestamp
                        ),
                        "unexpected presentation fallback: {reason:?}"
                    );
                }
            }
            Err(error) => assert_eq!(error, TimingUnavailable::NoMetalDevice.reason()),
        }
    }
}
