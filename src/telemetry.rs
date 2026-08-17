use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Tracks a single unsupported PE import (DLL + symbol pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsupportedImportEntry {
    pub dll: String,
    pub symbol: String,
    pub frequency: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Tracks a single unsupported vtable / COM method call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsupportedMethodEntry {
    pub method_name: String,
    pub frequency: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Tracks an unsupported shader-model request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaderModelEntry {
    pub requested: u32,
    pub supported: u32,
    pub frequency: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Tracks an unimplemented CPU instruction encounter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnimplementedInstructionEntry {
    pub description: String,
    pub frequency: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// A ranked gap item produced by [`TelemetryCollector::prioritize_unsupported`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapPrioritizationItem {
    /// The gap analysis number(s) this item maps to (e.g. `"3.1"`, `"8.4"`).
    pub gap_numbers: Vec<String>,
    /// The module or subsystem (e.g. `"kernel32"`, `"d3d11"`).
    pub module: String,
    /// The specific method, import or instruction name.
    pub item_name: String,
    /// The category: `"import"`, `"method"`, `"instruction"`, `"shader"`.
    pub category: String,
    /// How many times this was recorded.
    pub frequency: u64,
    /// A human-readable suggestion for a replacement or fix.
    pub suggestion: String,
}

/// The full telemetry data set, serialisable to JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetryData {
    pub unsupported_imports: BTreeMap<String, UnsupportedImportEntry>,
    pub unsupported_methods: BTreeMap<String, UnsupportedMethodEntry>,
    pub shader_models: BTreeMap<String, ShaderModelEntry>,
    pub unimplemented_instructions: BTreeMap<String, UnimplementedInstructionEntry>,
}

// ---------------------------------------------------------------------------
// TelemetryCollector
// ---------------------------------------------------------------------------

/// Thread-safe collector for unsupported-method / import / shader-model /
/// unimplemented-instruction telemetry.
///
/// All recording methods take `&self` because they synchronise internally
/// via `std::sync::Mutex`.  The collector can optionally persist its state
/// to a JSON file on disk at a configurable path. Persistence is batched:
/// the full dataset is serialized at most once per
/// [`AUTO_PERSIST_INTERVAL`], plus on explicit [`TelemetryCollector::persist_to`]
/// and on `Drop`, so recorders on hot failure paths never pay O(dataset) I/O
/// per event.
pub struct TelemetryCollector {
    data: Mutex<TelemetryData>,
    persistence_path: Mutex<Option<String>>,
    enabled: AtomicBool,
    /// Set when in-memory data changed since the last successful persist.
    dirty: AtomicBool,
    /// When the last persist ran, for throttling.
    last_persist: Mutex<Instant>,
}

/// Minimum interval between automatic background persists.
const AUTO_PERSIST_INTERVAL: Duration = Duration::from_secs(2);

impl TelemetryCollector {
    /// Creates a new collector with telemetry **disabled** by default.
    ///
    /// Call [`opt_in`] to enable recording. This matches the privacy-first
    /// default: no data is collected until the user explicitly opts in.
    pub fn new() -> Self {
        Self {
            data: Mutex::new(TelemetryData::default()),
            persistence_path: Mutex::new(None),
            enabled: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            last_persist: Mutex::new(Instant::now()),
        }
    }

    /// Creates a new collector that will automatically persist to `path`
    /// (throttled, see [`AUTO_PERSIST_INTERVAL`]).  Telemetry is **disabled**
    /// by default.
    pub fn with_persistence_path(path: &str) -> Self {
        Self {
            data: Mutex::new(TelemetryData::default()),
            persistence_path: Mutex::new(Some(path.to_string())),
            enabled: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            last_persist: Mutex::new(Instant::now()),
        }
    }

    /// Creates a new collector with telemetry **enabled** (for testing).
    pub fn new_enabled() -> Self {
        Self {
            data: Mutex::new(TelemetryData::default()),
            persistence_path: Mutex::new(None),
            enabled: AtomicBool::new(true),
            dirty: AtomicBool::new(false),
            last_persist: Mutex::new(Instant::now()),
        }
    }

    /// Opt in to telemetry collection.  After calling this, all `record_*`
    /// methods will store entries.
    pub fn opt_in(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// Opt out of telemetry collection.  After calling this, all `record_*`
    /// methods become no-ops.  Previously recorded data is retained (call
    /// [`clear`] to remove it).
    pub fn opt_out(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    /// Returns `true` if telemetry collection is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Sets (or clears) the persistence path.
    pub fn set_persistence_path(&self, path: Option<&str>) {
        let mut p = self.persistence_path.lock().unwrap();
        *p = path.map(|s| s.to_string());
    }

    /// Returns the current persistence path, if any.
    pub fn persistence_path(&self) -> Option<String> {
        self.persistence_path.lock().unwrap().clone()
    }

    // ------------------------------------------------------------------
    // Recording helpers
    // ------------------------------------------------------------------

    /// Records an unsupported PE import (`dll!symbol`).
    /// No-op if telemetry is disabled.
    pub fn record_unsupported_import(&self, dll: &str, symbol: &str) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let now = now_secs();
        {
            let mut data = self.data.lock().unwrap();
            let key = format!("{}!{}", dll, symbol);
            let entry =
                data.unsupported_imports
                    .entry(key)
                    .or_insert_with(|| UnsupportedImportEntry {
                        dll: dll.to_string(),
                        symbol: symbol.to_string(),
                        frequency: 0,
                        first_seen: now,
                        last_seen: now,
                    });
            entry.frequency += 1;
            entry.last_seen = now;
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.maybe_persist();
    }

    /// Records an unsupported vtable / COM method dispatch.
    /// No-op if telemetry is disabled.
    ///
    /// `name` is conventionally `"InterfaceName::MethodName"`.
    pub fn record_unsupported_method(&self, name: &str) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let now = now_secs();
        {
            let mut data = self.data.lock().unwrap();
            let entry = data
                .unsupported_methods
                .entry(name.to_string())
                .or_insert_with(|| UnsupportedMethodEntry {
                    method_name: name.to_string(),
                    frequency: 0,
                    first_seen: now,
                    last_seen: now,
                });
            entry.frequency += 1;
            entry.last_seen = now;
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.maybe_persist();
    }

    /// Records an unsupported shader-model request.
    /// No-op if telemetry is disabled.
    pub fn record_unsupported_shader_model(&self, requested: u32, supported: u32) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let now = now_secs();
        {
            let mut data = self.data.lock().unwrap();
            let key = format!("shader_model_0x{requested:02x}_0x{supported:02x}");
            let entry = data
                .shader_models
                .entry(key)
                .or_insert_with(|| ShaderModelEntry {
                    requested,
                    supported,
                    frequency: 0,
                    first_seen: now,
                    last_seen: now,
                });
            entry.frequency += 1;
            entry.last_seen = now;
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.maybe_persist();
    }

    /// Records an unimplemented CPU instruction.
    /// No-op if telemetry is disabled.
    pub fn record_unimplemented_instruction(&self, description: &str) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let now = now_secs();
        {
            let mut data = self.data.lock().unwrap();
            let entry = data
                .unimplemented_instructions
                .entry(description.to_string())
                .or_insert_with(|| UnimplementedInstructionEntry {
                    description: description.to_string(),
                    frequency: 0,
                    first_seen: now,
                    last_seen: now,
                });
            entry.frequency += 1;
            entry.last_seen = now;
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.maybe_persist();
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Writes the current telemetry data to the file at `path`.
    pub fn persist_to(&self, path: &str) -> Result<(), String> {
        let data = self.data.lock().unwrap();
        let json_str = serde_json::to_string_pretty(&*data)
            .map_err(|e| format!("telemetry serialisation error: {e}"))?;
        // Atomically write via a unique temporary file: a fixed `{path}.tmp`
        // would let concurrent processes clobber each other's temp file and
        // rename half-written data into place. The temp file is removed on
        // any failure.
        let tmp = format!("{path}.{}.{}.tmp", std::process::id(), unique_tmp_suffix());
        if let Err(e) = fs::write(&tmp, &json_str) {
            let _ = fs::remove_file(&tmp);
            return Err(format!("telemetry write error: {e}"));
        }
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(format!("telemetry rename error: {e}"));
        }
        Ok(())
    }

    /// Loads telemetry data from the file at `path`, merging it into the
    /// current in-memory state.  Existing entries are overwritten.
    pub fn load_from(&self, path: &str) -> Result<(), String> {
        if !Path::new(path).exists() {
            return Ok(()); // Nothing to load – not an error.
        }
        let json_str =
            fs::read_to_string(path).map_err(|e| format!("telemetry read error: {e}"))?;
        let loaded: TelemetryData = serde_json::from_str(&json_str)
            .map_err(|e| format!("telemetry deserialisation error: {e}"))?;
        let mut data = self.data.lock().unwrap();
        // Merge loaded data (existing entries take precedence on conflict).
        for (k, v) in loaded.unsupported_imports {
            data.unsupported_imports.entry(k).or_insert(v);
        }
        for (k, v) in loaded.unsupported_methods {
            data.unsupported_methods.entry(k).or_insert(v);
        }
        for (k, v) in loaded.shader_models {
            data.shader_models.entry(k).or_insert(v);
        }
        for (k, v) in loaded.unimplemented_instructions {
            data.unimplemented_instructions.entry(k).or_insert(v);
        }
        Ok(())
    }

    /// Clears all telemetry data.
    pub fn clear(&self) {
        let mut data = self.data.lock().unwrap();
        *data = TelemetryData::default();
    }

    /// Returns a snapshot of the current data.
    pub fn snapshot(&self) -> TelemetryData {
        self.data.lock().unwrap().clone()
    }

    // ------------------------------------------------------------------
    // Report generation (sorted by frequency, most-blocking first)
    // ------------------------------------------------------------------

    /// Produces a JSON report sorted by impact (most frequent first).
    pub fn generate_report(&self) -> Value {
        let data = self.data.lock().unwrap();

        // --- unsupported imports ---
        let mut imports: Vec<&UnsupportedImportEntry> = data.unsupported_imports.values().collect();
        imports.sort_by_key(|e| Reverse(e.frequency));

        // --- unsupported methods ---
        let mut methods: Vec<&UnsupportedMethodEntry> = data.unsupported_methods.values().collect();
        methods.sort_by_key(|e| Reverse(e.frequency));

        // --- shader models ---
        let mut shader_models: Vec<&ShaderModelEntry> = data.shader_models.values().collect();
        shader_models.sort_by_key(|e| Reverse(e.frequency));

        // --- unimplemented instructions ---
        let mut insns: Vec<&UnimplementedInstructionEntry> =
            data.unimplemented_instructions.values().collect();
        insns.sort_by_key(|e| Reverse(e.frequency));

        json!({
            "generated_at": now_secs(),
            "ranked_unsupported_imports": imports.iter().map(|e| json!({
                "dll": e.dll,
                "symbol": e.symbol,
                "frequency": e.frequency,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            })).collect::<Vec<_>>(),
            "ranked_unsupported_methods": methods.iter().map(|e| json!({
                "method": e.method_name,
                "frequency": e.frequency,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            })).collect::<Vec<_>>(),
            "ranked_shader_models": shader_models.iter().map(|e| json!({
                "requested": e.requested,
                "supported": e.supported,
                "frequency": e.frequency,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            })).collect::<Vec<_>>(),
            "ranked_unimplemented_instructions": insns.iter().map(|e| json!({
                "description": e.description,
                "frequency": e.frequency,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            })).collect::<Vec<_>>(),
        })
    }

    /// Analyze telemetry data and produce a ranked list of unsupported items
    /// sorted by call frequency, with module grouping and gap-number mapping.
    ///
    /// Each entry is enriched with:
    /// - A `module` name extracted from the DLL / interface prefix.
    /// - A `suggestion` for a replacement or fix.
    /// - One or more gap-analysis numbers that this item maps to.
    pub fn prioritize_unsupported(&self) -> Vec<GapPrioritizationItem> {
        let data = self.data.lock().unwrap();
        let mut items: Vec<GapPrioritizationItem> = Vec::new();

        // --- unsupported imports ---
        for entry in data.unsupported_imports.values() {
            let module = entry.dll.trim_end_matches(".dll").to_string();
            let (gaps, suggestion) = map_import_to_gap(&entry.dll, &entry.symbol);
            items.push(GapPrioritizationItem {
                gap_numbers: gaps,
                module,
                item_name: format!("{}!{}", entry.dll, entry.symbol),
                category: "import".to_string(),
                frequency: entry.frequency,
                suggestion,
            });
        }

        // --- unsupported methods (COM / vtable) ---
        for entry in data.unsupported_methods.values() {
            let module = entry
                .method_name
                .split("::")
                .next()
                .unwrap_or("unknown")
                .trim_start_matches('I')
                .to_string();
            let (gaps, suggestion) = map_method_to_gap(&entry.method_name);
            items.push(GapPrioritizationItem {
                gap_numbers: gaps,
                module,
                item_name: entry.method_name.clone(),
                category: "method".to_string(),
                frequency: entry.frequency,
                suggestion,
            });
        }

        // --- shader models ---
        for entry in data.shader_models.values() {
            items.push(GapPrioritizationItem {
                gap_numbers: vec!["15.2".to_string()],
                module: "shader".to_string(),
                item_name: format!("shader_model_0x{:02x}", entry.requested),
                category: "shader".to_string(),
                frequency: entry.frequency,
                suggestion: format!(
                    "Upgrade shader model from 0x{:02x} to 0x{:02x}",
                    entry.requested, entry.supported
                ),
            });
        }

        // --- unimplemented instructions ---
        for entry in data.unimplemented_instructions.values() {
            let module = classify_instruction_module(&entry.description);
            let (gaps, suggestion) = map_instruction_to_gap(&entry.description);
            items.push(GapPrioritizationItem {
                gap_numbers: gaps,
                module,
                item_name: entry.description.clone(),
                category: "instruction".to_string(),
                frequency: entry.frequency,
                suggestion,
            });
        }

        // Sort by frequency descending
        items.sort_by_key(|a| Reverse(a.frequency));
        items
    }

    /// Returns the top `n` most-frequently-called unsupported methods with
    /// call counts, module context, and replacement suggestions.
    ///
    /// This is a convenience wrapper around [`prioritize_unsupported`].
    pub fn report_top_unsupported(&self, n: usize) -> Vec<GapPrioritizationItem> {
        let all = self.prioritize_unsupported();
        all.into_iter().take(n).collect()
    }

    /// Produce a JSON report that includes gap-analysis cross-references,
    /// suitable for feeding into the gap-analysis pipeline.
    ///
    /// The report groups items by gap number so each gap can be worked on
    /// independently.  This is a richer variant of [`generate_report`].
    pub fn generate_gap_analysis_report(&self) -> Value {
        let prioritized = self.prioritize_unsupported();

        // Group by gap number
        let mut by_gap: BTreeMap<String, Vec<&GapPrioritizationItem>> = BTreeMap::new();
        for item in &prioritized {
            for gap in &item.gap_numbers {
                by_gap.entry(gap.clone()).or_default().push(item);
            }
        }

        let gaps: Vec<Value> = by_gap
            .into_iter()
            .map(|(gap_num, items)| {
                json!({
                    "gap": gap_num,
                    "total_calls": items.iter().map(|i| i.frequency).sum::<u64>(),
                    "unique_items": items.len(),
                    "items": items.iter().map(|i| json!({
                        "module": i.module,
                        "name": i.item_name,
                        "category": i.category,
                        "frequency": i.frequency,
                        "suggestion": i.suggestion,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();

        json!({
            "generated_at": now_secs(),
            "total_unsupported_calls": prioritized.iter().map(|i| i.frequency).sum::<u64>(),
            "unique_unsupported_items": prioritized.len(),
            "gaps": gaps,
        })
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn maybe_persist(&self) {
        // Batch persistence: serialize and write the full dataset at most
        // once per interval, so recorders on hot emulation failure paths
        // never pay O(dataset) I/O per event. The dirty flag keeps the
        // in-memory state durable across throttled intervals and on Drop.
        if !self.dirty.load(Ordering::Relaxed) {
            return;
        }
        let mut last = self.last_persist.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*last) < AUTO_PERSIST_INTERVAL {
            return;
        }
        *last = now;
        drop(last);

        let path = self.persistence_path.lock().unwrap().clone();
        let Some(p) = path else {
            self.dirty.store(false, Ordering::Relaxed);
            return;
        };
        match self.persist_to(&p) {
            Ok(()) => {
                self.dirty.store(false, Ordering::Relaxed);
            }
            Err(e) => {
                // Keep the dirty flag so a later flush retries the write.
                eprintln!("[telemetry] failed to persist telemetry data: {e}");
            }
        }
    }
}

impl Drop for TelemetryCollector {
    fn drop(&mut self) {
        // Best-effort final flush so a batched session's tail is not lost.
        if !self.dirty.load(Ordering::Relaxed) {
            return;
        }
        let Ok(path) = self.persistence_path.lock() else {
            return;
        };
        let Some(p) = path.clone() else {
            return;
        };
        drop(path);
        if let Err(e) = self.persist_to(&p) {
            eprintln!("[telemetry] failed to flush telemetry data at drop: {e}");
        }
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Gap-analysis mapping functions (public for external use)
// ---------------------------------------------------------------------------

/// Map a (DLL, symbol) pair to gap-analysis numbers and a suggestion.
///
/// This maps known Windows API imports to the Casa1 gap-analysis sections
/// so that telemetry-driven prioritisation feeds directly into the gap
/// closure workflow.
pub fn map_import_to_gap(dll: &str, symbol: &str) -> (Vec<String>, String) {
    let dll_lower = dll.to_ascii_lowercase();
    let sym_lower = symbol.to_ascii_lowercase();

    match dll_lower.as_str() {
        "kernel32.dll" | "kernelbase.dll" => {
            if sym_lower.contains("file")
                || sym_lower.contains("directory")
                || sym_lower.contains("path")
            {
                (
                    vec!["3.1".to_string()],
                    "Implement kernel32 file-system thunk (Gap 3.1)".to_string(),
                )
            } else if sym_lower.contains("process") || sym_lower.contains("thread") {
                (
                    vec!["3.2".to_string()],
                    "Implement kernel32 process/thread thunk (Gap 3.2)".to_string(),
                )
            } else if sym_lower.contains("memory")
                || sym_lower.contains("virtual")
                || sym_lower.contains("heap")
            {
                (
                    vec!["3.3".to_string()],
                    "Implement kernel32 memory-management thunk (Gap 3.3)".to_string(),
                )
            } else if sym_lower.contains("library") || sym_lower.contains("module") {
                (
                    vec!["3.4".to_string()],
                    "Implement kernel32 library/module thunk (Gap 3.4)".to_string(),
                )
            } else if sym_lower.contains("sync")
                || sym_lower.contains("wait")
                || sym_lower.contains("event")
                || sym_lower.contains("mutex")
            {
                (
                    vec!["3.5".to_string()],
                    "Implement kernel32 sync/async thunk (Gap 3.5)".to_string(),
                )
            } else {
                (
                    vec!["3.6".to_string()],
                    "Implement kernel32 miscellaneous thunk (Gap 3.6)".to_string(),
                )
            }
        }
        "user32.dll" => (
            vec!["4.1".to_string()],
            "Implement user32 thunk (Gap 4.1)".to_string(),
        ),
        "ws2_32.dll" => (
            vec!["6.1".to_string()],
            "Implement ws2_32 Winsock thunk (Gap 6.1)".to_string(),
        ),
        "gdi32.dll" => (
            vec!["5.1".to_string()],
            "Implement gdi32 thunk (Gap 5.1)".to_string(),
        ),
        "advapi32.dll" => (
            vec!["8.1".to_string()],
            "Implement advapi32 registry/security thunk (Gap 8.1)".to_string(),
        ),
        "crypt32.dll" => (
            vec!["9.1".to_string()],
            "Implement crypt32 thunk (Gap 9.1)".to_string(),
        ),
        "shell32.dll" => (
            vec!["10.1".to_string()],
            "Implement shell32 thunk (Gap 10.1)".to_string(),
        ),
        "psapi.dll" => (
            vec!["3.7".to_string()],
            "Implement psapi process-status thunk (Gap 3.7)".to_string(),
        ),
        "bcrypt.dll" => (
            vec!["9.2".to_string()],
            "Implement bcrypt cryptographic thunk (Gap 9.2)".to_string(),
        ),
        "comctl32.dll" => (
            vec!["11.1".to_string()],
            "Implement comctl32 common-controls thunk (Gap 11.1)".to_string(),
        ),
        "ole32.dll" => (
            vec!["12.1".to_string()],
            "Implement ole32 COM thunk (Gap 12.1)".to_string(),
        ),
        "oleaut32.dll" => (
            vec!["12.2".to_string()],
            "Implement oleaut32 COM automation thunk (Gap 12.2)".to_string(),
        ),
        "version.dll" => (
            vec!["10.2".to_string()],
            "Implement version-info thunk (Gap 10.2)".to_string(),
        ),
        "wsock32.dll" => (
            vec!["6.2".to_string()],
            "Implement wsock32 legacy Winsock thunk (Gap 6.2)".to_string(),
        ),
        _ if dll_lower.contains("d3d11") || dll_lower.contains("dxgi") => (
            vec!["7.1".to_string()],
            "Implement D3D11/DXGI thunk (Gap 7.1)".to_string(),
        ),
        _ if dll_lower.contains("d3d12") => (
            vec!["7.2".to_string()],
            "Implement D3D12 thunk (Gap 7.2)".to_string(),
        ),
        _ if dll_lower.contains("d3d10") => (
            vec!["7.3".to_string()],
            "Implement D3D10 thunk (Gap 7.3)".to_string(),
        ),
        _ => (
            vec!["15.2".to_string()],
            format!("Implement {dll} thunk (general gap)").to_string(),
        ),
    }
}

/// Map a COM/vtable method name to gap-analysis numbers and a suggestion.
pub fn map_method_to_gap(method: &str) -> (Vec<String>, String) {
    let low = method.to_ascii_lowercase();
    if low.contains("d3d11") || low.contains("dxgi") {
        (
            vec!["7.1".to_string()],
            format!("Implement D3D11/DXGI method: {method}"),
        )
    } else if low.contains("d3d12") {
        (
            vec!["7.2".to_string()],
            format!("Implement D3D12 method: {method}"),
        )
    } else if low.contains("d2d") || low.contains("dwrite") {
        (
            vec!["7.4".to_string()],
            format!("Implement D2D/DWrite method: {method}"),
        )
    } else if low.contains("media") || low.contains("mf") || low.contains("mfs") {
        (
            vec!["14.1".to_string()],
            format!("Implement Media Foundation method: {method}"),
        )
    } else if low.contains("audio") || low.contains("wasapi") || low.contains("xaudio") {
        (
            vec!["13.1".to_string()],
            format!("Implement audio method: {method}"),
        )
    } else if low.contains("input") || low.contains("hid") || low.contains("rawinput") {
        (
            vec!["16.1".to_string()],
            format!("Implement input/HID method: {method}"),
        )
    } else {
        (
            vec!["15.2".to_string()],
            format!("Implement COM method: {method}"),
        )
    }
}

/// Map an unimplemented CPU instruction to gap-analysis numbers and a suggestion.
pub fn map_instruction_to_gap(instruction: &str) -> (Vec<String>, String) {
    let low = instruction.to_ascii_lowercase();
    if low.contains("xsave")
        || low.contains("xrstor")
        || low.contains("fxrstor")
        || low.contains("fxsave")
    {
        (
            vec!["2.1".to_string()],
            format!("Implement x87/SSE save/restore instruction: {instruction} (Gap 2.1)"),
        )
    } else if low.contains("aes") || low.contains("sha") || low.contains("clmul") {
        (
            vec!["2.2".to_string()],
            format!("Implement AES/SHA crypto instruction: {instruction} (Gap 2.2)"),
        )
    } else if low.contains("invpcid") || low.contains("invlpg") {
        (
            vec!["2.3".to_string()],
            format!("Implement TLB/MMU instruction: {instruction} (Gap 2.3)"),
        )
    } else if low.contains("clflush") || low.contains("clwb") || low.contains("pcommit") {
        (
            vec!["2.4".to_string()],
            format!("Implement cache-control instruction: {instruction} (Gap 2.4)"),
        )
    } else if low.contains("vm") || low.contains("vmx") || low.contains("svm") {
        (
            vec!["2.5".to_string()],
            format!("Implement virtualization instruction: {instruction} (Gap 2.5)"),
        )
    } else {
        (
            vec!["2.6".to_string()],
            format!("Implement miscellaneous CPU instruction: {instruction} (Gap 2.6)"),
        )
    }
}

/// Classify an instruction into a module name for grouping.
pub fn classify_instruction_module(instruction: &str) -> String {
    let low = instruction.to_ascii_lowercase();
    if low.contains("xsave")
        || low.contains("xrstor")
        || low.contains("fxsave")
        || low.contains("fxrstor")
    {
        "fpu".to_string()
    } else if low.contains("aes")
        || low.contains("sha")
        || low.contains("clmul")
        || low.contains("pclmul")
    {
        "crypto".to_string()
    } else if low.contains("invpcid") || low.contains("invlpg") || low.contains("invlp") {
        "mmu".to_string()
    } else if low.contains("clflush") || low.contains("clwb") || low.contains("pcommit") {
        "cache".to_string()
    } else if low.contains("vm") || low.contains("vmx") || low.contains("svm") {
        "virtualization".to_string()
    } else if low.contains("rdrand") || low.contains("rdseed") {
        "rng".to_string()
    } else if low.contains("bmi") || low.contains("lzcnt") || low.contains("popcnt") {
        "bit_manip".to_string()
    } else {
        "other".to_string()
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A cheap unique suffix for temporary persistence files: the monotonic
/// clock mixed with a process-global counter, so concurrent writers (even in
/// different processes) never target the same temp path.
fn unique_tmp_suffix() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    now ^ COUNTER.fetch_add(1, Ordering::Relaxed).rotate_left(16)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_unsupported_import() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_import("user32.dll", "MessageBoxW");

        let data = c.snapshot();
        assert_eq!(data.unsupported_imports.len(), 2);

        let key1 = "kernel32.dll!CreateFileW";
        let entry1 = data.unsupported_imports.get(key1).unwrap();
        assert_eq!(entry1.frequency, 2);

        let key2 = "user32.dll!MessageBoxW";
        let entry2 = data.unsupported_imports.get(key2).unwrap();
        assert_eq!(entry2.frequency, 1);
    }

    #[test]
    fn test_record_unsupported_method() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_method("ID3D11Device::CreateTexture1D");
        c.record_unsupported_method("ID3D11Device::CreateTexture1D");
        c.record_unsupported_method("ID3D11Device::CreateGeometryShader");

        let data = c.snapshot();
        assert_eq!(data.unsupported_methods.len(), 2);

        let e1 = data
            .unsupported_methods
            .get("ID3D11Device::CreateTexture1D")
            .unwrap();
        assert_eq!(e1.frequency, 2);

        let e2 = data
            .unsupported_methods
            .get("ID3D11Device::CreateGeometryShader")
            .unwrap();
        assert_eq!(e2.frequency, 1);
    }

    #[test]
    fn test_record_shader_model() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_shader_model(0x65, 0x66);
        c.record_unsupported_shader_model(0x65, 0x66);

        let data = c.snapshot();
        assert_eq!(data.shader_models.len(), 1);
        let entry = data.shader_models.values().next().unwrap();
        assert_eq!(entry.frequency, 2);
        assert_eq!(entry.requested, 0x65);
        assert_eq!(entry.supported, 0x66);
    }

    #[test]
    fn test_record_unimplemented_instruction() {
        let c = TelemetryCollector::new_enabled();
        c.record_unimplemented_instruction("FXRSTOR");
        c.record_unimplemented_instruction("FXRSTOR");
        c.record_unimplemented_instruction("INVPCID");

        let data = c.snapshot();
        assert_eq!(data.unimplemented_instructions.len(), 2);

        let e1 = data.unimplemented_instructions.get("FXRSTOR").unwrap();
        assert_eq!(e1.frequency, 2);

        let e2 = data.unimplemented_instructions.get("INVPCID").unwrap();
        assert_eq!(e2.frequency, 1);
    }

    #[test]
    fn test_persist_roundtrip() {
        let dir = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = dir.join(format!("casa1_telemetry_test_{unique}.json"));
        let path_str = path.to_str().unwrap().to_string();

        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_import("d3d11.dll", "D3D11CreateDevice");
        c.record_unsupported_method("IDXGISwapChain::ResizeTarget");
        c.record_unsupported_shader_model(0x65, 0x66);
        c.record_unimplemented_instruction("CLFLUSH");

        // Persist
        c.persist_to(&path_str).unwrap();
        assert!(path.exists());

        // Load into a fresh collector
        let c2 = TelemetryCollector::new_enabled();
        c2.load_from(&path_str).unwrap();

        let data = c2.snapshot();
        assert_eq!(data.unsupported_imports.len(), 1);
        assert_eq!(data.unsupported_methods.len(), 1);
        assert_eq!(data.shader_models.len(), 1);
        assert_eq!(data.unimplemented_instructions.len(), 1);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_generate_report_sorted() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_import("a.dll", "low");
        c.record_unsupported_import("b.dll", "high");
        c.record_unsupported_import("b.dll", "high");

        c.record_unsupported_method("IFoo::Bar");
        c.record_unsupported_method("IFoo::Baz");
        c.record_unsupported_method("IFoo::Baz");

        let report = c.generate_report();

        // Check imports sorted by frequency descending
        let imports = report["ranked_unsupported_imports"].as_array().unwrap();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0]["symbol"], "high");
        assert_eq!(imports[0]["frequency"], 2);
        assert_eq!(imports[1]["symbol"], "low");
        assert_eq!(imports[1]["frequency"], 1);

        // Check methods sorted by frequency descending
        let methods = report["ranked_unsupported_methods"].as_array().unwrap();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0]["method"], "IFoo::Baz");
        assert_eq!(methods[0]["frequency"], 2);
        assert_eq!(methods[1]["method"], "IFoo::Bar");
        assert_eq!(methods[1]["frequency"], 1);
    }

    #[test]
    fn test_clear() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_import("x.dll", "y");
        assert_eq!(c.snapshot().unsupported_imports.len(), 1);
        c.clear();
        assert_eq!(c.snapshot().unsupported_imports.len(), 0);
    }

    #[test]
    fn test_persistence_path() {
        let c = TelemetryCollector::with_persistence_path("/tmp/test_telemetry.json");
        assert_eq!(
            c.persistence_path(),
            Some("/tmp/test_telemetry.json".to_string())
        );

        c.set_persistence_path(Some("/other/path.json"));
        assert_eq!(c.persistence_path(), Some("/other/path.json".to_string()));

        c.set_persistence_path(None);
        assert_eq!(c.persistence_path(), None);
    }

    #[test]
    fn test_prioritize_unsupported_empty() {
        let c = TelemetryCollector::new_enabled();
        let ranked = c.prioritize_unsupported();
        assert!(ranked.is_empty());
    }

    #[test]
    fn test_prioritize_unsupported_ranking() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_import("user32.dll", "MessageBoxW");
        c.record_unsupported_method("ID3D11Device::CreateTexture1D");

        let ranked = c.prioritize_unsupported();
        assert!(!ranked.is_empty());

        // First item should be CreateFileW (frequency 3)
        assert_eq!(ranked[0].item_name, "kernel32.dll!CreateFileW");
        assert_eq!(ranked[0].frequency, 3);
        assert_eq!(ranked[0].module, "kernel32");
        assert_eq!(ranked[0].category, "import");

        // Second item should be MessageBoxW (frequency 1) or CreateTexture1D
        assert_eq!(ranked[1].frequency, 1);
    }

    #[test]
    fn test_report_top_unsupported() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_import("a.dll", "foo");
        c.record_unsupported_import("b.dll", "bar");
        c.record_unsupported_import("c.dll", "baz");

        let top2 = c.report_top_unsupported(2);
        assert_eq!(top2.len(), 2);

        let top10 = c.report_top_unsupported(10);
        assert_eq!(top10.len(), 3); // only 3 items exist
    }

    #[test]
    fn test_map_import_to_gap() {
        let (gaps, _) = map_import_to_gap("kernel32.dll", "CreateFileW");
        assert!(gaps.contains(&"3.1".to_string()));

        let (gaps, _) = map_import_to_gap("d3d11.dll", "D3D11CreateDevice");
        assert!(gaps.contains(&"7.1".to_string()));

        let (gaps, _) = map_import_to_gap("user32.dll", "MessageBoxW");
        assert!(gaps.contains(&"4.1".to_string()));
    }

    #[test]
    fn test_map_method_to_gap() {
        let (gaps, _) = map_method_to_gap("IDXGISwapChain::Present");
        assert!(gaps.contains(&"7.1".to_string()));

        let (gaps, _) = map_method_to_gap("IXAudio2::CreateSourceVoice");
        assert!(gaps.contains(&"13.1".to_string()));
    }

    #[test]
    fn test_map_instruction_to_gap() {
        let (gaps, _) = map_instruction_to_gap("FXRSTOR");
        assert!(gaps.contains(&"2.1".to_string()));

        let (gaps, _) = map_instruction_to_gap("INVPCID");
        assert!(gaps.contains(&"2.3".to_string()));

        let (gaps, _) = map_instruction_to_gap("AESENC");
        assert!(gaps.contains(&"2.2".to_string()));
    }

    #[test]
    fn test_classify_instruction_module() {
        assert_eq!(classify_instruction_module("FXRSTOR"), "fpu");
        assert_eq!(classify_instruction_module("AESENC"), "crypto");
        assert_eq!(classify_instruction_module("INVPCID"), "mmu");
        assert_eq!(classify_instruction_module("CLFLUSH"), "cache");
        assert_eq!(classify_instruction_module("RDRAND"), "rng");
    }

    #[test]
    fn test_generate_gap_analysis_report() {
        let c = TelemetryCollector::new_enabled();
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_method("ID3D11Device::CreateTexture1D");

        let report = c.generate_gap_analysis_report();
        assert!(report["total_unsupported_calls"].as_u64().unwrap() > 0);
        assert!(report["unique_unsupported_items"].as_u64().unwrap() > 0);
        assert!(!report["gaps"].as_array().unwrap().is_empty());
    }

    // ── Opt-in / opt-out behavior tests ─────────────────────────────────────

    #[test]
    fn test_telemetry_disabled_by_default() {
        let c = TelemetryCollector::new();
        assert!(!c.is_enabled(), "telemetry should be disabled by default");

        // Recording should be a no-op
        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        c.record_unsupported_method("IFoo::Bar");
        c.record_unsupported_shader_model(0x65, 0x66);
        c.record_unimplemented_instruction("FXRSTOR");

        let data = c.snapshot();
        assert!(
            data.unsupported_imports.is_empty(),
            "no data should be recorded when disabled"
        );
        assert!(data.unsupported_methods.is_empty());
        assert!(data.shader_models.is_empty());
        assert!(data.unimplemented_instructions.is_empty());
    }

    #[test]
    fn test_opt_in_enables_recording() {
        let c = TelemetryCollector::new();
        assert!(!c.is_enabled());

        c.opt_in();
        assert!(c.is_enabled(), "opt_in should enable telemetry");

        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        let data = c.snapshot();
        assert_eq!(data.unsupported_imports.len(), 1);
    }

    #[test]
    fn test_opt_out_disables_recording() {
        let c = TelemetryCollector::new_enabled();
        assert!(c.is_enabled());

        c.opt_out();
        assert!(!c.is_enabled(), "opt_out should disable telemetry");

        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        let data = c.snapshot();
        assert!(
            data.unsupported_imports.is_empty(),
            "no data should be recorded after opt-out"
        );
    }

    #[test]
    fn test_opt_in_then_opt_out_preserves_existing_data() {
        let c = TelemetryCollector::new();
        c.opt_in();

        c.record_unsupported_import("kernel32.dll", "CreateFileW");
        assert_eq!(c.snapshot().unsupported_imports.len(), 1);

        c.opt_out();

        // Data recorded before opt-out should still be there
        let data = c.snapshot();
        assert_eq!(
            data.unsupported_imports.len(),
            1,
            "previously recorded data should be preserved after opt-out"
        );

        // New recordings should be ignored
        c.record_unsupported_import("user32.dll", "MessageBoxW");
        assert_eq!(
            c.snapshot().unsupported_imports.len(),
            1,
            "no new data after opt-out"
        );
    }

    #[test]
    fn test_repeated_opt_in_opt_out_cycle() {
        let c = TelemetryCollector::new();

        // Cycle 1
        c.opt_in();
        c.record_unsupported_import("a.dll", "x");
        c.opt_out();
        assert_eq!(c.snapshot().unsupported_imports.len(), 1);

        // Cycle 2 — opt_in again, record more
        c.opt_in();
        c.record_unsupported_import("b.dll", "y");
        assert_eq!(c.snapshot().unsupported_imports.len(), 2);
        c.opt_out();

        // Data from both cycles should be present
        let data = c.snapshot();
        assert_eq!(data.unsupported_imports.len(), 2);
    }
}
