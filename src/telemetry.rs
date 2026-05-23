use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// The full telemetry data set, serialisable to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryData {
    pub unsupported_imports: BTreeMap<String, UnsupportedImportEntry>,
    pub unsupported_methods: BTreeMap<String, UnsupportedMethodEntry>,
    pub shader_models: BTreeMap<String, ShaderModelEntry>,
    pub unimplemented_instructions: BTreeMap<String, UnimplementedInstructionEntry>,
}

impl Default for TelemetryData {
    fn default() -> Self {
        Self {
            unsupported_imports: BTreeMap::new(),
            unsupported_methods: BTreeMap::new(),
            shader_models: BTreeMap::new(),
            unimplemented_instructions: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// TelemetryCollector
// ---------------------------------------------------------------------------

/// Thread-safe collector for unsupported-method / import / shader-model /
/// unimplemented-instruction telemetry.
///
/// All recording methods take `&self` because they synchronise internally
/// via `std::sync::Mutex`.  The collector can optionally persist its state
/// to a JSON file on disk at a configurable path.
pub struct TelemetryCollector {
    data: Mutex<TelemetryData>,
    persistence_path: Mutex<Option<String>>,
}

impl TelemetryCollector {
    /// Creates a new collector with no persistence path.
    pub fn new() -> Self {
        Self {
            data: Mutex::new(TelemetryData::default()),
            persistence_path: Mutex::new(None),
        }
    }

    /// Creates a new collector that will automatically persist to `path`
    /// after every recording call.
    pub fn with_persistence_path(path: &str) -> Self {
        Self {
            data: Mutex::new(TelemetryData::default()),
            persistence_path: Mutex::new(Some(path.to_string())),
        }
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
    pub fn record_unsupported_import(&self, dll: &str, symbol: &str) {
        let now = now_secs();
        let mut data = self.data.lock().unwrap();
        let key = format!("{}!{}", dll, symbol);
        let entry = data.unsupported_imports.entry(key).or_insert_with(|| {
            UnsupportedImportEntry {
                dll: dll.to_string(),
                symbol: symbol.to_string(),
                frequency: 0,
                first_seen: now,
                last_seen: now,
            }
        });
        entry.frequency += 1;
        entry.last_seen = now;
        drop(data);
        self.maybe_persist();
    }

    /// Records an unsupported vtable / COM method dispatch.
    ///
    /// `name` is conventionally `"InterfaceName::MethodName"`.
    pub fn record_unsupported_method(&self, name: &str) {
        let now = now_secs();
        let mut data = self.data.lock().unwrap();
        let entry = data.unsupported_methods.entry(name.to_string()).or_insert_with(|| {
            UnsupportedMethodEntry {
                method_name: name.to_string(),
                frequency: 0,
                first_seen: now,
                last_seen: now,
            }
        });
        entry.frequency += 1;
        entry.last_seen = now;
        drop(data);
        self.maybe_persist();
    }

    /// Records an unsupported shader-model request.
    pub fn record_unsupported_shader_model(&self, requested: u32, supported: u32) {
        let now = now_secs();
        let mut data = self.data.lock().unwrap();
        let key = format!("shader_model_0x{requested:02x}_0x{supported:02x}");
        let entry = data.shader_models.entry(key).or_insert_with(|| {
            ShaderModelEntry {
                requested,
                supported,
                frequency: 0,
                first_seen: now,
                last_seen: now,
            }
        });
        entry.frequency += 1;
        entry.last_seen = now;
        drop(data);
        self.maybe_persist();
    }

    /// Records an unimplemented CPU instruction.
    pub fn record_unimplemented_instruction(&self, description: &str) {
        let now = now_secs();
        let mut data = self.data.lock().unwrap();
        let entry = data.unimplemented_instructions.entry(description.to_string()).or_insert_with(|| {
            UnimplementedInstructionEntry {
                description: description.to_string(),
                frequency: 0,
                first_seen: now,
                last_seen: now,
            }
        });
        entry.frequency += 1;
        entry.last_seen = now;
        drop(data);
        self.maybe_persist();
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Writes the current telemetry data to the file at `path`.
    pub fn persist_to(&self, path: &str) -> Result<(), String> {
        let data = self.data.lock().unwrap();
        let json = serde_json::to_string_pretty(&*data)
            .map_err(|e| format!("telemetry serialisation error: {e}"))?;
        // Atomically write via a temporary file.
        let tmp = format!("{}.tmp", path);
        fs::write(&tmp, &json).map_err(|e| format!("telemetry write error: {e}"))?;
        fs::rename(&tmp, path).map_err(|e| format!("telemetry rename error: {e}"))?;
        Ok(())
    }

    /// Loads telemetry data from the file at `path`, merging it into the
    /// current in-memory state.  Existing entries are overwritten.
    pub fn load_from(&self, path: &str) -> Result<(), String> {
        if !Path::new(path).exists() {
            return Ok(()); // Nothing to load – not an error.
        }
        let json = fs::read_to_string(path)
            .map_err(|e| format!("telemetry read error: {e}"))?;
        let loaded: TelemetryData = serde_json::from_str(&json)
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
        let mut imports: Vec<&UnsupportedImportEntry> =
            data.unsupported_imports.values().collect();
        imports.sort_by(|a, b| b.frequency.cmp(&a.frequency));

        // --- unsupported methods ---
        let mut methods: Vec<&UnsupportedMethodEntry> =
            data.unsupported_methods.values().collect();
        methods.sort_by(|a, b| b.frequency.cmp(&a.frequency));

        // --- shader models ---
        let mut shader_models: Vec<&ShaderModelEntry> =
            data.shader_models.values().collect();
        shader_models.sort_by(|a, b| b.frequency.cmp(&a.frequency));

        // --- unimplemented instructions ---
        let mut insns: Vec<&UnimplementedInstructionEntry> =
            data.unimplemented_instructions.values().collect();
        insns.sort_by(|a, b| b.frequency.cmp(&a.frequency));

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

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn maybe_persist(&self) {
        let path = self.persistence_path.lock().unwrap().clone();
        if let Some(p) = path {
            let _ = self.persist_to(&p);
        }
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new()
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

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_record_unsupported_import() {
        let c = TelemetryCollector::new();
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
        let c = TelemetryCollector::new();
        c.record_unsupported_method("ID3D11Device::CreateTexture1D");
        c.record_unsupported_method("ID3D11Device::CreateTexture1D");
        c.record_unsupported_method("ID3D11Device::CreateGeometryShader");

        let data = c.snapshot();
        assert_eq!(data.unsupported_methods.len(), 2);

        let e1 = data.unsupported_methods.get("ID3D11Device::CreateTexture1D").unwrap();
        assert_eq!(e1.frequency, 2);

        let e2 = data.unsupported_methods.get("ID3D11Device::CreateGeometryShader").unwrap();
        assert_eq!(e2.frequency, 1);
    }

    #[test]
    fn test_record_shader_model() {
        let c = TelemetryCollector::new();
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
        let c = TelemetryCollector::new();
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
        let path = dir.join("casa1_telemetry_test.json");
        let path_str = path.to_str().unwrap().to_string();

        let c = TelemetryCollector::new();
        c.record_unsupported_import("d3d11.dll", "D3D11CreateDevice");
        c.record_unsupported_method("IDXGISwapChain::ResizeTarget");
        c.record_unsupported_shader_model(0x65, 0x66);
        c.record_unimplemented_instruction("CLFLUSH");

        // Persist
        c.persist_to(&path_str).unwrap();
        assert!(path.exists());

        // Load into a fresh collector
        let c2 = TelemetryCollector::new();
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
        let c = TelemetryCollector::new();
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
        let c = TelemetryCollector::new();
        c.record_unsupported_import("x.dll", "y");
        assert_eq!(c.snapshot().unsupported_imports.len(), 1);
        c.clear();
        assert_eq!(c.snapshot().unsupported_imports.len(), 0);
    }

    #[test]
    fn test_persistence_path() {
        let c = TelemetryCollector::with_persistence_path("/tmp/test_telemetry.json");
        assert_eq!(c.persistence_path(), Some("/tmp/test_telemetry.json".to_string()));

        c.set_persistence_path(Some("/other/path.json"));
        assert_eq!(c.persistence_path(), Some("/other/path.json".to_string()));

        c.set_persistence_path(None);
        assert_eq!(c.persistence_path(), None);
    }
}
