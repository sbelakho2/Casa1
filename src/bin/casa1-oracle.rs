use casa1::oracle_model::{
    ApiSetCase, ApiSetSuite, CaseCollisionSuite, DelayLoadCase, DelayLoadExpectation,
    DelayLoadSuite, DelayLoadSymbol, DllOrderSuite, ExportSpec, ExportSpecTarget,
    LifecycleLogEntry, LockShareSuite, PathEdgeCase, PathEdgeOutcome, PathEdgeSuite,
    RegistryNotifyOperation, RegistryNotifySuite,
};
use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};

const RC_FS_ALREADY_EXISTS: u32 = 1101;
const RC_FS_RESERVED_NAME: u32 = 1103;
const RC_FS_PATH_TOO_LONG: u32 = 1104;
const RC_FS_SHARING_VIOLATION: u32 = 1105;
const RC_FS_LOCK_VIOLATION: u32 = 1106;
const STATUS_DLL_NOT_FOUND: u32 = 0xc000_0135;
const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xc000_0139;

#[derive(Debug, Parser)]
struct OracleCli {
    #[command(subcommand)]
    command: OracleCommand,
}

#[derive(Debug, Subcommand)]
enum OracleCommand {
    #[command(name = "section2-path")]
    Section2Path,
    #[command(name = "section2-case")]
    Section2Case,
    #[command(name = "section2-lock")]
    Section2Lock,
    #[command(name = "section2-registry")]
    Section2Registry,
    #[command(name = "section3-dll-order")]
    Section3DllOrder,
    #[command(name = "section3-delay-load")]
    Section3DelayLoad,
    #[command(name = "section3-apiset")]
    Section3ApiSet,
}

fn main() {
    let cli = OracleCli::parse();
    let output = match cli.command {
        OracleCommand::Section2Path => serde_json::to_string(&section2_path_suite()),
        OracleCommand::Section2Case => serde_json::to_string(&section2_case_suite()),
        OracleCommand::Section2Lock => serde_json::to_string(&section2_lock_suite()),
        OracleCommand::Section2Registry => serde_json::to_string(&section2_registry_suite()),
        OracleCommand::Section3DllOrder => serde_json::to_string(&section3_dll_order_suite()),
        OracleCommand::Section3DelayLoad => serde_json::to_string(&section3_delay_load_suite()),
        OracleCommand::Section3ApiSet => serde_json::to_string(&section3_api_set_suite()),
    };
    match output {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to encode oracle suite: {error}");
            std::process::exit(1);
        }
    }
}

fn section2_path_suite() -> PathEdgeSuite {
    let long_path = format!(
        "C:\\{}",
        (0..40)
            .map(|index| format!("segment{index:02}"))
            .collect::<Vec<_>>()
            .join("\\")
    );
    PathEdgeSuite {
        cases: vec![
            (
                "C:\\Alpha\\Beta\\.\\Gamma\\..\\File.txt. ".to_string(),
                false,
            ),
            ("\\\\?\\C:\\Alpha\\Beta. ".to_string(), false),
            ("\\\\.\\pipe\\steam".to_string(), false),
            ("C:\\Temp\\NUL".to_string(), false),
            (long_path.clone(), false),
            (long_path, true),
        ]
        .into_iter()
        .map(|(input, long_paths_enabled)| PathEdgeCase {
            outcome: oracle_parse_windows_path(&input, long_paths_enabled),
            input,
            long_paths_enabled,
        })
        .collect(),
    }
}

fn section2_case_suite() -> CaseCollisionSuite {
    let mut directory = OracleDirectory::default();
    directory.create("ReadMe.TXT").expect("ASCII insert");
    directory.create("Σ.txt").expect("unicode insert");
    let unicode_collision_code = directory.create("ς.txt").expect_err("collision");
    let resolved_unicode_name = directory.resolve("ς.txt").expect("resolve unicode");
    CaseCollisionSuite {
        create_directory: "C:\\Case".to_string(),
        collision_directory: "C:\\case".to_string(),
        ascii_file: "C:\\Case\\ReadMe.TXT".to_string(),
        unicode_file: "C:\\Case\\Σ.txt".to_string(),
        unicode_lookup: "C:\\case\\ς.txt".to_string(),
        enumeration_path: "C:\\CASE".to_string(),
        directory_collision_code: RC_FS_ALREADY_EXISTS,
        unicode_collision_code,
        resolved_unicode_path: format!("C:\\case\\{}", resolved_unicode_name.to_lowercase()),
        enumeration: directory.enumeration(),
    }
}

fn section2_lock_suite() -> LockShareSuite {
    let first = OracleOpenState {
        desired_access: OracleFileAccess {
            read: true,
            write: true,
            delete: false,
        },
        share_mode: OracleShareMode {
            read: false,
            write: false,
            delete: false,
        },
    };
    let second_access = OracleFileAccess {
        read: true,
        write: false,
        delete: false,
    };
    let second_share = OracleShareMode {
        read: true,
        write: true,
        delete: true,
    };
    LockShareSuite {
        path: "C:\\Locks\\data.bin".to_string(),
        share_violation_code: if share_conflict(&first, second_access, second_share) {
            RC_FS_SHARING_VIOLATION
        } else {
            0
        },
        lock_violation_code: if ranges_overlap(0, 8, 4, 4) {
            RC_FS_LOCK_VIOLATION
        } else {
            0
        },
        first_lock_offset: 0,
        first_lock_length: 8,
        overlap_offset: 4,
        overlap_length: 4,
    }
}

fn section2_registry_suite() -> RegistryNotifySuite {
    let operations = vec![
        RegistryNotifyOperation::Set {
            value: "Alpha".to_string(),
            value_type: "REG_SZ".to_string(),
            data: serde_json::json!("one"),
        },
        RegistryNotifyOperation::Set {
            value: "Beta".to_string(),
            value_type: "REG_DWORD".to_string(),
            data: serde_json::json!(7),
        },
        RegistryNotifyOperation::Delete {
            value: "Alpha".to_string(),
        },
    ];
    RegistryNotifySuite {
        hive: "HKCU".to_string(),
        key: "Software\\Casa1\\OracleNotify".to_string(),
        recursive: true,
        expected_wake_count: operations.len() as u64,
        operations,
    }
}

fn section3_dll_order_suite() -> DllOrderSuite {
    let dependencies = BTreeMap::from([
        (
            "game.exe".to_string(),
            vec!["kernel32.dll".to_string(), "user32.dll".to_string()],
        ),
        ("user32.dll".to_string(), vec!["gdi32.dll".to_string()]),
        ("gdi32.dll".to_string(), Vec::new()),
        ("kernel32.dll".to_string(), Vec::new()),
    ]);
    let tls_callbacks = BTreeMap::from([
        ("kernel32.dll".to_string(), vec![0x1800_2000]),
        ("game.exe".to_string(), vec![0x1400_1010]),
    ]);
    let load_order = oracle_load_order("game.exe", &dependencies);
    DllOrderSuite {
        root_module: "game.exe".to_string(),
        dependencies,
        tls_callbacks: tls_callbacks.clone(),
        expected_log_lines: oracle_lifecycle_log_lines(&load_order, &tls_callbacks),
    }
}

fn section3_delay_load_suite() -> DelayLoadSuite {
    let resolved_provider_exports = BTreeMap::from([
        (
            "kernel32.dll".to_string(),
            vec![ExportSpec {
                ordinal: 18,
                name: Some("Forwarded".to_string()),
                target: ExportSpecTarget::Forwarder {
                    value: "KERNELBASE.Sleep".to_string(),
                },
            }],
        ),
        (
            "kernelbase.dll".to_string(),
            vec![ExportSpec {
                ordinal: 1,
                name: Some("Sleep".to_string()),
                target: ExportSpecTarget::Rva { value: 0x2500 },
            }],
        ),
    ]);
    DelayLoadSuite {
        cases: vec![
            DelayLoadCase {
                scenario: "resolved_forwarder".to_string(),
                requested_module: "kernel32.dll".to_string(),
                symbol: DelayLoadSymbol::ByName {
                    name: "Forwarded".to_string(),
                },
                expected: resolve_delay_expectation(
                    "kernel32.dll",
                    &DelayLoadSymbol::ByName {
                        name: "Forwarded".to_string(),
                    },
                    &resolved_provider_exports,
                ),
                provider_exports: resolved_provider_exports,
            },
            DelayLoadCase {
                scenario: "missing_provider".to_string(),
                requested_module: "missing.dll".to_string(),
                symbol: DelayLoadSymbol::ByName {
                    name: "Forwarded".to_string(),
                },
                expected: DelayLoadExpectation::StructuredException {
                    code: STATUS_DLL_NOT_FOUND,
                },
                provider_exports: BTreeMap::new(),
            },
            DelayLoadCase {
                scenario: "missing_entrypoint".to_string(),
                requested_module: "kernel32.dll".to_string(),
                symbol: DelayLoadSymbol::ByName {
                    name: "Forwarded".to_string(),
                },
                expected: DelayLoadExpectation::StructuredException {
                    code: STATUS_ENTRYPOINT_NOT_FOUND,
                },
                provider_exports: BTreeMap::from([("kernel32.dll".to_string(), Vec::new())]),
            },
        ],
    }
}

fn section3_api_set_suite() -> ApiSetSuite {
    ApiSetSuite {
        cases: [
            "api-ms-win-core-file-l1-1-0.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "ext-ms-win-ntuser-window-l1-1-0.dll",
            "custom.dll",
        ]
        .into_iter()
        .map(|contract| ApiSetCase {
            contract: contract.to_string(),
            expected_host: oracle_api_set_resolve(contract),
        })
        .collect(),
    }
}

#[derive(Debug, Default)]
struct OracleDirectory {
    by_folded_name: BTreeMap<String, String>,
}

impl OracleDirectory {
    fn create(&mut self, name: &str) -> Result<(), u32> {
        let folded = oracle_fold_key(name);
        if self.by_folded_name.contains_key(&folded) {
            return Err(RC_FS_ALREADY_EXISTS);
        }
        self.by_folded_name.insert(folded, name.to_string());
        Ok(())
    }

    fn resolve(&self, requested: &str) -> Option<String> {
        self.by_folded_name
            .get(&oracle_fold_key(requested))
            .cloned()
    }

    fn enumeration(&self) -> Vec<String> {
        let mut values = self.by_folded_name.values().cloned().collect::<Vec<_>>();
        values.sort();
        values
    }
}

#[derive(Debug, Clone, Copy)]
struct OracleFileAccess {
    read: bool,
    write: bool,
    delete: bool,
}

#[derive(Debug, Clone, Copy)]
struct OracleShareMode {
    read: bool,
    write: bool,
    delete: bool,
}

#[derive(Debug, Clone, Copy)]
struct OracleOpenState {
    desired_access: OracleFileAccess,
    share_mode: OracleShareMode,
}

fn oracle_parse_windows_path(input: &str, long_paths_enabled: bool) -> PathEdgeOutcome {
    let mut raw = input.replace('/', "\\");
    let verbatim = raw.starts_with("\\\\?\\");
    let device_namespace = raw.starts_with("\\\\.\\");
    if device_namespace {
        return PathEdgeOutcome::Success {
            normalized_path: raw,
            verbatim: false,
            device_namespace: true,
        };
    }
    if verbatim {
        raw = raw.trim_start_matches("\\\\?\\").to_string();
    }
    if raw.len() < 2 || !raw.as_bytes()[0].is_ascii_alphabetic() || raw.as_bytes()[1] != b':' {
        return PathEdgeOutcome::Error {
            reason_code: RC_FS_RESERVED_NAME,
        };
    }
    let drive = raw[0..1].to_ascii_uppercase();
    let mut remainder = raw[2..].to_string();
    if remainder.is_empty() {
        remainder.push('\\');
    }
    let mut components = Vec::new();
    for component in remainder.split('\\') {
        if component.is_empty() {
            continue;
        }
        let normalized_component = if verbatim {
            component.to_string()
        } else if component == "." {
            continue;
        } else if component == ".." {
            components.pop();
            continue;
        } else {
            let trimmed = component.trim_end_matches([' ', '.']);
            if trimmed.is_empty() {
                continue;
            }
            if is_reserved_dos_name(trimmed) {
                return PathEdgeOutcome::Error {
                    reason_code: RC_FS_RESERVED_NAME,
                };
            }
            trimmed.to_string()
        };
        components.push(normalized_component);
    }
    let normalized_path = if verbatim {
        format!("\\\\?\\{}", build_drive_path(&drive, &components))
    } else {
        build_drive_path(
            &drive,
            &components
                .iter()
                .map(|component| component.to_lowercase())
                .collect::<Vec<_>>(),
        )
    };
    if !verbatim && !long_paths_enabled && normalized_path.len() > 260 {
        return PathEdgeOutcome::Error {
            reason_code: RC_FS_PATH_TOO_LONG,
        };
    }
    PathEdgeOutcome::Success {
        normalized_path,
        verbatim,
        device_namespace: false,
    }
}

fn oracle_fold_key(value: &str) -> String {
    let mut folded = String::new();
    for character in value.chars() {
        let mut uppercase = character.to_uppercase();
        match (uppercase.next(), uppercase.next()) {
            (Some(single), None) => folded.push(single),
            _ => {
                let mut lowercase = character.to_lowercase();
                match (lowercase.next(), lowercase.next()) {
                    (Some(single), None) => folded.push(single),
                    _ => folded.push(character),
                }
            }
        }
    }
    folded
}

fn share_conflict(
    existing: &OracleOpenState,
    desired_access: OracleFileAccess,
    share_mode: OracleShareMode,
) -> bool {
    (desired_access.read && !existing.share_mode.read)
        || (desired_access.write && !existing.share_mode.write)
        || (desired_access.delete && !existing.share_mode.delete)
        || (existing.desired_access.read && !share_mode.read)
        || (existing.desired_access.write && !share_mode.write)
        || (existing.desired_access.delete && !share_mode.delete)
}

fn ranges_overlap(
    left_offset: u64,
    left_length: u64,
    right_offset: u64,
    right_length: u64,
) -> bool {
    let left_end = left_offset.saturating_add(left_length);
    let right_end = right_offset.saturating_add(right_length);
    left_offset < right_end && right_offset < left_end
}

fn oracle_load_order(
    root_module: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    oracle_visit(
        &normalize_module_name(root_module),
        dependencies,
        &mut visiting,
        &mut visited,
        &mut order,
    );
    order
}

fn oracle_visit(
    module: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    if visited.contains(module) {
        return;
    }
    if !visiting.insert(module.to_string()) {
        return;
    }
    for dependency in dependencies.get(module).into_iter().flatten() {
        oracle_visit(
            &normalize_module_name(dependency),
            dependencies,
            visiting,
            visited,
            order,
        );
    }
    visiting.remove(module);
    visited.insert(module.to_string());
    order.push(module.to_string());
}

fn oracle_lifecycle_log_lines(
    load_order: &[String],
    tls_callbacks: &BTreeMap<String, Vec<u64>>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for module in load_order {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_process_attach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_process_attach", None));
    }
    for module in load_order {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_thread_attach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_thread_attach", None));
    }
    for module in load_order.iter().rev() {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_thread_detach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_thread_detach", None));
    }
    for module in load_order.iter().rev() {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            lines.push(log_line(module, "tls_process_detach", Some(*callback)));
        }
        lines.push(log_line(module, "dllmain_process_detach", None));
    }
    lines
}

fn log_line(module: &str, stage: &str, value: Option<u64>) -> String {
    serde_json::to_string(&LifecycleLogEntry {
        module: module.to_string(),
        stage: stage.to_string(),
        value,
    })
    .expect("encode lifecycle log line")
}

fn resolve_delay_expectation(
    requested_module: &str,
    symbol: &DelayLoadSymbol,
    provider_exports: &BTreeMap<String, Vec<ExportSpec>>,
) -> DelayLoadExpectation {
    let resolved_module = normalize_module_name(requested_module);
    let Some(exports) = provider_exports.get(&resolved_module) else {
        return DelayLoadExpectation::StructuredException {
            code: STATUS_DLL_NOT_FOUND,
        };
    };
    match oracle_lookup_export(
        symbol,
        &resolved_module,
        exports,
        provider_exports,
        &mut BTreeSet::new(),
    ) {
        Some(export) => DelayLoadExpectation::Resolved { export },
        None => DelayLoadExpectation::StructuredException {
            code: STATUS_ENTRYPOINT_NOT_FOUND,
        },
    }
}

fn oracle_lookup_export(
    symbol: &DelayLoadSymbol,
    current_module: &str,
    exports: &[ExportSpec],
    provider_exports: &BTreeMap<String, Vec<ExportSpec>>,
    visited: &mut BTreeSet<String>,
) -> Option<ExportSpec> {
    let visit_key = format!("{}::{symbol:?}", current_module);
    if !visited.insert(visit_key) {
        return None;
    }
    let export = match symbol {
        DelayLoadSymbol::ByName { name } => exports
            .iter()
            .find(|export| export.name.as_deref() == Some(name.as_str()))
            .cloned(),
        DelayLoadSymbol::ByOrdinal { ordinal } => exports
            .iter()
            .find(|export| export.ordinal == *ordinal as u32)
            .cloned(),
    }?;
    match &export.target {
        ExportSpecTarget::Rva { .. } => Some(export),
        ExportSpecTarget::Forwarder { value } => {
            let (module_name, forwarded_symbol) = parse_forwarder(value)?;
            let exports = provider_exports.get(&module_name)?;
            oracle_lookup_export(
                &forwarded_symbol,
                &module_name,
                exports,
                provider_exports,
                visited,
            )
        }
    }
}

fn parse_forwarder(value: &str) -> Option<(String, DelayLoadSymbol)> {
    let (module, symbol) = value.split_once('.')?;
    if let Some(rest) = symbol.strip_prefix('#') {
        let ordinal = rest.parse::<u16>().ok()?;
        Some((
            normalize_module_name(module),
            DelayLoadSymbol::ByOrdinal { ordinal },
        ))
    } else {
        Some((
            normalize_module_name(module),
            DelayLoadSymbol::ByName {
                name: symbol.to_string(),
            },
        ))
    }
}

fn oracle_api_set_resolve(dll_name: &str) -> String {
    let normalized = normalize_module_name(dll_name);
    if normalized.starts_with("api-ms-win-core-") {
        return "kernel32.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-crt-") {
        return "ucrtbase.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-security-")
        || normalized.starts_with("api-ms-win-service-")
    {
        return "advapi32.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-shell-") {
        return "shell32.dll".to_string();
    }
    if normalized.starts_with("api-ms-win-com-") || normalized.starts_with("api-ms-win-core-com-") {
        return "ole32.dll".to_string();
    }
    if normalized.starts_with("ext-ms-win-ntuser-") {
        return "user32.dll".to_string();
    }
    normalized
}

fn normalize_module_name(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.contains('.') {
        normalized
    } else {
        format!("{normalized}.dll")
    }
}

fn build_drive_path(drive: &str, components: &[String]) -> String {
    if components.is_empty() {
        format!("{drive}:\\")
    } else {
        format!("{drive}:\\{}", components.join("\\"))
    }
}

fn is_reserved_dos_name(component: &str) -> bool {
    let name = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    matches!(
        name.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}
