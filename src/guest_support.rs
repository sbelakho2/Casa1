use crate::error::{AppError, AppResult};
use crate::ge::{StoredRegistryValue, load_registry_db, store_registry_db};
use crate::reason::ReasonCode;
use crate::trace::TraceEvent;
use crate::util;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

pub fn sample_guest_main<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let args = args
        .into_iter()
        .map(|value| value.into().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    match run_sample_guest(&args) {
        Ok(()) => 0,
        Err(error) => {
            let response = util::stable_json(&error.to_response())
                .unwrap_or_else(|_| "{\"reason_code\":1003,\"reason_name\":\"RC_IO\",\"message\":\"failed to encode guest error\",\"reproduction_hints\":[]}".to_string());
            eprintln!("{response}");
            1
        }
    }
}

fn run_sample_guest(args: &[String]) -> AppResult<()> {
    let ge_root = required_env_path("CASA1_GE_ROOT")?;
    let hkcu_path = required_env_path("CASA1_REGISTRY_HKCU")?;
    let trace_file = required_env_path("CASA1_TRACE_FILE")?;
    let dtm = env::var("CASA1_DTM").unwrap_or_default() == "1";
    let intent = env::var("CASA1_RUN_INTENT").unwrap_or_else(|_| "run".to_string());
    let silent = env::var("CASA1_INSTALL_SILENT").unwrap_or_default() == "1"
        || args.iter().any(|arg| arg == "--silent");
    let guid =
        env::var("CASA1_FIXED_GUID").unwrap_or_else(|_| util::deterministic_guid("guest", dtm));
    let guest_nonce = util::sha256_bytes(&util::noncrypto_random_bytes("guest-session", dtm, 16));
    let install_root = ge_root
        .join("drive_c")
        .join("Program Files")
        .join("Casa1 Sample");
    fs::create_dir_all(&install_root).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to create {}", install_root.display()),
            &error,
        )
    })?;
    let output_file = if intent == "install" {
        install_root.join("install.txt")
    } else {
        install_root.join("hello.txt")
    };
    let payload = format!("mode={intent};guid={guid};dtm={dtm}");
    util::write_string(&output_file, &payload)?;

    let mut hkcu = load_registry_db(&hkcu_path)?;
    let key = hkcu
        .entry("Software\\Casa1Test".to_string())
        .or_insert_with(BTreeMap::new);
    key.insert(
        "InstallPath".to_string(),
        StoredRegistryValue {
            value_type: "REG_SZ".to_string(),
            data: Value::String("C:\\Program Files\\Casa1 Sample".to_string()),
        },
    );
    key.insert(
        "GuestGuid".to_string(),
        StoredRegistryValue {
            value_type: "REG_SZ".to_string(),
            data: Value::String(guid.clone()),
        },
    );
    key.insert(
        "GuestNonce".to_string(),
        StoredRegistryValue {
            value_type: "REG_SZ".to_string(),
            data: Value::String(guest_nonce),
        },
    );
    key.insert(
        "RunMode".to_string(),
        StoredRegistryValue {
            value_type: "REG_SZ".to_string(),
            data: Value::String(intent.clone()),
        },
    );
    if let Ok(value) = env::var("CASA1_TEST_OVERRIDE_ENV") {
        key.insert(
            "OverrideEnv".to_string(),
            StoredRegistryValue {
                value_type: "REG_SZ".to_string(),
                data: Value::String(value),
            },
        );
    }
    if let Ok(value) = env::var("CASA1_ACTIVE_OVERRIDE_PAYLOAD") {
        key.insert(
            "ActiveOverridePayload".to_string(),
            StoredRegistryValue {
                value_type: "REG_SZ".to_string(),
                data: Value::String(value),
            },
        );
    }
    store_registry_db(&hkcu_path, &hkcu)?;

    let file_hash = util::sha256_file(&output_file)?;
    let guest_events = vec![
        trace_event(
            0,
            "file",
            "CreateDirectoryW",
            btreemap(vec![(
                "path".to_string(),
                Value::String("C:\\Program Files\\Casa1 Sample".to_string()),
            )]),
            json!(true),
            Vec::new(),
        ),
        trace_event(
            1,
            "file",
            "WriteFile",
            btreemap(vec![(
                "path".to_string(),
                Value::String(if intent == "install" {
                    "C:\\Program Files\\Casa1 Sample\\install.txt".to_string()
                } else {
                    "C:\\Program Files\\Casa1 Sample\\hello.txt".to_string()
                }),
            )]),
            json!(payload.len()),
            vec![file_hash],
        ),
        trace_event(
            2,
            "registry",
            "RegSetValueExW",
            btreemap(vec![(
                "key".to_string(),
                Value::String("HKCU\\Software\\Casa1Test\\GuestGuid".to_string()),
            )]),
            json!(guid),
            Vec::new(),
        ),
        trace_event(
            3,
            "time",
            "GetSystemTimeAsFileTime",
            btreemap(vec![("dtm".to_string(), json!(dtm))]),
            if dtm {
                json!(0)
            } else {
                json!(util::current_unix_ms())
            },
            Vec::new(),
        ),
    ];
    util::write_string(&trace_file, &util::stable_json(&guest_events)?)?;

    if !silent {
        if let Ok(value) = env::var("CASA1_TEST_OVERRIDE_ENV") {
            println!("Casa1 sample guest finished mode={intent} guid={guid} override={value}");
        } else {
            println!("Casa1 sample guest finished mode={intent} guid={guid}");
        }
    }
    eprintln!("guest-mode={intent}");
    if env::var("CASA1_SAMPLE_GUEST_CRASH").unwrap_or_default() == "1" {
        std::process::abort();
    }
    Ok(())
}

fn required_env_path(key: &str) -> AppResult<PathBuf> {
    env::var(key).map(PathBuf::from).map_err(|_| {
        AppError::new(
            ReasonCode::RcCliInvalid,
            format!("missing required environment variable {key}"),
        )
    })
}

fn trace_event(
    event_index: u64,
    category: &str,
    call_id: &str,
    parameters: BTreeMap<String, Value>,
    return_value: Value,
    side_effect_hashes: Vec<String>,
) -> TraceEvent {
    TraceEvent {
        event_index,
        category: category.to_string(),
        call_id: call_id.to_string(),
        parameters,
        return_value,
        get_last_error: None,
        side_effect_hashes,
    }
}

fn btreemap(entries: Vec<(String, Value)>) -> BTreeMap<String, Value> {
    entries.into_iter().collect()
}
