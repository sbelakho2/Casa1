//! advapi32.dll subsystem models: the access-token model, the service
//! control manager (SCM) database, and the CryptoAPI provider/hash/key
//! contexts.
//!
//! The module holds the *model* (pure data + operations); the guest-memory
//! marshalling lives in the runtime dispatch arms, following the same
//! split as [`crate::winmm`] and [`crate::midi`].
//!
//! - **Access tokens** — the process token carries the guest user SID,
//!   the standard group SIDs and the standard privilege list with the
//!   documented LUID constants.  `AdjustTokenPrivileges`,
//!   `OpenProcessToken`, `OpenThreadToken`, `GetTokenInformation`,
//!   `DuplicateTokenEx`, `ImpersonateLoggedOnUser`/`RevertToSelf` and
//!   `LookupPrivilegeValueW` all operate on this model.
//! - **SCM** — a service database stored in the guest registry at
//!   `HKLM\SYSTEM\CurrentControlSet\Services\<name>` (the documented
//!   location) with the service configuration values; the runtime keeps
//!   the documented status flow (STOPPED → START_PENDING → RUNNING →
//!   STOP_PENDING → STOPPED) and the documented errors
//!   (`ERROR_SERVICE_DOES_NOT_EXIST`, `ERROR_SERVICE_EXISTS`,
//!   `ERROR_SERVICE_ALREADY_RUNNING`, `ERROR_SERVICE_MARKED_FOR_DELETE`).
//! - **CryptoAPI** — provider contexts keyed by HCRYPTPROV (with the
//!   container name), hash objects (MD5/SHA-1/SHA-2 through the shared
//!   digest machinery) and key objects (RC4/RC2/3DES/DES/AES through
//!   [`crate::crypto`] and the AES machinery), with the documented
//!   buffer/padding contracts of `CryptEncrypt`/`CryptDecrypt`.

use crate::ge::{GameEnvironment, RegistryView, StoredRegistryValue};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Access-token model
// ---------------------------------------------------------------------------

/// A well-known privilege with its documented LUID constant and enabled
/// state in the guest user's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivilegeEntry {
    pub name: &'static str,
    pub luid: u32,
    pub enabled: bool,
}

/// The standard privileges of a normal interactive guest user's token
/// (the documented LUID constants from winnt.h).
pub fn standard_privileges() -> Vec<PrivilegeEntry> {
    vec![
        PrivilegeEntry {
            name: "SeChangeNotifyPrivilege",
            luid: 23,
            enabled: true,
        },
        PrivilegeEntry {
            name: "SeIncreaseWorkingSetPrivilege",
            luid: 32,
            enabled: true,
        },
        PrivilegeEntry {
            name: "SeImpersonatePrivilege",
            luid: 29,
            enabled: true,
        },
        PrivilegeEntry {
            name: "SeCreateGlobalPrivilege",
            luid: 30,
            enabled: true,
        },
        PrivilegeEntry {
            name: "SeShutdownPrivilege",
            luid: 19,
            enabled: false,
        },
        PrivilegeEntry {
            name: "SeTimeZonePrivilege",
            luid: 33,
            enabled: false,
        },
        PrivilegeEntry {
            name: "SeUndockPrivilege",
            luid: 31,
            enabled: false,
        },
        PrivilegeEntry {
            name: "SeIncreaseQuotaPrivilege",
            luid: 5,
            enabled: false,
        },
        PrivilegeEntry {
            name: "SeAssignPrimaryTokenPrivilege",
            luid: 3,
            enabled: false,
        },
        PrivilegeEntry {
            name: "SeSecurityPrivilege",
            luid: 8,
            enabled: false,
        },
    ]
}

/// Resolve a privilege name to its documented LUID (winnt.h constants).
/// Case-insensitive, with the `Se` prefix and `Privilege` suffix
/// tolerated.
pub fn lookup_privilege_luid(name: &str) -> Option<u32> {
    let mut normalized = name.to_ascii_lowercase();
    if let Some(stripped) = normalized.strip_prefix("se") {
        normalized = stripped.to_string();
    }
    if let Some(stripped) = normalized.strip_suffix("privilege") {
        normalized = stripped.to_string();
    }
    match normalized.as_str() {
        "createtoken" => Some(1),
        "assigndprimarytoken" => Some(3),
        "lockmemory" => Some(4),
        "increasequota" => Some(5),
        "machineaccount" => Some(6),
        "tcb" => Some(7),
        "security" => Some(8),
        "takeownership" => Some(9),
        "loaddriver" => Some(10),
        "systemprofile" => Some(11),
        "systemtime" => Some(12),
        "profilesingleprocess" => Some(13),
        "increasebasepriority" => Some(14),
        "createpagefile" => Some(15),
        "createpermanent" => Some(16),
        "backup" => Some(17),
        "restore" => Some(18),
        "shutdown" => Some(19),
        "debug" => Some(20),
        "audit" => Some(21),
        "systemenvironment" => Some(22),
        "changenotify" => Some(23),
        "remote_shutdown" => Some(24),
        "undock" => Some(31),
        "managevolume" => Some(28),
        "impersonate" => Some(29),
        "createglobal" => Some(30),
        "increaseworkingset" => Some(32),
        "timezone" => Some(33),
        "createsymboliclink" => Some(34),
        "delegatesessionuserimpersonate" => Some(35),
        _ => None,
    }
}

/// Encode a SID string (`S-1-5-21-...-1001`) into its binary form
/// (revision byte, subauthority count byte, 6-byte identifier authority
/// big-endian, subauthorities little-endian).
pub fn encode_sid(sid_string: &str) -> Option<Vec<u8>> {
    let rest = sid_string.strip_prefix("S-")?;
    let mut parts = rest.split('-');
    let revision: u8 = parts.next()?.parse().ok()?;
    let authority: u64 = parts.next()?.parse().ok()?;
    if authority > 0xFF_FFFF_FFFF_FFFF {
        return None; // the 48-bit authority field cannot hold more
    }
    let subauthorities = parts
        .map(|part| part.parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()?;
    if subauthorities.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(8 + subauthorities.len() * 4);
    out.push(revision);
    out.push(subauthorities.len() as u8);
    // The 48-bit authority is the low 6 bytes of the big-endian u64.
    out.extend_from_slice(&authority.to_be_bytes()[2..]);
    for subauthority in subauthorities {
        out.extend_from_slice(&subauthority.to_le_bytes());
    }
    Some(out)
}

/// Decode a binary SID into its canonical `S-...` string form.
pub fn decode_sid(sid: &[u8]) -> Option<String> {
    if sid.len() < 8 {
        return None;
    }
    let revision = sid[0];
    let count = sid[1] as usize;
    if sid.len() != 8 + count * 4 {
        return None;
    }
    let authority = u64::from_be_bytes([0, 0, sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]]);
    let mut out = format!("S-{revision}-{authority}");
    for index in 0..count {
        let offset = 8 + index * 4;
        let sub = u32::from_le_bytes([
            sid[offset],
            sid[offset + 1],
            sid[offset + 2],
            sid[offset + 3],
        ]);
        out.push('-');
        out.push_str(&sub.to_string());
    }
    Some(out)
}

/// Compare two binary SIDs for equality.
pub fn sid_equal(left: &[u8], right: &[u8]) -> bool {
    left == right
}

/// The guest user's SID (a well-known-style user RID in the runtime's
/// synthetic domain): `S-1-5-21-3654781254-1934577812-2019068222-1001`.
pub fn guest_user_sid() -> Vec<u8> {
    encode_sid("S-1-5-21-3654781254-1934577812-2019068222-1001").expect("guest user SID encodes")
}

/// The standard group SIDs of the guest user's token.
pub fn guest_group_sids() -> Vec<Vec<u8>> {
    [
        "S-1-5-32-544", // Administrators
        "S-1-5-32-545", // Users
        "S-1-1-0",      // Everyone
        "S-1-5-11",     // Authenticated Users
        "S-1-5-32-554", // BUILTIN\Pre-Windows 2000 Compatible Access
    ]
    .iter()
    .map(|sid| encode_sid(sid).expect("group SID encodes"))
    .collect()
}

/// Resolve a well-known account name to its SID (the documented
/// BUILTIN/well-known SIDs plus the guest user).
pub fn lookup_account_name(name: &str) -> Option<(Vec<u8>, u32)> {
    // (binary SID, SID_NAME_USE: 1 = SidTypeUser, 4 = SidTypeGroup,
    //  5 = SidTypeWellKnownGroup, 6 = SidTypeAlias)
    match name.to_ascii_lowercase().as_str() {
        "guestuser" | "user" => Some((guest_user_sid(), 1)),
        "administrators" | "administrators group" => {
            Some((encode_sid("S-1-5-32-544").expect("SID"), 6))
        }
        "users" => Some((encode_sid("S-1-5-32-545").expect("SID"), 6)),
        "everyone" | "world" => Some((encode_sid("S-1-1-0").expect("SID"), 5)),
        "authenticated users" => Some((encode_sid("S-1-5-11").expect("SID"), 5)),
        "system" | "local system" | "nt authority\\system" => {
            Some((encode_sid("S-1-5-18").expect("SID"), 1))
        }
        "guest" => Some((
            encode_sid("S-1-5-21-3654781254-1934577812-2019068222-501").expect("SID"),
            1,
        )),
        _ => None,
    }
}

/// The access-token model: the process token (with the guest user SID,
/// group SIDs and standard privileges) plus an optional impersonation
/// token.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub user_name: String,
    pub user_sid: Vec<u8>,
    pub group_sids: Vec<Vec<u8>>,
    pub privileges: Vec<PrivilegeEntry>,
    /// Whether the token currently impersonates (an impersonation token
    /// attached by `ImpersonateLoggedOnUser`).
    pub impersonating: bool,
    /// Impersonation level for duplicated/impersonation tokens
    /// (SecurityImpersonation = 2).
    pub impersonation_level: u32,
}

impl TokenInfo {
    /// The process token for the guest user.
    pub fn process_token() -> Self {
        Self {
            user_name: "user".to_string(),
            user_sid: guest_user_sid(),
            group_sids: guest_group_sids(),
            privileges: standard_privileges(),
            impersonating: false,
            impersonation_level: 2,
        }
    }

    /// Whether the token (user or groups) contains `sid`.
    pub fn contains_sid(&self, sid: &[u8]) -> bool {
        sid_equal(&self.user_sid, sid) || self.group_sids.iter().any(|group| sid_equal(group, sid))
    }

    /// Set the enabled state of a privilege by LUID.  Returns `true`
    /// when the LUID is present in the token.
    pub fn set_privilege_state(&mut self, luid: u32, enable: bool) -> bool {
        let Some(entry) = self.privileges.iter_mut().find(|entry| entry.luid == luid) else {
            return false;
        };
        entry.enabled = enable;
        true
    }

    /// Whether the privilege with `luid` is present and enabled.
    pub fn privilege_enabled(&self, luid: u32) -> bool {
        self.privileges
            .iter()
            .any(|entry| entry.luid == luid && entry.enabled)
    }
}

// ---------------------------------------------------------------------------
// Service control manager (SCM)
// ---------------------------------------------------------------------------

/// Documented SERVICE_STATUS state values.
pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_START_PENDING: u32 = 2;
pub const SERVICE_STOP_PENDING: u32 = 3;
pub const SERVICE_RUNNING: u32 = 4;
pub const SERVICE_CONTINUE_PENDING: u32 = 5;
pub const SERVICE_PAUSE_PENDING: u32 = 6;
pub const SERVICE_PAUSED: u32 = 7;

/// Documented service-type values.
pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
pub const SERVICE_WIN32_SHARE_PROCESS: u32 = 0x20;
pub const SERVICE_KERNEL_DRIVER: u32 = 0x01;
pub const SERVICE_FILE_SYSTEM_DRIVER: u32 = 0x02;
pub const SERVICE_INTERACTIVE_PROCESS: u32 = 0x100;
pub const SERVICE_TYPE_ALL: u32 = 0x13F;

/// Documented start-type values.
pub const SERVICE_BOOT_START: u32 = 0;
pub const SERVICE_SYSTEM_START: u32 = 1;
pub const SERVICE_AUTO_START: u32 = 2;
pub const SERVICE_DEMAND_START: u32 = 3;
pub const SERVICE_DISABLED: u32 = 4;

/// Documented error-control values.
pub const SERVICE_ERROR_IGNORE: u32 = 0;
pub const SERVICE_ERROR_NORMAL: u32 = 1;
pub const SERVICE_ERROR_SEVERE: u32 = 2;
pub const SERVICE_ERROR_CRITICAL: u32 = 3;

/// Documented control codes.
pub const SERVICE_CONTROL_STOP: u32 = 1;
pub const SERVICE_CONTROL_PAUSE: u32 = 2;
pub const SERVICE_CONTROL_CONTINUE: u32 = 3;
pub const SERVICE_CONTROL_INTERROGATE: u32 = 4;
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 5;

/// Documented SERVICE_STATUS.dwControlsAccepted bits.
pub const SERVICE_ACCEPT_STOP: u32 = 0x1;
pub const SERVICE_ACCEPT_PAUSE_CONTINUE: u32 = 0x2;
pub const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x4;
pub const SERVICE_ACCEPT_PARAMCHANGE: u32 = 0x8;
pub const SERVICE_ACCEPT_NETBINDCHANGE: u32 = 0x10;
pub const SERVICE_ACCEPT_HARDWAREPROFILECHANGE: u32 = 0x20;
pub const SERVICE_ACCEPT_POWEREVENT: u32 = 0x40;
pub const SERVICE_ACCEPT_SESSIONCHANGE: u32 = 0x80;

/// The controls a guest Win32 service accepts (the documented default).
pub const SERVICE_ACCEPT_DEFAULT: u32 = SERVICE_ACCEPT_STOP
    | SERVICE_ACCEPT_PAUSE_CONTINUE
    | SERVICE_ACCEPT_SHUTDOWN
    | SERVICE_ACCEPT_PARAMCHANGE;

/// Documented SCM error codes (winerror.h).
pub const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
pub const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
pub const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;
pub const ERROR_SERVICE_EXISTS: u32 = 1073;
pub const ERROR_SERVICE_NOT_ACTIVE: u32 = 1063;
pub const ERROR_DUPLICATE_SERVICE_NAME: u32 = 1078;
pub const ERROR_SERVICE_NEVER_STARTED: u32 = 1058;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_ALREADY_EXISTS: u32 = 183;

/// The registry path of the service database (the documented location of
/// the SCM's service configuration).
pub fn scm_service_key(name: &str) -> String {
    format!("SYSTEM\\CurrentControlSet\\Services\\{name}")
}

/// The registry path of a service's status values.
pub fn scm_service_status_key(name: &str) -> String {
    format!("SYSTEM\\CurrentControlSet\\Services\\{name}\\Status")
}

/// The runtime's in-memory status flow for one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatusFlow {
    pub state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub checkpoint: u32,
    pub wait_hint: u32,
    /// True once `DeleteService` marked the service for deletion.
    pub marked_for_delete: bool,
}

impl ServiceStatusFlow {
    pub fn new(controls_accepted: u32) -> Self {
        Self {
            state: SERVICE_STOPPED,
            controls_accepted,
            win32_exit_code: ERROR_SUCCESS,
            service_specific_exit_code: 0,
            checkpoint: 0,
            wait_hint: 0,
            marked_for_delete: false,
        }
    }

    /// Apply a control code (ControlService) with the documented state
    /// transitions; returns the error code (ERROR_SUCCESS or
    /// ERROR_SERVICE_NOT_ACTIVE when the service is not running).
    pub fn apply_control(&mut self, control: u32) -> u32 {
        match control {
            SERVICE_CONTROL_INTERROGATE => ERROR_SUCCESS,
            SERVICE_CONTROL_STOP => {
                if self.state == SERVICE_STOPPED {
                    return ERROR_SERVICE_NOT_ACTIVE;
                }
                self.state = SERVICE_STOP_PENDING;
                self.checkpoint += 1;
                self.wait_hint = 30000;
                ERROR_SUCCESS
            }
            SERVICE_CONTROL_PAUSE => {
                if self.state != SERVICE_RUNNING {
                    return ERROR_SERVICE_NOT_ACTIVE;
                }
                self.state = SERVICE_PAUSE_PENDING;
                self.checkpoint += 1;
                ERROR_SUCCESS
            }
            SERVICE_CONTROL_CONTINUE => {
                if self.state != SERVICE_PAUSED && self.state != SERVICE_PAUSE_PENDING {
                    return ERROR_SERVICE_NOT_ACTIVE;
                }
                self.state = SERVICE_CONTINUE_PENDING;
                self.checkpoint += 1;
                ERROR_SUCCESS
            }
            _ => ERROR_INVALID_PARAMETER,
        }
    }

    /// Advance a pending transition to its settled state (the runtime
    /// resolves START_PENDING → RUNNING and STOP_PENDING → STOPPED as the
    /// deterministic model of the service's work completing).
    pub fn settle(&mut self) {
        match self.state {
            SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING => {
                self.state = SERVICE_RUNNING;
            }
            SERVICE_STOP_PENDING | SERVICE_PAUSE_PENDING => {
                self.state = if self.state == SERVICE_STOP_PENDING {
                    SERVICE_STOPPED
                } else {
                    SERVICE_PAUSED
                };
            }
            _ => {}
        }
        self.checkpoint = 0;
        self.wait_hint = 0;
    }

    /// `StartServiceW`: the documented ERROR_SERVICE_ALREADY_RUNNING when
    /// the service is active.
    pub fn start(&mut self) -> u32 {
        if self.marked_for_delete {
            return ERROR_SERVICE_MARKED_FOR_DELETE;
        }
        if matches!(
            self.state,
            SERVICE_RUNNING | SERVICE_START_PENDING | SERVICE_PAUSE_PENDING | SERVICE_PAUSED
        ) {
            return ERROR_SERVICE_ALREADY_RUNNING;
        }
        self.state = SERVICE_START_PENDING;
        self.checkpoint = 1;
        self.wait_hint = 30000;
        ERROR_SUCCESS
    }
}

/// Read a REG_DWORD service value from the guest registry.
pub fn service_registry_dword(
    ge: &GameEnvironment,
    service_name: &str,
    value_name: &str,
    view: RegistryView,
) -> Option<u32> {
    let key = scm_service_key(service_name);
    let stored = ge
        .registry_get_value("HKLM", &key, value_name, view)
        .ok()
        .flatten()?;
    match stored.value_type.to_ascii_uppercase().as_str() {
        "REG_DWORD" => stored.data.as_u64().map(|value| value as u32),
        _ => None,
    }
}

/// Read a REG_SZ service value from the guest registry.
pub fn service_registry_string(
    ge: &GameEnvironment,
    service_name: &str,
    value_name: &str,
    view: RegistryView,
) -> Option<String> {
    let key = scm_service_key(service_name);
    let stored = ge
        .registry_get_value("HKLM", &key, value_name, view)
        .ok()
        .flatten()?;
    match stored.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" => stored.data.as_str().map(str::to_string),
        _ => None,
    }
}

/// Write a REG_DWORD service value into the guest registry.
pub fn set_service_registry_dword(
    ge: &GameEnvironment,
    service_name: &str,
    value_name: &str,
    value: u32,
    view: RegistryView,
) -> Result<(), String> {
    let key = scm_service_key(service_name);
    ge.registry_set_value(
        "HKLM",
        &key,
        value_name,
        "REG_DWORD",
        Value::from(value),
        view,
    )
    .map_err(|error| error.to_string())
}

/// Write a REG_SZ service value into the guest registry.
pub fn set_service_registry_string(
    ge: &GameEnvironment,
    service_name: &str,
    value_name: &str,
    value: &str,
    view: RegistryView,
) -> Result<(), String> {
    let key = scm_service_key(service_name);
    ge.registry_set_value(
        "HKLM",
        &key,
        value_name,
        "REG_SZ",
        Value::from(value.to_string()),
        view,
    )
    .map_err(|error| error.to_string())
}

/// Create a service in the registry database.
///
/// Returns `Err(ERROR_SERVICE_EXISTS)` when the service key already
/// exists; `Ok(())` after writing the documented configuration values.
#[allow(clippy::too_many_arguments)]
pub fn create_service(
    ge: &GameEnvironment,
    name: &str,
    display_name: &str,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary_path: &str,
    view: RegistryView,
) -> Result<(), u32> {
    let key = scm_service_key(name);
    if ge
        .registry_key_exists("HKLM", &key, view)
        .map_err(|_| ERROR_ACCESS_DENIED)?
    {
        return Err(ERROR_SERVICE_EXISTS);
    }
    ge.registry_create_key("HKLM", &key, view)
        .map_err(|_| ERROR_ACCESS_DENIED)?;
    let write = |value_name: &str, value: u32| -> Result<(), u32> {
        set_service_registry_dword(ge, name, value_name, value, view)
            .map_err(|_| ERROR_ACCESS_DENIED)
    };
    write("Type", service_type)?;
    write("Start", start_type)?;
    write("ErrorControl", error_control)?;
    set_service_registry_string(ge, name, "ImagePath", binary_path, view)
        .map_err(|_| ERROR_ACCESS_DENIED)?;
    set_service_registry_string(ge, name, "DisplayName", display_name, view)
        .map_err(|_| ERROR_ACCESS_DENIED)?;
    // The documented object name: the guest user runs services.
    let _ = set_service_registry_string(ge, name, "ObjectName", "LocalSystem", view);
    Ok(())
}

/// Whether a service exists in the registry database.
pub fn service_exists(ge: &GameEnvironment, name: &str, view: RegistryView) -> bool {
    ge.registry_key_exists("HKLM", &scm_service_key(name), view)
        .unwrap_or(false)
}

/// Delete a service from the registry database (DeleteService).  A
/// missing service reports ERROR_SERVICE_DOES_NOT_EXIST.
pub fn delete_service(ge: &GameEnvironment, name: &str, view: RegistryView) -> Result<(), u32> {
    if !service_exists(ge, name, view) {
        return Err(ERROR_SERVICE_DOES_NOT_EXIST);
    }
    ge.registry_delete_key("HKLM", &scm_service_key(name), view)
        .map_err(|_| ERROR_ACCESS_DENIED)
}

/// Enumerate the services in the database (sorted, matching
/// EnumServicesStatus order).
pub fn enumerate_services(ge: &GameEnvironment, view: RegistryView) -> Vec<String> {
    let mut services = ge
        .registry_enum_keys("HKLM", "SYSTEM\\CurrentControlSet\\Services", view)
        .unwrap_or_default();
    services.sort();
    services
}

// ---------------------------------------------------------------------------
// CryptoAPI provider / hash / key model
// ---------------------------------------------------------------------------

/// Documented CryptoAPI algorithm identifiers (wincrypt.h).
pub const CALG_MD5: u32 = 0x0000_8003;
pub const CALG_SHA1: u32 = 0x0000_8004;
pub const CALG_SHA_256: u32 = 0x0000_800C;
pub const CALG_SHA_384: u32 = 0x0000_800D;
pub const CALG_SHA_512: u32 = 0x0000_800E;
pub const CALG_RC4: u32 = 0x0000_6801;
pub const CALG_RC2: u32 = 0x0000_6602;
pub const CALG_3DES: u32 = 0x0000_6603;
pub const CALG_DES: u32 = 0x0000_6601;
pub const CALG_AES_128: u32 = 0x0000_660E;
pub const CALG_AES_256: u32 = 0x0000_6610;

/// Documented CryptoAPI error codes (winerror.h, NTE_*).
pub const NTE_BAD_ALGID: u32 = 0x8009_0001;
pub const NTE_BAD_HASH: u32 = 0x8009_0003;
pub const NTE_BAD_UID: u32 = 0x8009_0004;
pub const NTE_BAD_KEY: u32 = 0x8009_0005;
pub const NTE_BAD_DATA: u32 = 0x8009_0006;
pub const NTE_BAD_TYPE: u32 = 0x8009_0007;
pub const NTE_BAD_FLAGS: u32 = 0x8009_0009;

/// Documented winerror values used by the crypto arms.
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NO_SUCH_PRIVILEGE: u32 = 1313;
pub const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
pub const ERROR_NO_TOKEN: u32 = 1008;
pub const ERROR_LOGON_FAILURE: u32 = 1326;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_NOT_SUPPORTED: u32 = 50;

/// The name of a provider type (for the provider registry model).
pub fn provider_type_name(provider_type: u32) -> &'static str {
    match provider_type {
        1 => "RSA Full",
        2 => "RSA Sig",
        3 => "DSS",
        12 => "RSA AES",
        13 => "RSA Full AES",
        24 => "RSA AES AES",
        _ => "Provider",
    }
}

/// A CryptoAPI provider context (HCRYPTPROV).
#[derive(Debug, Clone)]
pub struct CryptProvider {
    /// The container name ("" for CRYPT_VERIFYCONTEXT contexts).
    pub container: String,
    pub provider_type: u32,
    pub verify_context: bool,
}

/// A CryptoAPI hash object (HCRYPTHASH): the algorithm and the bytes fed
/// by CryptHashData; the digest is finalized by CryptGetHashParam.
#[derive(Debug, Clone)]
pub struct CryptHashState {
    pub algorithm: u32,
    pub data: Vec<u8>,
}

/// A CryptoAPI key object (HCRYPTKEY).
#[derive(Debug, Clone)]
pub struct CryptKeyState {
    pub algorithm: u32,
    pub key: Vec<u8>,
    /// CBC chaining state (the key object owns the IV, as documented).
    pub iv: [u8; 8],
    /// Block size in bytes (0 for the RC4 stream cipher).
    pub block_size: usize,
}

impl CryptHashState {
    /// Whether `algorithm` is a supported digest algorithm.
    pub fn is_supported_algorithm(algorithm: u32) -> bool {
        matches!(
            algorithm,
            CALG_MD5 | CALG_SHA1 | CALG_SHA_256 | CALG_SHA_384 | CALG_SHA_512
        )
    }

    /// The digest size in bytes of `algorithm`.
    pub fn digest_size(algorithm: u32) -> Option<usize> {
        match algorithm {
            CALG_MD5 => Some(16),
            CALG_SHA1 => Some(20),
            CALG_SHA_256 => Some(32),
            CALG_SHA_384 => Some(48),
            CALG_SHA_512 => Some(64),
            _ => None,
        }
    }

    /// Finalize the digest through the shared digest machinery.
    pub fn finish(&self) -> Option<Vec<u8>> {
        match self.algorithm {
            CALG_MD5 => Some(crate::crypto::md5(&self.data).to_vec()),
            CALG_SHA1 => Some(crate::crypto::sha1(&self.data).to_vec()),
            CALG_SHA_256 => Some(crate::network::sha256_hash(&self.data).to_vec()),
            CALG_SHA_384 => {
                use sha2::{Digest, Sha384};
                let mut hasher = Sha384::new();
                hasher.update(&self.data);
                Some(hasher.finalize().to_vec())
            }
            CALG_SHA_512 => {
                use sha2::{Digest, Sha512};
                let mut hasher = Sha512::new();
                hasher.update(&self.data);
                Some(hasher.finalize().to_vec())
            }
            _ => None,
        }
    }
}

impl CryptKeyState {
    /// Whether `algorithm` is a supported key algorithm.
    pub fn is_supported_algorithm(algorithm: u32) -> bool {
        matches!(
            algorithm,
            CALG_RC4 | CALG_RC2 | CALG_3DES | CALG_DES | CALG_AES_128 | CALG_AES_256
        )
    }

    /// The documented key length in bytes for `algorithm` (RC2 takes its
    /// length from the derivation, defaulting to 8).
    pub fn key_length(algorithm: u32) -> Option<usize> {
        match algorithm {
            CALG_RC4 => Some(16),
            CALG_RC2 => Some(8),
            CALG_3DES => Some(24),
            CALG_DES => Some(8),
            CALG_AES_128 => Some(16),
            CALG_AES_256 => Some(32),
            _ => None,
        }
    }

    /// Derive key material from a hash digest (CryptDeriveKey): the
    /// digest is truncated or zero-padded to the algorithm's key length.
    pub fn derive_material(algorithm: u32, digest: &[u8]) -> Option<Vec<u8>> {
        let key_length = Self::key_length(algorithm)?;
        let mut material = vec![0u8; key_length];
        let copy = digest.len().min(key_length);
        material[..copy].copy_from_slice(&digest[..copy]);
        Some(material)
    }

    /// Create a key state from raw key material.
    pub fn from_material(algorithm: u32, key: Vec<u8>) -> Option<Self> {
        let block_size = match algorithm {
            CALG_RC4 => 0,
            CALG_RC2 | CALG_3DES | CALG_DES => 8,
            CALG_AES_128 | CALG_AES_256 => 16,
            _ => return None,
        };
        Some(Self {
            algorithm,
            key,
            iv: [0u8; 8],
            block_size,
        })
    }

    /// The PKCS#7-style padding size for a plaintext length under
    /// `block_size` (the documented CryptEncrypt padding contract: the
    /// ciphertext is a multiple of the block size).
    fn padding_len(plain_len: usize, block_size: usize) -> usize {
        let remainder = plain_len % block_size;
        if remainder == 0 {
            block_size
        } else {
            block_size - remainder
        }
    }

    /// Encrypt `data` in place semantics: returns the padded ciphertext
    /// and updates the chaining state.
    pub fn encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        match self.algorithm {
            CALG_RC4 => Some(crate::crypto::rc4(&self.key, data)),
            CALG_RC2 => {
                let padded = pkcs7_pad(data, 8);
                let ciphertext = crate::crypto::rc2_cbc(
                    &self.key,
                    (self.key.len() * 8) as u32,
                    &self.iv,
                    &padded,
                    true,
                );
                self.iv.copy_from_slice(&ciphertext[ciphertext.len() - 8..]);
                Some(ciphertext)
            }
            CALG_3DES | CALG_DES => {
                let padded = pkcs7_pad(data, 8);
                let ciphertext = if self.algorithm == CALG_3DES {
                    crate::crypto::triple_des_cbc(&self.key, &self.iv, &padded, true)
                } else {
                    crate::crypto::des_cbc_public(&self.key, &self.iv, &padded, true)
                };
                self.iv.copy_from_slice(&ciphertext[ciphertext.len() - 8..]);
                Some(ciphertext)
            }
            CALG_AES_128 | CALG_AES_256 => {
                let padded = pkcs7_pad(data, 16);
                let ciphertext = aes_cbc(&self.key, &self.iv, &padded, true)?;
                self.iv.copy_from_slice(&ciphertext[ciphertext.len() - 8..]);
                Some(ciphertext)
            }
            _ => None,
        }
    }

    /// Decrypt `data` (a full-block ciphertext) and strip the padding.
    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        match self.algorithm {
            CALG_RC4 => Some(crate::crypto::rc4(&self.key, data)),
            CALG_RC2 => {
                if !data.len().is_multiple_of(8) || data.is_empty() {
                    return None;
                }
                let plain = crate::crypto::rc2_cbc(
                    &self.key,
                    (self.key.len() * 8) as u32,
                    &self.iv,
                    data,
                    false,
                );
                self.iv.copy_from_slice(&data[data.len() - 8..]);
                pkcs7_unpad(&plain, 8)
            }
            CALG_3DES | CALG_DES => {
                if !data.len().is_multiple_of(8) || data.is_empty() {
                    return None;
                }
                let plain = if self.algorithm == CALG_3DES {
                    crate::crypto::triple_des_cbc(&self.key, &self.iv, data, false)
                } else {
                    crate::crypto::des_cbc_public(&self.key, &self.iv, data, false)
                };
                self.iv.copy_from_slice(&data[data.len() - 8..]);
                pkcs7_unpad(&plain, 8)
            }
            CALG_AES_128 | CALG_AES_256 => {
                if !data.len().is_multiple_of(16) || data.is_empty() {
                    return None;
                }
                let plain = aes_cbc(&self.key, &self.iv, data, false)?;
                self.iv.copy_from_slice(&data[data.len() - 8..]);
                pkcs7_unpad(&plain, 16)
            }
            _ => None,
        }
    }
}

/// PKCS#7 padding (the documented CryptEncrypt padding scheme: pad
/// bytes all equal the pad count).
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad = CryptKeyState::padding_len(data.len(), block_size);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

/// Strip PKCS#7 padding; returns `None` when the padding byte is
/// invalid for the block size.
fn pkcs7_unpad(data: &[u8], block_size: usize) -> Option<Vec<u8>> {
    let pad = *data.last()? as usize;
    if pad == 0 || pad > block_size || pad > data.len() {
        return None;
    }
    if data[data.len() - pad..]
        .iter()
        .any(|byte| *byte != pad as u8)
    {
        return None;
    }
    Some(data[..data.len() - pad].to_vec())
}

/// AES-CBC through the shared `aes`/`cbc` machinery (16-byte blocks).
fn aes_cbc(key: &[u8], iv: &[u8; 8], data: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    type Aes128Cbc = cbc::Encryptor<aes::Aes128>;
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    type Aes256Cbc = cbc::Encryptor<aes::Aes256>;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    let mut iv_full = [0u8; 16];
    iv_full[..8].copy_from_slice(iv);
    let result = match key.len() {
        16 if encrypt => Aes128Cbc::new_from_slices(key, &iv_full)
            .ok()?
            .encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(data),
        16 => Aes128CbcDec::new_from_slices(key, &iv_full)
            .ok()?
            .decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(data)
            .ok()?,
        32 if encrypt => Aes256Cbc::new_from_slices(key, &iv_full)
            .ok()?
            .encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(data),
        32 => Aes256CbcDec::new_from_slices(key, &iv_full)
            .ok()?
            .decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(data)
            .ok()?,
        _ => return None,
    };
    Some(result)
}

/// The standard registry view for SCM operations under the guest
/// (32-bit) process.
pub fn scm_registry_view() -> RegistryView {
    RegistryView::Native
}

/// Read the stored registry values of a service as `StoredRegistryValue`
/// map (for RegQueryInfoKey-style introspection in tests).
pub fn service_registry_values(
    ge: &GameEnvironment,
    name: &str,
    view: RegistryView,
) -> Vec<(String, StoredRegistryValue)> {
    ge.registry_enum_values("HKLM", &scm_service_key(name), view)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value_name| {
            ge.registry_get_value("HKLM", &scm_service_key(name), &value_name, view)
                .ok()
                .flatten()
                .map(|stored| (value_name, stored))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_encode_decode_round_trip() {
        let sid = encode_sid("S-1-5-21-3654781254-1934577812-2019068222-1001").unwrap();
        assert_eq!(sid[0], 1); // revision
        assert_eq!(sid[1], 5); // 5 subauthorities (21 + domain + RID)
        assert_eq!(
            decode_sid(&sid).unwrap(),
            "S-1-5-21-3654781254-1934577812-2019068222-1001"
        );
        let well_known = encode_sid("S-1-5-32-544").unwrap();
        assert_eq!(decode_sid(&well_known).unwrap(), "S-1-5-32-544");
        assert_eq!(encode_sid("S-1-5"), None); // no subauthorities
        assert_eq!(encode_sid("not-a-sid"), None);
    }

    #[test]
    fn privilege_lookup_matches_documented_luids() {
        assert_eq!(lookup_privilege_luid("SeDebugPrivilege"), Some(20));
        assert_eq!(lookup_privilege_luid("SeChangeNotifyPrivilege"), Some(23));
        assert_eq!(lookup_privilege_luid("SeImpersonatePrivilege"), Some(29));
        assert_eq!(lookup_privilege_luid("sebackupprivilege"), Some(17));
        assert_eq!(lookup_privilege_luid("SeNoSuchPrivilege"), None);
    }

    #[test]
    fn token_privilege_state_transitions() {
        let mut token = TokenInfo::process_token();
        assert!(token.privilege_enabled(23)); // SeChangeNotifyPrivilege on
        assert!(!token.privilege_enabled(19)); // SeShutdownPrivilege off
        assert!(token.set_privilege_state(19, true));
        assert!(token.privilege_enabled(19));
        assert!(!token.set_privilege_state(999, true));
    }

    #[test]
    fn token_contains_guest_user_and_groups() {
        let token = TokenInfo::process_token();
        assert!(token.contains_sid(&guest_user_sid()));
        assert!(token.contains_sid(&encode_sid("S-1-1-0").unwrap()));
        assert!(!token.contains_sid(&encode_sid("S-1-5-18").unwrap()));
    }

    #[test]
    fn scm_status_flow_start_stop() {
        let mut status = ServiceStatusFlow::new(SERVICE_ACCEPT_DEFAULT);
        assert_eq!(status.state, SERVICE_STOPPED);
        assert_eq!(status.start(), ERROR_SUCCESS);
        assert_eq!(status.state, SERVICE_START_PENDING);
        assert_eq!(status.start(), ERROR_SERVICE_ALREADY_RUNNING);
        status.settle();
        assert_eq!(status.state, SERVICE_RUNNING);
        assert_eq!(status.apply_control(SERVICE_CONTROL_STOP), ERROR_SUCCESS);
        assert_eq!(status.state, SERVICE_STOP_PENDING);
        status.settle();
        assert_eq!(status.state, SERVICE_STOPPED);
        assert_eq!(
            status.apply_control(SERVICE_CONTROL_STOP),
            ERROR_SERVICE_NOT_ACTIVE
        );
    }

    #[test]
    fn scm_pause_continue_interrogate() {
        let mut status = ServiceStatusFlow::new(SERVICE_ACCEPT_DEFAULT);
        status.start();
        status.settle();
        assert_eq!(
            status.apply_control(SERVICE_CONTROL_INTERROGATE),
            ERROR_SUCCESS
        );
        assert_eq!(status.apply_control(SERVICE_CONTROL_PAUSE), ERROR_SUCCESS);
        status.settle();
        assert_eq!(status.state, SERVICE_PAUSED);
        assert_eq!(
            status.apply_control(SERVICE_CONTROL_CONTINUE),
            ERROR_SUCCESS
        );
        status.settle();
        assert_eq!(status.state, SERVICE_RUNNING);
        assert_eq!(status.apply_control(99), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn crypt_hash_digests_match_shared_machinery() {
        let mut md5_hash = CryptHashState {
            algorithm: CALG_MD5,
            data: Vec::new(),
        };
        md5_hash.data.extend_from_slice(b"abc");
        assert_eq!(
            md5_hash.finish().unwrap(),
            crate::crypto::md5(b"abc").to_vec()
        );
        let mut sha1_hash = CryptHashState {
            algorithm: CALG_SHA1,
            data: Vec::new(),
        };
        sha1_hash.data.extend_from_slice(b"abc");
        assert_eq!(
            sha1_hash.finish().unwrap(),
            crate::crypto::sha1(b"abc").to_vec()
        );
        assert_eq!(CryptHashState::digest_size(CALG_SHA_256), Some(32));
        assert_eq!(CryptHashState::digest_size(CALG_RC4), None);
    }

    #[test]
    fn crypt_key_encrypt_decrypt_round_trips() {
        // RC4: stream, no padding.
        let mut rc4_key = CryptKeyState::from_material(CALG_RC4, vec![1, 2, 3, 4, 5]).unwrap();
        let plain = b"stream cipher data".to_vec();
        let cipher = rc4_key.encrypt(&plain).unwrap();
        assert_eq!(cipher.len(), plain.len());
        let mut dec_key = CryptKeyState::from_material(CALG_RC4, vec![1, 2, 3, 4, 5]).unwrap();
        assert_eq!(dec_key.decrypt(&cipher).unwrap(), plain);

        // RC2: block, PKCS#7 padded to a multiple of 8.
        let mut rc2_key = CryptKeyState::from_material(CALG_RC2, vec![9; 8]).unwrap();
        let plain = b"rc2 secret".to_vec(); // 9 bytes → 16 ciphertext
        let cipher = rc2_key.encrypt(&plain).unwrap();
        assert_eq!(cipher.len() % 8, 0);
        let mut rc2_dec = CryptKeyState::from_material(CALG_RC2, vec![9; 8]).unwrap();
        assert_eq!(rc2_dec.decrypt(&cipher).unwrap(), plain);

        // 3DES: EDE with the documented 24-byte key.
        let mut tdes_key = CryptKeyState::from_material(CALG_3DES, vec![7; 24]).unwrap();
        let cipher = tdes_key.encrypt(&plain).unwrap();
        let mut tdes_dec = CryptKeyState::from_material(CALG_3DES, vec![7; 24]).unwrap();
        assert_eq!(tdes_dec.decrypt(&cipher).unwrap(), plain);

        // AES-128: 16-byte blocks.
        let mut aes_key = CryptKeyState::from_material(CALG_AES_128, vec![3; 16]).unwrap();
        let cipher = aes_key.encrypt(&plain).unwrap();
        assert_eq!(cipher.len() % 16, 0);
        let mut aes_dec = CryptKeyState::from_material(CALG_AES_128, vec![3; 16]).unwrap();
        assert_eq!(aes_dec.decrypt(&cipher).unwrap(), plain);
    }

    #[test]
    fn crypt_key_derive_material_contract() {
        let digest = crate::crypto::sha1(b"derivation input").to_vec();
        let rc4_material = CryptKeyState::derive_material(CALG_RC4, &digest).unwrap();
        assert_eq!(rc4_material.len(), 16);
        assert_eq!(rc4_material, &digest[..16]);
        let tdes_material = CryptKeyState::derive_material(CALG_3DES, &digest).unwrap();
        assert_eq!(tdes_material.len(), 24);
        assert_eq!(&tdes_material[..20], &digest[..]);
        assert_eq!(CryptKeyState::derive_material(CALG_MD5, &digest), None);
    }
}
