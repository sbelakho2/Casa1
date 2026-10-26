//! TPM 2.0 wire constants used by the software TPM and its TBS adapter.
//!
//! Values are taken from the TPM 2.0 Library Specification (Parts 1-3).  The
//! error-code helpers encode the format-one `TPM_RC` layout
//! (`base | R | index << 8`) so every rejection carries the same code a
//! hardware TPM would return.

// ---------------------------------------------------------------------------
// Structure tags
// ---------------------------------------------------------------------------

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_ST_CREATION: u16 = 0x8021;
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

// ---------------------------------------------------------------------------
// Command codes
// ---------------------------------------------------------------------------

pub const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
pub const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
pub const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
pub const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
pub const TPM_CC_NV_WRITE_LOCK: u32 = 0x0000_0138;
pub const TPM_CC_SELF_TEST: u32 = 0x0000_0143;
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub const TPM_CC_STIR_RANDOM: u32 = 0x0000_0146;
pub const TPM_CC_NV_READ: u32 = 0x0000_014E;
pub const TPM_CC_NV_READ_LOCK: u32 = 0x0000_014F;
pub const TPM_CC_CREATE: u32 = 0x0000_0153;
pub const TPM_CC_LOAD: u32 = 0x0000_0157;
pub const TPM_CC_QUOTE: u32 = 0x0000_0158;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
pub const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

pub const TPM_RH_OWNER: u32 = 0x4000_0001;
pub const TPM_RH_NULL: u32 = 0x4000_0007;
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const TPM_RH_LOCKOUT: u32 = 0x4000_000A;
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
pub const TPM_RH_PLATFORM: u32 = 0x4000_000C;

pub const TPM_HT_PCR: u8 = 0x00;
pub const TPM_HT_NV_INDEX: u8 = 0x01;
pub const TPM_HT_HMAC_SESSION: u8 = 0x02;
pub const TPM_HT_LOADED_SESSION: u8 = 0x02;
pub const TPM_HT_PERMANENT: u8 = 0x40;
pub const TPM_HT_TRANSIENT: u8 = 0x80;
pub const TPM_HT_PERSISTENT: u8 = 0x81;

pub const TRANSIENT_HANDLE_BASE: u32 = 0x8000_0000;
pub const TRANSIENT_HANDLE_LAST: u32 = 0x80FF_FFFF;
pub const SESSION_HANDLE_BASE: u32 = 0x0200_0000;
pub const SESSION_HANDLE_LAST: u32 = SESSION_HANDLE_BASE + 0x00FF_FFFF;
pub const NV_INDEX_BASE: u32 = 0x0100_0000;
pub const NV_INDEX_LAST: u32 = 0x01FF_FFFF;

pub fn is_transient_handle(handle: u32) -> bool {
    (TRANSIENT_HANDLE_BASE..=TRANSIENT_HANDLE_LAST).contains(&handle)
}

pub fn is_session_handle(handle: u32) -> bool {
    (SESSION_HANDLE_BASE..=SESSION_HANDLE_LAST).contains(&handle)
}

pub fn is_nv_index(handle: u32) -> bool {
    (NV_INDEX_BASE..=NV_INDEX_LAST).contains(&handle)
}

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

pub const TPM_ALG_ERROR: u16 = 0x0000;
pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_HMAC: u16 = 0x0005;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM_ALG_XOR: u16 = 0x000A;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_SHA384: u16 = 0x000C;
pub const TPM_ALG_SHA512: u16 = 0x000D;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_RSASSA: u16 = 0x0014;
pub const TPM_ALG_RSAPSS: u16 = 0x0016;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECDH: u16 = 0x0025;
pub const TPM_ALG_ECC: u16 = 0x0023;

pub const TPM_ECC_NIST_P256: u16 = 0x0003;

// ---------------------------------------------------------------------------
// Object / NV attributes
// ---------------------------------------------------------------------------

pub const TPMA_OBJECT_FIXED_TPM: u32 = 1 << 1;
pub const TPMA_OBJECT_FIXED_PARENT: u32 = 1 << 4;
pub const TPMA_OBJECT_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const TPMA_OBJECT_USER_WITH_AUTH: u32 = 1 << 6;
pub const TPMA_OBJECT_NO_DA: u32 = 1 << 10;
pub const TPMA_OBJECT_RESTRICTED: u32 = 1 << 16;
pub const TPMA_OBJECT_DECRYPT: u32 = 1 << 17;
pub const TPMA_OBJECT_SIGN: u32 = 1 << 18;

pub const TPMA_NV_PPWRITE: u32 = 1 << 0;
pub const TPMA_NV_OWNERWRITE: u32 = 1 << 1;
pub const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
pub const TPMA_NV_POLICYWRITE: u32 = 1 << 3;
pub const TPMA_NV_PPREAD: u32 = 1 << 16;
pub const TPMA_NV_OWNERREAD: u32 = 1 << 17;
pub const TPMA_NV_AUTHREAD: u32 = 1 << 18;
pub const TPMA_NV_POLICYREAD: u32 = 1 << 19;
pub const TPMA_NV_NO_DA: u32 = 1 << 25;
pub const TPMA_NV_ORDERLY: u32 = 1 << 26;
pub const TPMA_NV_READLOCKED: u32 = 1 << 28;
pub const TPMA_NV_WRITTEN: u32 = 1 << 29;
pub const TPMA_NV_PLATFORMCREATE: u32 = 1 << 30;
pub const TPMA_NV_READ_STCLEAR: u32 = 1 << 31;

pub const TPMA_NV_WRITELOCKED: u32 = 1 << 11;

// ---------------------------------------------------------------------------
// Startup / shutdown / self-test parameters
// ---------------------------------------------------------------------------

pub const TPM_SU_CLEAR: u16 = 0x0000;
pub const TPM_SU_STATE: u16 = 0x0001;

pub const TPM_SE_HMAC: u8 = 0x00;
pub const TPM_SE_POLICY: u8 = 0x01;

// ---------------------------------------------------------------------------
// Capabilities and properties
// ---------------------------------------------------------------------------

pub const TPM_CAP_ALGS: u32 = 0x0000_0000;
pub const TPM_CAP_HANDLES: u32 = 0x0000_0001;
pub const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
pub const TPM_CAP_PCRS: u32 = 0x0000_0005;
pub const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
pub const TPM_CAP_ECC_CURVES: u32 = 0x0000_0008;

pub const TPM_PT_FAMILY_INDICATOR: u32 = 0x0000_0100;
pub const TPM_PT_LEVEL: u32 = 0x0000_0101;
pub const TPM_PT_REVISION: u32 = 0x0000_0102;
pub const TPM_PT_DAY_OF_YEAR: u32 = 0x0000_0103;
pub const TPM_PT_YEAR: u32 = 0x0000_0104;
pub const TPM_PT_MANUFACTURER: u32 = 0x0000_0105;
pub const TPM_PT_VENDOR_STRING_1: u32 = 0x0000_0106;
pub const TPM_PT_VENDOR_STRING_2: u32 = 0x0000_0107;
pub const TPM_PT_VENDOR_STRING_3: u32 = 0x0000_0108;
pub const TPM_PT_VENDOR_STRING_4: u32 = 0x0000_0109;
pub const TPM_PT_VENDOR_TPM_TYPE: u32 = 0x0000_010A;
pub const TPM_PT_FIRMWARE_VERSION_1: u32 = 0x0000_010B;
pub const TPM_PT_FIRMWARE_VERSION_2: u32 = 0x0000_010C;
pub const TPM_PT_INPUT_BUFFER: u32 = 0x0000_010D;
pub const TPM_PT_HR_TRANSIENT_MIN: u32 = 0x0000_010E;
pub const TPM_PT_HR_PERSISTENT_MIN: u32 = 0x0000_010F;
pub const TPM_PT_HR_LOADED_MIN: u32 = 0x0000_0110;
pub const TPM_PT_ACTIVE_SESSIONS_MAX: u32 = 0x0000_0111;
pub const TPM_PT_PCR_COUNT: u32 = 0x0000_0112;
pub const TPM_PT_PCR_SELECT_MIN: u32 = 0x0000_0113;
pub const TPM_PT_CONTEXT_GAP_MAX: u32 = 0x0000_0114;
pub const TPM_PT_NV_COUNTERS_MAX: u32 = 0x0000_0116;
pub const TPM_PT_NV_INDEX_MAX: u32 = 0x0000_0117;
pub const TPM_PT_MEMORY: u32 = 0x0000_0118;
pub const TPM_PT_CLOCK_UPDATE: u32 = 0x0000_0119;
pub const TPM_PT_CONTEXT_HASH: u32 = 0x0000_011A;
pub const TPM_PT_CONTEXT_SYM: u32 = 0x0000_011B;
pub const TPM_PT_CONTEXT_SYM_SIZE: u32 = 0x0000_011C;
pub const TPM_PT_ORDERLY_COUNT: u32 = 0x0000_011D;
pub const TPM_PT_MAX_COMMAND_SIZE: u32 = 0x0000_011E;
pub const TPM_PT_MAX_RESPONSE_SIZE: u32 = 0x0000_011F;
pub const TPM_PT_MAX_DIGEST: u32 = 0x0000_0120;
pub const TPM_PT_MAX_OBJECT_CONTEXT: u32 = 0x0000_0121;
pub const TPM_PT_MAX_SESSION_CONTEXT: u32 = 0x0000_0122;
pub const TPM_PT_PS_FAMILY_INDICATOR: u32 = 0x0000_0123;
pub const TPM_PT_PS_LEVEL: u32 = 0x0000_0124;
pub const TPM_PT_PS_REVISION: u32 = 0x0000_0125;
pub const TPM_PT_PS_DAY_OF_YEAR: u32 = 0x0000_0126;
pub const TPM_PT_PS_YEAR: u32 = 0x0000_0127;
pub const TPM_PT_SPLIT_MAX: u32 = 0x0000_0128;
pub const TPM_PT_TOTAL_COMMANDS: u32 = 0x0000_0129;
pub const TPM_PT_LIBRARY_COMMANDS: u32 = 0x0000_012A;
pub const TPM_PT_VENDOR_COMMANDS: u32 = 0x0000_012B;
pub const TPM_PT_NV_BUFFER_MAX: u32 = 0x0000_012C;
pub const TPM_PT_MODES: u32 = 0x0000_012D;
pub const TPM_PT_MAX_CAP_BUFFER: u32 = 0x0000_012E;

// ---------------------------------------------------------------------------
// TPM_RC error codes
// ---------------------------------------------------------------------------

pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;
pub const TPM_RC_INITIALIZE: u32 = 0x0000_0100;
pub const TPM_RC_FAILURE: u32 = 0x0000_0101;
pub const TPM_RC_SEQUENCE: u32 = 0x0000_0103;
pub const TPM_RC_DISABLED: u32 = 0x0000_0120;
pub const TPM_RC_AUTH_MISSING: u32 = 0x0000_0125;
pub const TPM_RC_COMMAND_SIZE: u32 = 0x0000_0142;
pub const TPM_RC_COMMAND_CODE: u32 = 0x0000_0143;
pub const TPM_RC_AUTHSIZE: u32 = 0x0000_0144;
pub const TPM_RC_NV_RANGE: u32 = 0x0000_0146;
pub const TPM_RC_NV_SIZE: u32 = 0x0000_0147;
pub const TPM_RC_NV_LOCKED: u32 = 0x0000_0148;
pub const TPM_RC_NV_AUTHORIZATION: u32 = 0x0000_0149;
pub const TPM_RC_NV_UNINITIALIZED: u32 = 0x0000_014A;
pub const TPM_RC_NV_SPACE: u32 = 0x0000_014B;
pub const TPM_RC_NV_DEFINED: u32 = 0x0000_014C;

pub const TPM_RC_ASYMMETRIC: u32 = 0x0000_0081;
pub const TPM_RC_ATTRIBUTES: u32 = 0x0000_0082;
pub const TPM_RC_HASH: u32 = 0x0000_0083;
pub const TPM_RC_VALUE: u32 = 0x0000_0084;
pub const TPM_RC_HIERARCHY: u32 = 0x0000_0085;
pub const TPM_RC_KEY_SIZE: u32 = 0x0000_0087;
pub const TPM_RC_MGF: u32 = 0x0000_0088;
pub const TPM_RC_MODE: u32 = 0x0000_0089;
pub const TPM_RC_TYPE: u32 = 0x0000_008A;
pub const TPM_RC_HANDLE: u32 = 0x0000_008B;
pub const TPM_RC_KDF: u32 = 0x0000_008C;
pub const TPM_RC_RANGE: u32 = 0x0000_008D;
pub const TPM_RC_AUTH_FAIL: u32 = 0x0000_008E;
pub const TPM_RC_NONCE: u32 = 0x0000_008F;
pub const TPM_RC_PP: u32 = 0x0000_0090;
pub const TPM_RC_SCHEME: u32 = 0x0000_0092;
pub const TPM_RC_SIZE: u32 = 0x0000_0095;
pub const TPM_RC_SYMMETRIC: u32 = 0x0000_0096;
pub const TPM_RC_TAG: u32 = 0x0000_0097;
pub const TPM_RC_SELECTOR: u32 = 0x0000_0098;
pub const TPM_RC_INSUFFICIENT: u32 = 0x0000_009A;
pub const TPM_RC_SIGNATURE: u32 = 0x0000_009B;
pub const TPM_RC_KEY: u32 = 0x0000_009C;
pub const TPM_RC_POLICY_FAIL: u32 = 0x0000_009D;
pub const TPM_RC_INTEGRITY: u32 = 0x0000_009F;
pub const TPM_RC_TICKET: u32 = 0x0000_00A0;
pub const TPM_RC_RESERVED_BITS: u32 = 0x0000_00A1;
pub const TPM_RC_BAD_AUTH: u32 = 0x0000_00A2;
pub const TPM_RC_EXPIRED: u32 = 0x0000_00A3;
pub const TPM_RC_POLICY_CC: u32 = 0x0000_00A4;
pub const TPM_RC_BINDING: u32 = 0x0000_00A5;
pub const TPM_RC_CURVE: u32 = 0x0000_00A6;
pub const TPM_RC_ECC_POINT: u32 = 0x0000_00A7;

/// Format-one index offset for the first handle slot.
pub const TPM_RC_H: u32 = 0x0000_0000;
/// Format-one index offset for the first parameter slot.
pub const TPM_RC_P: u32 = 0x0000_0040;
/// Format-one index offset for the first session slot.
pub const TPM_RC_S: u32 = 0x0000_0800;
/// Format-one index selector 1.
pub const TPM_RC_1: u32 = 0x0000_0100;
/// Format-one index selector 2.
pub const TPM_RC_2: u32 = 0x0000_0200;
/// Format-one index selector 3.
pub const TPM_RC_3: u32 = 0x0000_0300;

/// Format-one error for handle slot `index` (1-based).
pub const fn rc_handle(base: u32, index: u32) -> u32 {
    base | TPM_RC_H | (index << 8)
}

/// Format-one error for parameter slot `index` (1-based).
pub const fn rc_parameter(base: u32, index: u32) -> u32 {
    base | TPM_RC_P | (index << 8)
}

/// Format-one error for session slot `index` (1-based).
pub const fn rc_session(base: u32, index: u32) -> u32 {
    base | TPM_RC_S | (index << 8)
}

/// Largest command the engine accepts (matching the advertised
/// `TPM_PT_MAX_COMMAND_SIZE` property).
pub const MAX_COMMAND_SIZE: usize = 4096;
/// Largest response the engine emits (matching `TPM_PT_MAX_RESPONSE_SIZE`).
pub const MAX_RESPONSE_SIZE: usize = 4096;
/// Number of SHA-256 PCRs in the software TPM.
pub const PCR_COUNT: usize = 24;
/// Bytes needed to select all 24 PCRs.
pub const PCR_SELECT_BYTES: usize = 3;
/// Largest digest the engine produces or accepts (SHA-512).
pub const MAX_DIGEST_SIZE: usize = 64;
/// Largest NV index payload.
pub const MAX_NV_SIZE: usize = 4096;
/// Maximum number of defined NV indices.
pub const MAX_NV_INDICES: usize = 64;
/// Maximum number of simultaneously defined transient objects.
pub const MAX_TRANSIENT_OBJECTS: usize = 32;
/// Maximum number of loaded authorization sessions.
pub const MAX_SESSIONS: usize = 32;
/// TPM generated magic value in `TPMS_ATTEST`.
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;
