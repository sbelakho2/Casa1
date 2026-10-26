//! TPM 2.0 command engine.
//!
//! The engine parses the wire format itself (including the session area) and
//! dispatches to handlers.  Every handler validates sizes, handles, and
//! authorization before it mutates state, and rejection codes are the TPM 2.0
//! format-zero/format-one codes from [`super::constants`].

use super::Tpm;
use super::constants::*;
use super::crypto::{
    derive_seed, ecc_from_seed, ecc_point, ecdsa_sign, kdfa, rsa_from_seed, rsa_modulus, rsa_sign,
    sha256,
};
use super::persist::PersistError;
use super::session;
use super::state::{
    AuthCommand, AuthTarget, Hierarchy, KeyMaterial, NvIndex, PublicArea, ResponseSession,
};
use super::wire::{Header, Reader, Writer, no_auth_response, session_response};

const CREATION_MAGIC: &[u8; 4] = b"CPK1";

#[cfg(test)]
thread_local! {
    pub(crate) static FORCE_SELF_TEST_FAILURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Internal command failure: a TPM error code and, when persistence failed, the
/// I/O cause that TBS must surface as `TBS_E_IOERROR`.
#[derive(Debug)]
pub(crate) struct CmdError {
    pub rc: u32,
    pub io: Option<PersistError>,
}

impl From<u32> for CmdError {
    fn from(rc: u32) -> Self {
        Self { rc, io: None }
    }
}

impl From<PersistError> for CmdError {
    fn from(error: PersistError) -> Self {
        Self {
            rc: TPM_RC_FAILURE,
            io: Some(error),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Outcome {
    pub handles: Vec<u32>,
    pub params: Vec<u8>,
}

struct ExecCtx<'a> {
    tpm: &'a mut Tpm,
    code: u32,
    handles: Vec<u32>,
    /// Parameter bytes followed by the optional authorization area.
    body: &'a [u8],
    has_sessions: bool,
    params_end: usize,
    sessions: Vec<AuthCommand>,
    locality: u8,
    response_sessions: Vec<ResponseSession>,
}

impl<'a> ExecCtx<'a> {
    fn authorize(&mut self, targets: &[AuthTarget]) -> Result<(), u32> {
        let params = &self.body[..self.params_end];
        let response = session::authorize(
            self.tpm,
            self.code,
            &self.handles,
            params,
            &self.sessions,
            targets,
        )?;
        self.response_sessions = response;
        Ok(())
    }

    /// Finish parameter parsing and split off the authorization area.
    fn complete_params(&mut self, reader: &mut Reader<'a>) -> Result<(), u32> {
        if self.has_sessions {
            self.params_end = reader.position();
            let rest = &self.body[self.params_end..];
            self.sessions = parse_auth_area(rest)?;
        } else {
            reader.finish()?;
            self.params_end = self.body.len();
            self.sessions.clear();
        }
        Ok(())
    }

    fn reject_sessions(&self) -> Result<(), u32> {
        if self.sessions.is_empty() {
            Ok(())
        } else {
            Err(TPM_RC_AUTHSIZE)
        }
    }

    fn persist(&self) -> Result<(), CmdError> {
        self.tpm.persist().map_err(CmdError::from)
    }

    fn reader(&self) -> Reader<'a> {
        Reader::new(self.body)
    }
}

fn handle_count(code: u32) -> usize {
    match code {
        TPM_CC_NV_WRITE
        | TPM_CC_NV_READ
        | TPM_CC_NV_WRITE_LOCK
        | TPM_CC_NV_READ_LOCK
        | TPM_CC_NV_UNDEFINE_SPACE
        | TPM_CC_START_AUTH_SESSION => 2,
        TPM_CC_CREATE_PRIMARY
        | TPM_CC_CREATE
        | TPM_CC_LOAD
        | TPM_CC_READ_PUBLIC
        | TPM_CC_QUOTE
        | TPM_CC_PCR_EXTEND
        | TPM_CC_NV_DEFINE_SPACE
        | TPM_CC_HIERARCHY_CHANGE_AUTH
        | TPM_CC_NV_READ_PUBLIC => 1,
        _ => 0,
    }
}

fn contains_code(code: u32) -> bool {
    matches!(
        code,
        TPM_CC_NV_UNDEFINE_SPACE
            | TPM_CC_HIERARCHY_CHANGE_AUTH
            | TPM_CC_NV_DEFINE_SPACE
            | TPM_CC_CREATE_PRIMARY
            | TPM_CC_NV_WRITE
            | TPM_CC_NV_WRITE_LOCK
            | TPM_CC_SELF_TEST
            | TPM_CC_STARTUP
            | TPM_CC_SHUTDOWN
            | TPM_CC_STIR_RANDOM
            | TPM_CC_NV_READ
            | TPM_CC_NV_READ_LOCK
            | TPM_CC_CREATE
            | TPM_CC_LOAD
            | TPM_CC_QUOTE
            | TPM_CC_FLUSH_CONTEXT
            | TPM_CC_NV_READ_PUBLIC
            | TPM_CC_READ_PUBLIC
            | TPM_CC_START_AUTH_SESSION
            | TPM_CC_GET_CAPABILITY
            | TPM_CC_GET_RANDOM
            | TPM_CC_PCR_READ
            | TPM_CC_PCR_EXTEND
    )
}

/// Execute one TPM command and return the full response buffer.
pub(crate) fn execute(
    tpm: &mut Tpm,
    command: &[u8],
    locality: u8,
) -> Result<Vec<u8>, PersistError> {
    let header = match Header::parse(command) {
        Ok(header) => header,
        Err(rc) => return Ok(no_auth_response(TPM_ST_NO_SESSIONS, rc, &[])),
    };
    if header.tag != TPM_ST_NO_SESSIONS && header.tag != TPM_ST_SESSIONS {
        return Ok(no_auth_response(TPM_ST_NO_SESSIONS, TPM_RC_TAG, &[]));
    }
    if header.code != TPM_CC_STARTUP && !tpm.started && contains_code(header.code) {
        return Ok(no_auth_response(TPM_ST_NO_SESSIONS, TPM_RC_INITIALIZE, &[]));
    }
    tpm.state.clock = tpm.state.clock.wrapping_add(1);
    let body = &command[10..];
    let count = handle_count(header.code);
    let mut handles = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let Some(slice) = body.get(offset..offset + 4) else {
            return Ok(no_auth_response(TPM_ST_NO_SESSIONS, TPM_RC_SIZE, &[]));
        };
        handles.push(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
        offset += 4;
    }
    let mut ctx = ExecCtx {
        tpm,
        code: header.code,
        handles,
        body: &body[offset..],
        has_sessions: header.tag == TPM_ST_SESSIONS,
        params_end: 0,
        sessions: Vec::new(),
        locality,
        response_sessions: Vec::new(),
    };
    let outcome = match dispatch(&mut ctx) {
        Ok(outcome) => outcome,
        Err(error) => {
            if let Some(io) = error.io {
                return Err(io);
            }
            return Ok(no_auth_response(TPM_ST_NO_SESSIONS, error.rc, &[]));
        }
    };
    let mut body = Vec::new();
    for handle in &outcome.handles {
        body.extend_from_slice(&handle.to_be_bytes());
    }
    if header.tag == TPM_ST_SESSIONS {
        let auth =
            session::response_auth_area(header.code, 0, &outcome.params, &ctx.response_sessions);
        return Ok(session_response(
            0,
            &outcome.handles,
            &outcome.params,
            &auth,
        ));
    }
    body.extend_from_slice(&outcome.params);
    Ok(no_auth_response(TPM_ST_NO_SESSIONS, 0, &body))
}

fn parse_auth_area(rest: &[u8]) -> Result<Vec<AuthCommand>, u32> {
    if rest.len() < 4 {
        return Err(TPM_RC_AUTHSIZE);
    }
    let auth_size = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if auth_size != rest.len() - 4 || auth_size < 4 {
        return Err(TPM_RC_AUTHSIZE);
    }
    let mut reader = Reader::with_empty_code(&rest[4..], TPM_RC_AUTHSIZE);
    let count = reader.u32()? as usize;
    if count > MAX_SESSIONS {
        return Err(TPM_RC_AUTHSIZE);
    }
    let mut sessions = Vec::with_capacity(count);
    for _ in 0..count {
        let handle = reader.u32()?;
        let nonce = reader.tpm2b(64)?.to_vec();
        let attributes = reader.u8()?;
        let hmac = reader.tpm2b(64)?.to_vec();
        sessions.push(AuthCommand {
            handle,
            nonce,
            attributes,
            hmac,
        });
    }
    reader.finish()?;
    Ok(sessions)
}

fn dispatch(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    match ctx.code {
        TPM_CC_STARTUP => cmd_startup(ctx),
        TPM_CC_SHUTDOWN => cmd_shutdown(ctx),
        TPM_CC_SELF_TEST => cmd_self_test(ctx),
        TPM_CC_STIR_RANDOM => cmd_stir_random(ctx),
        TPM_CC_GET_RANDOM => cmd_get_random(ctx),
        TPM_CC_GET_CAPABILITY => cmd_get_capability(ctx),
        TPM_CC_PCR_EXTEND => cmd_pcr_extend(ctx),
        TPM_CC_PCR_READ => cmd_pcr_read(ctx),
        TPM_CC_CREATE_PRIMARY => cmd_create_primary(ctx),
        TPM_CC_CREATE => cmd_create(ctx),
        TPM_CC_LOAD => cmd_load(ctx),
        TPM_CC_FLUSH_CONTEXT => cmd_flush_context(ctx),
        TPM_CC_READ_PUBLIC => cmd_read_public(ctx),
        TPM_CC_QUOTE => cmd_quote(ctx),
        TPM_CC_HIERARCHY_CHANGE_AUTH => cmd_hierarchy_change_auth(ctx),
        TPM_CC_NV_DEFINE_SPACE => cmd_nv_define_space(ctx),
        TPM_CC_NV_WRITE => cmd_nv_write(ctx),
        TPM_CC_NV_READ => cmd_nv_read(ctx),
        TPM_CC_NV_WRITE_LOCK => cmd_nv_write_lock(ctx),
        TPM_CC_NV_READ_LOCK => cmd_nv_read_lock(ctx),
        TPM_CC_NV_READ_PUBLIC => cmd_nv_read_public(ctx),
        TPM_CC_NV_UNDEFINE_SPACE => cmd_nv_undefine_space(ctx),
        TPM_CC_START_AUTH_SESSION => cmd_start_auth_session(ctx),
        _ => Err(TPM_RC_COMMAND_CODE.into()),
    }
}

fn empty_outcome() -> Outcome {
    Outcome {
        handles: Vec::new(),
        params: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Startup / shutdown / self-test / randomness
// ---------------------------------------------------------------------------

fn cmd_startup(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let startup_type = reader.u16()?;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    if startup_type != TPM_SU_CLEAR && startup_type != TPM_SU_STATE {
        return Err(rc_parameter(TPM_RC_VALUE, 1).into());
    }
    if ctx.tpm.started {
        return Err(TPM_RC_INITIALIZE.into());
    }
    if startup_type == TPM_SU_CLEAR {
        ctx.tpm.state.pcrs.fill([0u8; 32]);
        ctx.tpm.state.pcr_update_counter = 0;
        ctx.tpm.state.reset_count = ctx.tpm.state.reset_count.wrapping_add(1);
        ctx.tpm.state.restart_count = 1;
        ctx.tpm.state.clock = 0;
    }
    ctx.tpm.objects.clear();
    ctx.tpm.sessions.clear();
    ctx.tpm.started = true;
    ctx.persist()?;
    Ok(empty_outcome())
}

fn cmd_shutdown(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let shutdown_type = reader.u16()?;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    if shutdown_type != TPM_SU_CLEAR && shutdown_type != TPM_SU_STATE {
        return Err(rc_parameter(TPM_RC_VALUE, 1).into());
    }
    if shutdown_type == TPM_SU_CLEAR {
        ctx.tpm.objects.clear();
        ctx.tpm.sessions.clear();
    }
    ctx.tpm.started = false;
    ctx.persist()?;
    Ok(empty_outcome())
}

/// Known-answer self-test for the primitives this TPM exposes.  Runs the
/// SHA-256, HMAC-SHA-256, and ECDSA P-256 paths that production commands use.
#[cfg(test)]
fn forced_self_test_failure() -> bool {
    FORCE_SELF_TEST_FAILURE.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn forced_self_test_failure() -> bool {
    false
}

fn self_test() -> bool {
    const SHA256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    const HMAC_RFC4231: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    let secret = ecc_from_seed(&[0x42; 32]);
    let (r, s) = ecdsa_sign(&secret, b"casa1-tpm-selftest");
    let mut raw = Vec::with_capacity(64);
    raw.extend_from_slice(&r);
    raw.extend_from_slice(&s);
    let signature = p256::ecdsa::Signature::from_slice(&raw).expect("ecdsa signature shape");
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = secret.public_key().to_encoded_point(false);
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes())
        .expect("p256 verification key");
    use p256::ecdsa::signature::Verifier;
    let verified = verifying.verify(b"casa1-tpm-selftest", &signature).is_ok();
    !forced_self_test_failure()
        && sha256(b"abc") == SHA256_ABC
        && super::crypto::hmac_sha256(&[0x0b; 20], b"Hi There") == HMAC_RFC4231
        && verified
}

fn cmd_self_test(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let full_test = reader.u8()?;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    if full_test > 1 {
        return Err(rc_parameter(TPM_RC_VALUE, 1).into());
    }
    if !self_test() {
        return Err(TPM_RC_FAILURE.into());
    }
    Ok(empty_outcome())
}

fn cmd_stir_random(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let data = reader.tpm2b(128)?.to_vec();
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    ctx.tpm.state.drbg.stir(&data);
    ctx.persist()?;
    Ok(empty_outcome())
}

fn cmd_get_random(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let requested = reader.u16()? as usize;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    if requested > MAX_DIGEST_SIZE {
        return Err(rc_parameter(TPM_RC_VALUE, 1).into());
    }
    let bytes = ctx.tpm.random_bytes(requested);
    let mut writer = Writer::new();
    writer.tpm2b(&bytes);
    ctx.persist()?;
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

// ---------------------------------------------------------------------------
// GetCapability
// ---------------------------------------------------------------------------

fn properties(_tpm: &Tpm) -> Vec<(u32, u32)> {
    vec![
        (TPM_PT_FAMILY_INDICATOR, 0x322E_3000),
        (TPM_PT_LEVEL, 0),
        (TPM_PT_REVISION, 138),
        (TPM_PT_DAY_OF_YEAR, 298),
        (TPM_PT_YEAR, 2026),
        (TPM_PT_MANUFACTURER, 0x4341_5341),
        (TPM_PT_VENDOR_STRING_1, 0x4361_7361),
        (TPM_PT_VENDOR_STRING_2, 0x3120_5450),
        (TPM_PT_VENDOR_STRING_3, 0x4D20_7632),
        (TPM_PT_VENDOR_STRING_4, 0x2E30_0000),
        (TPM_PT_VENDOR_TPM_TYPE, 1),
        (TPM_PT_FIRMWARE_VERSION_1, 0x0001_0000),
        (TPM_PT_FIRMWARE_VERSION_2, 0),
        (TPM_PT_INPUT_BUFFER, MAX_COMMAND_SIZE as u32),
        (TPM_PT_HR_TRANSIENT_MIN, 3),
        (TPM_PT_HR_PERSISTENT_MIN, 1),
        (TPM_PT_HR_LOADED_MIN, 3),
        (TPM_PT_ACTIVE_SESSIONS_MAX, MAX_SESSIONS as u32),
        (TPM_PT_PCR_COUNT, PCR_COUNT as u32),
        (TPM_PT_PCR_SELECT_MIN, PCR_SELECT_BYTES as u32),
        (TPM_PT_CONTEXT_GAP_MAX, 0),
        (TPM_PT_NV_COUNTERS_MAX, 0),
        (TPM_PT_NV_INDEX_MAX, MAX_NV_INDICES as u32),
        (TPM_PT_MEMORY, 0x0000_0002),
        (TPM_PT_CLOCK_UPDATE, 1000),
        (TPM_PT_CONTEXT_HASH, TPM_ALG_SHA256 as u32),
        (TPM_PT_CONTEXT_SYM, TPM_ALG_AES as u32),
        (TPM_PT_CONTEXT_SYM_SIZE, 128),
        (TPM_PT_ORDERLY_COUNT, 8),
        (TPM_PT_MAX_COMMAND_SIZE, MAX_COMMAND_SIZE as u32),
        (TPM_PT_MAX_RESPONSE_SIZE, MAX_RESPONSE_SIZE as u32),
        (TPM_PT_MAX_DIGEST, MAX_DIGEST_SIZE as u32),
        (TPM_PT_MAX_OBJECT_CONTEXT, 2048),
        (TPM_PT_MAX_SESSION_CONTEXT, 2048),
        (TPM_PT_PS_FAMILY_INDICATOR, 0x0000_0002),
        (TPM_PT_PS_LEVEL, 0),
        (TPM_PT_PS_REVISION, 0x0000_0100),
        (TPM_PT_PS_DAY_OF_YEAR, 1),
        (TPM_PT_PS_YEAR, 2026),
        (TPM_PT_SPLIT_MAX, 0),
        (TPM_PT_TOTAL_COMMANDS, supported_commands().len() as u32),
        (TPM_PT_LIBRARY_COMMANDS, supported_commands().len() as u32),
        (TPM_PT_VENDOR_COMMANDS, 0),
        (TPM_PT_NV_BUFFER_MAX, MAX_NV_SIZE as u32),
        (TPM_PT_MODES, 0),
        (TPM_PT_MAX_CAP_BUFFER, 1024),
    ]
}

fn algorithms() -> Vec<(u16, u32)> {
    const ASYMMETRIC: u32 = 1 << 0;
    const SYMMETRIC: u32 = 1 << 1;
    const HASH: u32 = 1 << 2;
    const OBJECT: u32 = 1 << 3;
    const SIGNING: u32 = 1 << 8;
    const ENCRYPTING: u32 = 1 << 9;
    const METHOD: u32 = 1 << 10;
    vec![
        (TPM_ALG_RSA, ASYMMETRIC | OBJECT | SIGNING | ENCRYPTING),
        (TPM_ALG_SHA1, HASH),
        (TPM_ALG_HMAC, HASH | SIGNING | METHOD),
        (TPM_ALG_AES, SYMMETRIC),
        (TPM_ALG_KEYEDHASH, OBJECT | SIGNING),
        (TPM_ALG_XOR, HASH | METHOD),
        (TPM_ALG_SHA256, HASH),
        (TPM_ALG_SHA384, HASH),
        (TPM_ALG_SHA512, HASH),
        (TPM_ALG_NULL, 0),
        (TPM_ALG_RSASSA, ASYMMETRIC | SIGNING),
        (TPM_ALG_ECDSA, ASYMMETRIC | SIGNING),
        (TPM_ALG_ECC, ASYMMETRIC | OBJECT | SIGNING),
        (TPM_ALG_ECDH, ASYMMETRIC | METHOD),
    ]
}

fn supported_commands() -> Vec<(u32, usize)> {
    vec![
        (TPM_CC_NV_UNDEFINE_SPACE, 2),
        (TPM_CC_HIERARCHY_CHANGE_AUTH, 1),
        (TPM_CC_NV_DEFINE_SPACE, 1),
        (TPM_CC_CREATE_PRIMARY, 1),
        (TPM_CC_NV_WRITE, 2),
        (TPM_CC_NV_WRITE_LOCK, 2),
        (TPM_CC_SELF_TEST, 0),
        (TPM_CC_STARTUP, 0),
        (TPM_CC_SHUTDOWN, 0),
        (TPM_CC_STIR_RANDOM, 0),
        (TPM_CC_NV_READ, 2),
        (TPM_CC_NV_READ_LOCK, 2),
        (TPM_CC_CREATE, 1),
        (TPM_CC_LOAD, 1),
        (TPM_CC_QUOTE, 1),
        (TPM_CC_FLUSH_CONTEXT, 0),
        (TPM_CC_NV_READ_PUBLIC, 1),
        (TPM_CC_READ_PUBLIC, 1),
        (TPM_CC_START_AUTH_SESSION, 2),
        (TPM_CC_GET_CAPABILITY, 0),
        (TPM_CC_GET_RANDOM, 0),
        (TPM_CC_PCR_READ, 0),
        (TPM_CC_PCR_EXTEND, 1),
    ]
}

fn cmd_get_capability(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let capability = reader.u32()?;
    let property = reader.u32()?;
    let property_count = reader.u32()? as usize;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    if property_count > 1024 {
        return Err(rc_parameter(TPM_RC_VALUE, 3).into());
    }
    let (more_data, data) = capability_data(ctx.tpm, capability, property, property_count)?;
    let mut writer = Writer::new();
    writer.u8(more_data);
    writer.bytes(&data);
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

fn capability_data(
    tpm: &Tpm,
    capability: u32,
    property: u32,
    requested: usize,
) -> Result<(u8, Vec<u8>), u32> {
    let mut writer = Writer::new();
    let mut more = 0u8;
    match capability {
        TPM_CAP_TPM_PROPERTIES => {
            let all = properties(tpm);
            let mut selected: Vec<(u32, u32)> =
                all.into_iter().filter(|(id, _)| *id >= property).collect();
            selected.sort_by_key(|(id, _)| *id);
            if selected.len() > requested {
                selected.truncate(requested);
                more = 1;
            }
            writer.u32(selected.len() as u32);
            for (id, value) in selected {
                writer.u32(id);
                writer.u32(value);
            }
        }
        TPM_CAP_ALGS => {
            let all = algorithms();
            let mut selected: Vec<(u16, u32)> = all
                .into_iter()
                .filter(|(id, _)| *id as u32 >= property)
                .collect();
            selected.sort_by_key(|(id, _)| *id);
            if selected.len() > requested {
                selected.truncate(requested);
                more = 1;
            }
            writer.u32(selected.len() as u32);
            for (id, attributes) in selected {
                writer.u16(id);
                writer.u32(attributes);
            }
        }
        TPM_CAP_COMMANDS => {
            let all = supported_commands();
            let mut selected: Vec<u32> = all
                .into_iter()
                .filter(|(code, _)| *code >= property)
                .map(|(code, handles)| code | ((handles as u32) << 25))
                .collect();
            selected.sort_unstable();
            if selected.len() > requested {
                selected.truncate(requested);
                more = 1;
            }
            writer.u32(selected.len() as u32);
            for command in selected {
                writer.u32(command);
            }
        }
        TPM_CAP_HANDLES => {
            let kind = (property >> 24) as u8;
            let mut handles: Vec<u32> = match kind {
                TPM_HT_TRANSIENT => tpm.objects.keys().copied().collect(),
                TPM_HT_PERSISTENT => Vec::new(),
                TPM_HT_HMAC_SESSION => tpm.sessions.keys().copied().collect(),
                TPM_HT_NV_INDEX => tpm.state.nv.iter().map(|entry| entry.index).collect(),
                _ => Vec::new(),
            };
            handles.retain(|handle| *handle >= property);
            handles.sort_unstable();
            if requested == 0 {
                handles.clear();
            } else if handles.len() > requested {
                handles.truncate(requested);
                more = 1;
            }
            writer.u32(handles.len() as u32);
            for handle in handles {
                writer.u32(handle);
            }
        }
        TPM_CAP_PCRS => {
            writer.u32(1);
            writer.u16(TPM_ALG_SHA256);
            writer.u8(PCR_SELECT_BYTES as u8);
            writer.bytes(&[0xFF, 0xFF, 0xFF]);
            if requested == 0 {
                writer = Writer::new();
                writer.u32(0);
            }
        }
        TPM_CAP_ECC_CURVES => {
            let curves = [TPM_ECC_NIST_P256];
            let count = if requested == 0 { 0 } else { curves.len() };
            writer.u32(count as u32);
            if requested == 0 {
                more = 0;
            }
            for curve in curves.iter().take(count) {
                writer.u16(*curve);
            }
        }
        _ => return Err(rc_parameter(TPM_RC_VALUE, 1)),
    }
    Ok((more, writer.into_vec()))
}

// ---------------------------------------------------------------------------
// PCRs
// ---------------------------------------------------------------------------

fn parse_pcr_selection(reader: &mut Reader<'_>) -> Result<Vec<u8>, u32> {
    let count = reader.u32()? as usize;
    if count > 16 {
        return Err(TPM_RC_SIZE);
    }
    let mut writer = Writer::new();
    writer.u32(count as u32);
    for _ in 0..count {
        let hash_alg = reader.u16()?;
        let size = reader.u8()? as usize;
        if size > 4 {
            return Err(TPM_RC_SIZE);
        }
        let bytes = reader.bytes(size)?;
        if hash_alg != TPM_ALG_SHA256 {
            return Err(TPM_RC_HASH);
        }
        writer.u16(hash_alg);
        writer.u8(size as u8);
        writer.bytes(bytes);
    }
    Ok(writer.into_vec())
}

pub(crate) fn selected_indices(selection: &[u8], param_index: u32) -> Result<Vec<usize>, u32> {
    let mut reader = Reader::new(selection);
    let count = reader.u32()? as usize;
    let mut indices = Vec::new();
    for _ in 0..count {
        let _hash_alg = reader.u16()?;
        let size = reader.u8()? as usize;
        let bytes = reader.bytes(size)?;
        for (byte, value) in bytes.iter().enumerate() {
            for bit in 0..8 {
                if *value & (1 << bit) != 0 {
                    let index = byte * 8 + bit;
                    if index >= PCR_COUNT {
                        return Err(rc_parameter(TPM_RC_VALUE, param_index));
                    }
                    indices.push(index);
                }
            }
        }
    }
    Ok(indices)
}

fn pcr_digest(tpm: &Tpm, selection: &[u8], param_index: u32) -> Result<Vec<u8>, u32> {
    let indices = selected_indices(selection, param_index)?;
    if indices.is_empty() {
        return Ok(Vec::new());
    }
    let mut data = Vec::with_capacity(indices.len() * 32);
    for index in indices {
        data.extend_from_slice(&tpm.state.pcrs[index]);
    }
    Ok(sha256(&data).to_vec())
}

fn cmd_pcr_extend(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let pcr_handle = ctx.handles[0];
    if pcr_handle as usize >= PCR_COUNT {
        return Err(rc_handle(TPM_RC_VALUE, 1).into());
    }
    let mut reader = ctx.reader();
    let count = reader.u32()? as usize;
    if count == 0 || count > 8 {
        return Err(rc_parameter(TPM_RC_VALUE, 1).into());
    }
    let mut digests = Vec::with_capacity(count);
    for _ in 0..count {
        let algorithm = reader.u16()?;
        let length = if algorithm == TPM_ALG_SHA256 {
            32
        } else {
            return Err(TPM_RC_HASH.into());
        };
        let digest = reader.bytes(length)?.to_vec();
        digests.push(digest);
    }
    ctx.complete_params(&mut reader)?;
    ctx.authorize(&[AuthTarget::Pcr(pcr_handle)])?;
    let index = pcr_handle as usize;
    for digest in digests {
        let mut hasher_data = Vec::with_capacity(64);
        hasher_data.extend_from_slice(&ctx.tpm.state.pcrs[index]);
        hasher_data.extend_from_slice(&digest);
        ctx.tpm.state.pcrs[index] = sha256(&hasher_data);
    }
    ctx.tpm.state.pcr_update_counter = ctx.tpm.state.pcr_update_counter.wrapping_add(1);
    ctx.persist()?;
    Ok(empty_outcome())
}

fn cmd_pcr_read(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let selection = parse_pcr_selection(&mut reader)?;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    let indices = selected_indices(&selection, 1)?;
    let mut writer = Writer::new();
    writer.u32(ctx.tpm.state.pcr_update_counter);
    writer.bytes(&selection);
    writer.u32(indices.len() as u32);
    for index in indices {
        writer.tpm2b(&ctx.tpm.state.pcrs[index]);
    }
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

fn parse_sensitive_auth(reader: &mut Reader<'_>) -> Result<Vec<u8>, u32> {
    let sensitive = reader.tpm2b(128)?;
    let mut inner = Reader::new(sensitive);
    let auth = inner.tpm2b(64)?.to_vec();
    let _data = inner.tpm2b(64)?;
    inner.finish()?;
    Ok(auth)
}

pub(crate) fn validate_template(public: &PublicArea) -> Result<(), u32> {
    if !matches!(public.name_alg, TPM_ALG_SHA1 | TPM_ALG_SHA256) {
        return Err(TPM_RC_HASH);
    }
    if !public.rsa_modulus.is_empty() || !public.ecc_x.is_empty() || !public.ecc_y.is_empty() {
        return Err(rc_parameter(TPM_RC_KEY, 2));
    }
    match public.object_type {
        TPM_ALG_RSA => {
            if public.key_bits != 1024 && public.key_bits != 2048 {
                return Err(rc_parameter(TPM_RC_KEY_SIZE, 2));
            }
            if public.exponent != 0 && public.exponent != 65537 {
                return Err(rc_parameter(TPM_RC_KEY, 2));
            }
            if public.scheme != TPM_ALG_NULL && public.scheme != TPM_ALG_RSASSA {
                return Err(rc_parameter(TPM_RC_SCHEME, 2));
            }
            if public.scheme == TPM_ALG_RSASSA
                && public.scheme_hash != 0
                && public.scheme_hash != TPM_ALG_SHA256
            {
                return Err(rc_parameter(TPM_RC_HASH, 2));
            }
        }
        TPM_ALG_ECC => {
            if public.curve != TPM_ECC_NIST_P256 {
                return Err(rc_parameter(TPM_RC_CURVE, 2));
            }
            if public.scheme != TPM_ALG_NULL && public.scheme != TPM_ALG_ECDSA {
                return Err(rc_parameter(TPM_RC_SCHEME, 2));
            }
            if public.scheme == TPM_ALG_ECDSA
                && public.scheme_hash != 0
                && public.scheme_hash != TPM_ALG_SHA256
            {
                return Err(rc_parameter(TPM_RC_HASH, 2));
            }
        }
        _ => return Err(rc_parameter(TPM_RC_TYPE, 2)),
    }
    Ok(())
}

pub(crate) fn key_from_seed(
    seed: &[u8; 32],
    template: &PublicArea,
) -> Result<(KeyMaterial, PublicArea), u32> {
    match template.object_type {
        TPM_ALG_RSA => {
            let private = rsa_from_seed(seed, template.key_bits)?;
            let modulus = rsa_modulus(&private, template.key_bits);
            let mut unique = Writer::new();
            unique.tpm2b(&modulus);
            let public = template.with_unique(unique.into_vec(), modulus, Vec::new(), Vec::new());
            Ok((KeyMaterial::Rsa(private), public))
        }
        TPM_ALG_ECC => {
            let secret = ecc_from_seed(seed);
            let (x, y) = ecc_point(&secret);
            let mut unique = Writer::new();
            unique.tpm2b(&x);
            unique.tpm2b(&y);
            let public = template.with_unique(unique.into_vec(), Vec::new(), x, y);
            Ok((KeyMaterial::Ecc(secret), public))
        }
        _ => Err(TPM_RC_TYPE),
    }
}

fn hierarchy_for_primary(handle: u32) -> Result<Hierarchy, u32> {
    match Hierarchy::from_handle(handle) {
        Some(hierarchy @ (Hierarchy::Owner | Hierarchy::Endorsement | Hierarchy::Platform)) => {
            Ok(hierarchy)
        }
        None if handle == TPM_RH_NULL => Ok(Hierarchy::Platform),
        _ => Err(rc_handle(TPM_RC_HIERARCHY, 1)),
    }
}

fn build_creation_data(
    tpm: &Tpm,
    selection: &[u8],
    locality: u8,
    parent_name_alg: u16,
    parent_name: &[u8],
    outside_info: &[u8],
) -> Result<Vec<u8>, u32> {
    let digest = pcr_digest(tpm, selection, 4)?;
    let mut inner = Writer::new();
    inner.bytes(selection);
    inner.tpm2b(&digest);
    inner.u8(locality);
    inner.u16(parent_name_alg);
    inner.tpm2b(parent_name);
    inner.tpm2b(parent_name);
    inner.tpm2b(outside_info);
    let inner = inner.into_vec();
    let mut outer = Writer::new();
    outer.tpm2b(&inner);
    Ok(outer.into_vec())
}

fn creation_ticket(tpm: &Tpm, hierarchy: Hierarchy, creation_hash: &[u8]) -> Vec<u8> {
    let mut key_data = b"casa1-tpm-creation-ticket".to_vec();
    key_data.extend_from_slice(creation_hash);
    let ticket = super::crypto::hmac_sha256(
        &derive_seed(&hierarchy.seed(&tpm.state), b"casa1-tpm-ticket-key"),
        &key_data,
    );
    let mut writer = Writer::new();
    writer.u16(TPM_ST_CREATION);
    writer.u32(hierarchy.handle());
    writer.tpm2b(&ticket);
    writer.into_vec()
}

fn cmd_create_primary(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let hierarchy = hierarchy_for_primary(ctx.handles[0])?;
    let (auth, public_raw, outside_info, selection) = {
        let mut reader = ctx.reader();
        let auth = parse_sensitive_auth(&mut reader)?;
        let public_raw = reader.tpm2b(1024)?.to_vec();
        let outside_info = reader.tpm2b(64)?.to_vec();
        let selection = parse_pcr_selection(&mut reader)?;
        ctx.complete_params(&mut reader)?;
        (auth, public_raw, outside_info, selection)
    };
    if ctx.handles[0] == TPM_RH_NULL {
        ctx.reject_sessions()?;
    } else {
        ctx.authorize(&[AuthTarget::Hierarchy(hierarchy)])?;
    }
    let template = PublicArea::parse(&public_raw)?;
    validate_template(&template)?;
    let seed = derive_seed(
        &hierarchy.seed(&ctx.tpm.state),
        &[
            b"casa1-tpm-primary-key-v1".as_slice(),
            public_raw.as_slice(),
        ]
        .concat(),
    );
    let (key, public) = key_from_seed(&seed, &template)?;
    let name = public.name();
    let creation_data = build_creation_data(
        ctx.tpm,
        &selection,
        ctx.locality,
        TPM_ALG_NULL,
        &[],
        &outside_info,
    )?;
    let creation_inner = {
        let mut reader = Reader::new(&creation_data);
        reader.tpm2b(1024)?.to_vec()
    };
    let creation_hash = sha256(&creation_inner).to_vec();
    let ticket = creation_ticket(ctx.tpm, hierarchy, &creation_hash);
    let handle = ctx.tpm.insert_object(public.clone(), auth, key, seed)?;
    let mut writer = Writer::new();
    writer.tpm2b(&public.raw);
    writer.bytes(&creation_data);
    writer.tpm2b(&creation_hash);
    writer.bytes(&ticket);
    writer.tpm2b(&name);
    ctx.persist()?;
    Ok(Outcome {
        handles: vec![handle],
        params: writer.into_vec(),
    })
}

fn cmd_create(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let parent_handle = ctx.handles[0];
    let Some(parent) = ctx.tpm.objects.get(&parent_handle) else {
        return Err(rc_handle(TPM_RC_HANDLE, 1).into());
    };
    let parent_seed = parent.child_seed;
    let parent_name = parent.name.clone();
    let parent_name_alg = parent.public.name_alg;
    let (auth, public_raw, outside_info, selection) = {
        let mut reader = ctx.reader();
        let auth = parse_sensitive_auth(&mut reader)?;
        let public_raw = reader.tpm2b(1024)?.to_vec();
        let outside_info = reader.tpm2b(64)?.to_vec();
        let selection = parse_pcr_selection(&mut reader)?;
        ctx.complete_params(&mut reader)?;
        (auth, public_raw, outside_info, selection)
    };
    ctx.authorize(&[AuthTarget::Object(parent_handle)])?;
    let template = PublicArea::parse(&public_raw)?;
    validate_template(&template)?;
    let child_seed = derive_seed(
        &parent_seed,
        &[
            b"casa1-tpm-child-key-v1".as_slice(),
            public_raw.as_slice(),
            auth.as_slice(),
            outside_info.as_slice(),
        ]
        .concat(),
    );
    let (_key, public) = key_from_seed(&child_seed, &template)?;
    let public_hash = sha256(&public.raw);
    let mut private = Writer::new();
    private.bytes(CREATION_MAGIC);
    private.u32(parent_handle);
    private.bytes(&child_seed);
    private.tpm2b(&auth);
    private.bytes(&public_hash);
    let signed = private.into_vec();
    let integrity_key = derive_seed(&parent_seed, b"casa1-tpm-private-integrity-v1");
    let hmac = super::crypto::hmac_sha256(&integrity_key, &signed);
    let mut private_blob = signed;
    private_blob.extend_from_slice(&hmac);
    let creation_data = build_creation_data(
        ctx.tpm,
        &selection,
        ctx.locality,
        parent_name_alg,
        &parent_name,
        &outside_info,
    )?;
    let creation_inner = {
        let mut reader = Reader::new(&creation_data);
        reader.tpm2b(1024)?.to_vec()
    };
    let creation_hash = sha256(&creation_inner).to_vec();
    let ticket = creation_ticket(
        ctx.tpm,
        Hierarchy::from_handle(parent_handle).unwrap_or(Hierarchy::Owner),
        &creation_hash,
    );
    let mut writer = Writer::new();
    writer.tpm2b(&private_blob);
    writer.tpm2b(&public.raw);
    writer.bytes(&creation_data);
    writer.tpm2b(&creation_hash);
    writer.bytes(&ticket);
    ctx.persist()?;
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

fn cmd_load(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let parent_handle = ctx.handles[0];
    let Some(parent) = ctx.tpm.objects.get(&parent_handle) else {
        return Err(rc_handle(TPM_RC_HANDLE, 1).into());
    };
    let parent_seed = parent.child_seed;
    let mut reader = ctx.reader();
    let private_blob = reader.tpm2b(1024)?.to_vec();
    let public_raw = reader.tpm2b(1024)?.to_vec();
    ctx.complete_params(&mut reader)?;
    ctx.authorize(&[AuthTarget::Object(parent_handle)])?;
    let public = PublicArea::parse(&public_raw)?;
    if private_blob.len() < 4 + 4 + 32 + 2 + 32 + 32 || &private_blob[..4] != CREATION_MAGIC {
        return Err(TPM_RC_INTEGRITY.into());
    }
    let signed_len = private_blob.len() - 32;
    let integrity_key = derive_seed(&parent_seed, b"casa1-tpm-private-integrity-v1");
    let expected = super::crypto::hmac_sha256(&integrity_key, &private_blob[..signed_len]);
    if !super::crypto::ct_eq(&expected, &private_blob[signed_len..]) {
        return Err(TPM_RC_INTEGRITY.into());
    }
    let mut inner = Reader::new(&private_blob[..signed_len]);
    inner.bytes(4)?;
    let stored_parent = inner.u32()?;
    if stored_parent != parent_handle {
        return Err(TPM_RC_INTEGRITY.into());
    }
    let child_seed: [u8; 32] = inner.bytes(32)?.try_into().unwrap();
    let auth = inner.tpm2b(64)?.to_vec();
    let stored_hash = inner.bytes(32)?.to_vec();
    inner.finish()?;
    let (key, regenerated) = key_from_seed(&child_seed, &public)?;
    if regenerated.raw != public.raw || sha256(&regenerated.raw).to_vec() != stored_hash {
        return Err(TPM_RC_INTEGRITY.into());
    }
    let name = regenerated.name();
    let handle = ctx.tpm.insert_object(regenerated, auth, key, child_seed)?;
    let mut writer = Writer::new();
    writer.tpm2b(&name);
    Ok(Outcome {
        handles: vec![handle],
        params: writer.into_vec(),
    })
}

fn cmd_flush_context(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let handle = reader.u32()?;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    if ctx.tpm.objects.remove(&handle).is_some() {
        return Ok(empty_outcome());
    }
    if ctx.tpm.sessions.remove(&handle).is_some() {
        return Ok(empty_outcome());
    }
    Err(rc_parameter(TPM_RC_HANDLE, 1).into())
}

fn cmd_read_public(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    let handle = ctx.handles[0];
    let Some(object) = ctx.tpm.objects.get(&handle) else {
        return Err(rc_handle(TPM_RC_HANDLE, 1).into());
    };
    let public = object.public.raw.clone();
    let name = object.name.clone();
    let mut writer = Writer::new();
    writer.tpm2b(&public);
    writer.tpm2b(&name);
    writer.tpm2b(&name);
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

// ---------------------------------------------------------------------------
// Quote
// ---------------------------------------------------------------------------

fn parse_sig_scheme(reader: &mut Reader<'_>) -> Result<(u16, u16), u32> {
    let scheme = reader.u16()?;
    if scheme == TPM_ALG_NULL {
        Ok((scheme, 0))
    } else {
        Ok((scheme, reader.u16()?))
    }
}

fn cmd_quote(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    let qualifying = reader.tpm2b(64)?.to_vec();
    let (requested_scheme, requested_hash) = parse_sig_scheme(&mut reader)?;
    let selection = parse_pcr_selection(&mut reader)?;
    ctx.complete_params(&mut reader)?;
    let handle = ctx.handles[0];
    if !ctx.tpm.objects.contains_key(&handle) {
        return Err(rc_handle(TPM_RC_HANDLE, 1).into());
    }
    ctx.authorize(&[AuthTarget::Object(handle)])?;
    let object = ctx
        .tpm
        .objects
        .get(&handle)
        .ok_or(rc_handle(TPM_RC_HANDLE, 1))?;
    if !object.public.is_signing_key() {
        return Err(TPM_RC_ATTRIBUTES.into());
    }
    let (signature_alg, hash_alg) = match object.public.object_type {
        TPM_ALG_RSA => {
            if requested_scheme != TPM_ALG_NULL && requested_scheme != TPM_ALG_RSASSA {
                return Err(rc_parameter(TPM_RC_SCHEME, 2).into());
            }
            let hash_alg = if requested_scheme == TPM_ALG_NULL {
                if object.public.scheme_hash == 0 {
                    TPM_ALG_SHA256
                } else {
                    object.public.scheme_hash
                }
            } else {
                requested_hash
            };
            (TPM_ALG_RSASSA, hash_alg)
        }
        TPM_ALG_ECC => {
            if requested_scheme != TPM_ALG_NULL && requested_scheme != TPM_ALG_ECDSA {
                return Err(rc_parameter(TPM_RC_SCHEME, 2).into());
            }
            let hash_alg = if requested_scheme == TPM_ALG_NULL {
                if object.public.scheme_hash == 0 {
                    TPM_ALG_SHA256
                } else {
                    object.public.scheme_hash
                }
            } else {
                requested_hash
            };
            (TPM_ALG_ECDSA, hash_alg)
        }
        _ => return Err(rc_parameter(TPM_RC_TYPE, 1).into()),
    };
    if hash_alg != TPM_ALG_SHA256 {
        return Err(rc_parameter(TPM_RC_HASH, 2).into());
    }
    let pcr_digest = pcr_digest(ctx.tpm, &selection, 3)?;
    let mut attest = Writer::new();
    attest.u32(TPM_GENERATED_VALUE);
    attest.u16(TPM_ST_ATTEST_QUOTE);
    attest.tpm2b(&object.name);
    attest.tpm2b(&qualifying);
    attest.u64(ctx.tpm.state.clock);
    attest.u32(ctx.tpm.state.reset_count);
    attest.u32(ctx.tpm.state.restart_count);
    attest.u8(1);
    attest.u64(0x0001_0000_0000_0000);
    attest.bytes(&selection);
    attest.tpm2b(&pcr_digest);
    let attest = attest.into_vec();
    let mut writer = Writer::new();
    writer.tpm2b(&attest);
    writer.u16(signature_alg);
    match &object.key {
        KeyMaterial::Rsa(private) => {
            let signature = rsa_sign(private, &attest);
            writer.tpm2b(&signature);
        }
        KeyMaterial::Ecc(secret) => {
            let (r, s) = ecdsa_sign(secret, &attest);
            writer.u16(hash_alg);
            writer.tpm2b(&r);
            writer.tpm2b(&s);
        }
    }
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

// ---------------------------------------------------------------------------
// Hierarchy auth
// ---------------------------------------------------------------------------

fn cmd_hierarchy_change_auth(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let handle = ctx.handles[0];
    let Some(hierarchy) = Hierarchy::from_handle(handle) else {
        return Err(rc_handle(TPM_RC_HIERARCHY, 1).into());
    };
    let mut reader = ctx.reader();
    let new_auth = reader.tpm2b(MAX_DIGEST_SIZE)?.to_vec();
    ctx.complete_params(&mut reader)?;
    ctx.authorize(&[AuthTarget::Hierarchy(hierarchy)])?;
    *hierarchy.auth_mut(&mut ctx.tpm.state) = new_auth;
    ctx.persist()?;
    Ok(empty_outcome())
}

// ---------------------------------------------------------------------------
// NV
// ---------------------------------------------------------------------------

fn nv_target(auth_handle: u32, index: u32) -> Result<AuthTarget, u32> {
    if auth_handle == index {
        return Ok(AuthTarget::Nv(index));
    }
    match Hierarchy::from_handle(auth_handle) {
        Some(hierarchy @ (Hierarchy::Owner | Hierarchy::Platform)) => {
            Ok(AuthTarget::Hierarchy(hierarchy))
        }
        _ => Err(TPM_RC_NV_AUTHORIZATION),
    }
}

pub(crate) fn nv_allows(attributes: u32, auth_handle: u32, index: u32, write: bool) -> bool {
    let required = if auth_handle == index {
        if write {
            TPMA_NV_AUTHWRITE
        } else {
            TPMA_NV_AUTHREAD
        }
    } else if auth_handle == TPM_RH_OWNER {
        if write {
            TPMA_NV_OWNERWRITE
        } else {
            TPMA_NV_OWNERREAD
        }
    } else if auth_handle == TPM_RH_PLATFORM {
        if write {
            TPMA_NV_PPWRITE
        } else {
            TPMA_NV_PPREAD
        }
    } else {
        return false;
    };
    attributes & required != 0
}

fn cmd_nv_define_space(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let handle = ctx.handles[0];
    let Some(hierarchy) = Hierarchy::from_handle(handle) else {
        return Err(rc_handle(TPM_RC_HIERARCHY, 1).into());
    };
    if !matches!(hierarchy, Hierarchy::Owner | Hierarchy::Platform) {
        return Err(rc_handle(TPM_RC_HIERARCHY, 1).into());
    }
    let mut reader = ctx.reader();
    let auth = reader.tpm2b(MAX_DIGEST_SIZE)?.to_vec();
    let public = reader.tpm2b(1024)?.to_vec();
    ctx.complete_params(&mut reader)?;
    ctx.authorize(&[AuthTarget::Hierarchy(hierarchy)])?;
    let (index, name_alg, attributes, auth_policy, data_size) =
        super::state::parse_nv_public(&public)?;
    if !NvIndex::is_valid_index(index) {
        return Err(rc_parameter(TPM_RC_VALUE, 2).into());
    }
    if data_size == 0 || data_size as usize > MAX_NV_SIZE {
        return Err(TPM_RC_NV_SIZE.into());
    }
    if !matches!(name_alg, TPM_ALG_SHA1 | TPM_ALG_SHA256) {
        return Err(rc_parameter(TPM_RC_HASH, 2).into());
    }
    if ctx.tpm.state.nv.iter().any(|entry| entry.index == index) {
        return Err(TPM_RC_NV_DEFINED.into());
    }
    if ctx.tpm.state.nv.len() >= MAX_NV_INDICES {
        return Err(TPM_RC_NV_SPACE.into());
    }
    ctx.tpm.state.nv.push(
        NvIndex::from_public(
            index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
            auth,
            public,
        )
        .to_persisted(),
    );
    ctx.persist()?;
    Ok(empty_outcome())
}

fn nv_index_and_target(ctx: &ExecCtx<'_>, auth_handle: u32, index: u32) -> Result<AuthTarget, u32> {
    if ctx.tpm.state.nv.iter().all(|entry| entry.index != index) {
        return Err(rc_handle(TPM_RC_HANDLE, 2));
    }
    nv_target(auth_handle, index)
}

fn cmd_nv_write(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let auth_handle = ctx.handles[0];
    let index = ctx.handles[1];
    let mut reader = ctx.reader();
    let data = reader.tpm2b(MAX_NV_SIZE)?.to_vec();
    let offset = reader.u16()? as usize;
    ctx.complete_params(&mut reader)?;
    let target = nv_index_and_target(ctx, auth_handle, index)?;
    ctx.authorize(&[target])?;
    let entry = ctx
        .tpm
        .state
        .nv
        .iter_mut()
        .find(|entry| entry.index == index)
        .ok_or(rc_handle(TPM_RC_HANDLE, 2))?;
    if !nv_allows(entry.attributes, auth_handle, index, true) {
        return Err(TPM_RC_NV_AUTHORIZATION.into());
    }
    if entry.write_locked {
        return Err(TPM_RC_NV_LOCKED.into());
    }
    let end = offset + data.len();
    if end > entry.data_size as usize {
        return Err(TPM_RC_NV_RANGE.into());
    }
    if entry.data.len() < end {
        entry.data.resize(end, 0);
    }
    entry.data[offset..end].copy_from_slice(&data);
    entry.written = true;
    ctx.persist()?;
    Ok(empty_outcome())
}

fn cmd_nv_read(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let auth_handle = ctx.handles[0];
    let index = ctx.handles[1];
    let mut reader = ctx.reader();
    let size = reader.u16()? as usize;
    let offset = reader.u16()? as usize;
    ctx.complete_params(&mut reader)?;
    let target = nv_index_and_target(ctx, auth_handle, index)?;
    ctx.authorize(&[target])?;
    let entry = ctx
        .tpm
        .state
        .nv
        .iter()
        .find(|entry| entry.index == index)
        .ok_or(rc_handle(TPM_RC_HANDLE, 2))?;
    if !nv_allows(entry.attributes, auth_handle, index, false) {
        return Err(TPM_RC_NV_AUTHORIZATION.into());
    }
    if entry.read_locked {
        return Err(TPM_RC_NV_LOCKED.into());
    }
    if !entry.written {
        return Err(TPM_RC_NV_UNINITIALIZED.into());
    }
    let end = offset + size;
    if end > entry.data_size as usize || end > entry.data.len() {
        return Err(TPM_RC_NV_RANGE.into());
    }
    let mut writer = Writer::new();
    writer.tpm2b(&entry.data[offset..end]);
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

fn cmd_nv_write_lock(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let auth_handle = ctx.handles[0];
    let index = ctx.handles[1];
    let mut reader = ctx.reader();
    ctx.complete_params(&mut reader)?;
    let target = nv_index_and_target(ctx, auth_handle, index)?;
    ctx.authorize(&[target])?;
    let entry = ctx
        .tpm
        .state
        .nv
        .iter_mut()
        .find(|entry| entry.index == index)
        .ok_or(rc_handle(TPM_RC_HANDLE, 2))?;
    if !nv_allows(entry.attributes, auth_handle, index, true) {
        return Err(TPM_RC_NV_AUTHORIZATION.into());
    }
    entry.write_locked = true;
    ctx.persist()?;
    Ok(empty_outcome())
}

fn cmd_nv_read_lock(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let auth_handle = ctx.handles[0];
    let index = ctx.handles[1];
    let mut reader = ctx.reader();
    ctx.complete_params(&mut reader)?;
    let target = nv_index_and_target(ctx, auth_handle, index)?;
    ctx.authorize(&[target])?;
    let entry = ctx
        .tpm
        .state
        .nv
        .iter_mut()
        .find(|entry| entry.index == index)
        .ok_or(rc_handle(TPM_RC_HANDLE, 2))?;
    if !nv_allows(entry.attributes, auth_handle, index, false) {
        return Err(TPM_RC_NV_AUTHORIZATION.into());
    }
    entry.read_locked = true;
    ctx.persist()?;
    Ok(empty_outcome())
}

fn cmd_nv_read_public(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let mut reader = ctx.reader();
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    let index = ctx.handles[0];
    let Some(entry) = ctx.tpm.state.nv.iter().find(|entry| entry.index == index) else {
        return Err(rc_handle(TPM_RC_HANDLE, 1).into());
    };
    let nv = NvIndex::from_persisted(entry.clone());
    let mut writer = Writer::new();
    writer.bytes(&nv.nv_public());
    writer.tpm2b(&nv.name());
    Ok(Outcome {
        handles: Vec::new(),
        params: writer.into_vec(),
    })
}

fn cmd_nv_undefine_space(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    let auth_handle = ctx.handles[0];
    let index = ctx.handles[1];
    let mut reader = ctx.reader();
    ctx.complete_params(&mut reader)?;
    let target = nv_index_and_target(ctx, auth_handle, index)?;
    ctx.authorize(&[target])?;
    ctx.tpm.state.nv.retain(|entry| entry.index != index);
    ctx.persist()?;
    Ok(empty_outcome())
}

// ---------------------------------------------------------------------------
// StartAuthSession
// ---------------------------------------------------------------------------

fn cmd_start_auth_session(ctx: &mut ExecCtx<'_>) -> Result<Outcome, CmdError> {
    if ctx.handles[0] != TPM_RH_NULL {
        return Err(rc_handle(TPM_RC_HANDLE, 1).into());
    }
    if ctx.handles[1] != TPM_RH_NULL {
        return Err(rc_handle(TPM_RC_HANDLE, 2).into());
    }
    let mut reader = ctx.reader();
    let nonce_caller = reader.tpm2b(64)?.to_vec();
    let encrypted_salt = reader.tpm2b(64)?;
    if !encrypted_salt.is_empty() {
        return Err(rc_parameter(TPM_RC_SIZE, 2).into());
    }
    let session_type = reader.u8()?;
    let symmetric = reader.u16()?;
    if symmetric != TPM_ALG_NULL {
        let _key_bits = reader.u16()?;
        let _mode = reader.u16()?;
        return Err(rc_parameter(TPM_RC_SYMMETRIC, 4).into());
    }
    let auth_hash = reader.u16()?;
    ctx.complete_params(&mut reader)?;
    ctx.reject_sessions()?;
    if session_type != TPM_SE_HMAC {
        return Err(rc_parameter(TPM_RC_VALUE, 3).into());
    }
    if auth_hash != TPM_ALG_SHA256 {
        return Err(rc_parameter(TPM_RC_HASH, 5).into());
    }
    if !(16..=64).contains(&nonce_caller.len()) {
        return Err(rc_parameter(TPM_RC_SIZE, 1).into());
    }
    let nonce_tpm = ctx.tpm.random_bytes(32);
    let mut nonce_array = [0u8; 32];
    nonce_array.copy_from_slice(&nonce_tpm);
    let session_key = kdfa(b"ATH\0", &nonce_tpm, &nonce_caller, 256);
    let mut key = [0u8; 32];
    key.copy_from_slice(&session_key);
    let handle = ctx
        .tpm
        .insert_session(nonce_array, key, auth_hash, TPM_RH_NULL)?;
    let mut writer = Writer::new();
    writer.tpm2b(&nonce_tpm);
    Ok(Outcome {
        handles: vec![handle],
        params: writer.into_vec(),
    })
}
