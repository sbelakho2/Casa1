//! Adversarial, pinned tests for the software TPM.
//!
//! Every test exercises a malformed/unauthorized/absent/boundary condition and
//! pins an exact TPM_RC or TBS_RESULT value.

use std::fs;

use super::constants::*;
use super::crypto::{
    derive_seed, ecc_from_seed, hmac_sha256, kdfa, rsa_from_seed, rsa_modulus, sha256,
};
use super::persist::{Corruption, NvPersisted, PersistError, PersistedState};
use super::session;
use super::state::{AuthCommand, AuthTarget, Hierarchy, KeyMaterial, NvIndex, PublicArea, Session};
use super::tbs::{
    TBS_CONTEXT_VERSION_ONE, TBS_E_BAD_PARAMETER, TBS_E_BUFFER_TOO_LARGE,
    TBS_E_INSUFFICIENT_BUFFER, TBS_E_INVALID_CONTEXT, TBS_E_INVALID_CONTEXT_PARAM, TBS_SUCCESS,
    TbsAdapter, TbsContextParams, TbsError, TbsPriority, response_code,
};
use super::wire::{Reader, Writer};
use super::{Tpm, TpmError};

// ---------------------------------------------------------------------------
// Command builders
// ---------------------------------------------------------------------------

fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn password_entry(password: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(password.len() as u16).to_be_bytes());
    out.extend_from_slice(password);
    out
}

fn hmac_entry(handle: u32, nonce: &[u8], attributes: u8, hmac: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&handle.to_be_bytes());
    out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce);
    out.push(attributes);
    out.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
    out.extend_from_slice(hmac);
    out
}

fn command(tag: u16, code: u32, handles: &[u32], params: &[u8], sessions: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for handle in handles {
        body.extend_from_slice(&handle.to_be_bytes());
    }
    body.extend_from_slice(params);
    if tag == TPM_ST_SESSIONS {
        let mut auth = Vec::new();
        auth.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
        for session in sessions {
            auth.extend_from_slice(session);
        }
        body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn run(tpm: &mut Tpm, command: &[u8]) -> Vec<u8> {
    tpm.execute(command, 0).expect("in-memory TPM never fails")
}

fn rc(response: &[u8]) -> u32 {
    response_code(response)
}

fn startup() -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&TPM_SU_CLEAR.to_be_bytes());
    command(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP, &[], &params, &[])
}

fn started_tpm() -> Tpm {
    let mut tpm = Tpm::new_with_seed([0x42; 32]);
    assert_eq!(rc(&run(&mut tpm, &startup())), TPM_RC_SUCCESS);
    tpm
}

fn pcr_selection(indices: &[u8]) -> Vec<u8> {
    let mut select = [0u8; PCR_SELECT_BYTES];
    for index in indices {
        select[*index as usize / 8] |= 1 << (*index % 8);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.push(PCR_SELECT_BYTES as u8);
    out.extend_from_slice(&select);
    out
}

fn empty_sensitive() -> Vec<u8> {
    let mut sensitive = Vec::new();
    sensitive.extend_from_slice(&tpm2b(&[]));
    sensitive.extend_from_slice(&tpm2b(&[]));
    tpm2b(&sensitive)
}

fn rsa_template(bits: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.extend_from_slice(
        &(TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_NO_DA
            | TPMA_OBJECT_SIGN)
            .to_be_bytes(),
    );
    out.extend_from_slice(&tpm2b(&[]));
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_RSASSA.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.extend_from_slice(&bits.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    out
}

fn ecc_template() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.extend_from_slice(
        &(TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_NO_DA
            | TPMA_OBJECT_SIGN)
            .to_be_bytes(),
    );
    out.extend_from_slice(&tpm2b(&[]));
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    out.extend_from_slice(&tpm2b(&[]));
    out
}

fn rsa_public_raw(
    name_alg: u16,
    attributes: u32,
    symmetric: Option<(u16, u16, u16)>,
    scheme: Option<(u16, u16)>,
    key_bits: u16,
    exponent: u32,
    unique: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&attributes.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    match symmetric {
        Some((algorithm, bits, mode)) => {
            out.extend_from_slice(&algorithm.to_be_bytes());
            out.extend_from_slice(&bits.to_be_bytes());
            out.extend_from_slice(&mode.to_be_bytes());
        }
        None => out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()),
    }
    match scheme {
        Some((algorithm, hash)) => {
            out.extend_from_slice(&algorithm.to_be_bytes());
            out.extend_from_slice(&hash.to_be_bytes());
        }
        None => out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()),
    }
    out.extend_from_slice(&key_bits.to_be_bytes());
    out.extend_from_slice(&exponent.to_be_bytes());
    out.extend_from_slice(&tpm2b(unique));
    out
}

fn ecc_public_raw(
    name_alg: u16,
    attributes: u32,
    symmetric: Option<(u16, u16, u16)>,
    scheme: Option<(u16, u16)>,
    curve: u16,
    kdf: Option<(u16, u16)>,
    x: &[u8],
    y: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&attributes.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    match symmetric {
        Some((algorithm, bits, mode)) => {
            out.extend_from_slice(&algorithm.to_be_bytes());
            out.extend_from_slice(&bits.to_be_bytes());
            out.extend_from_slice(&mode.to_be_bytes());
        }
        None => out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()),
    }
    match scheme {
        Some((algorithm, hash)) => {
            out.extend_from_slice(&algorithm.to_be_bytes());
            out.extend_from_slice(&hash.to_be_bytes());
        }
        None => out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()),
    }
    out.extend_from_slice(&curve.to_be_bytes());
    match kdf {
        Some((algorithm, hash)) => {
            out.extend_from_slice(&algorithm.to_be_bytes());
            out.extend_from_slice(&hash.to_be_bytes());
        }
        None => out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()),
    }
    out.extend_from_slice(&tpm2b(x));
    out.extend_from_slice(&tpm2b(y));
    out
}

fn default_signing_attributes() -> u32 {
    TPMA_OBJECT_FIXED_TPM
        | TPMA_OBJECT_FIXED_PARENT
        | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
        | TPMA_OBJECT_USER_WITH_AUTH
        | TPMA_OBJECT_NO_DA
        | TPMA_OBJECT_SIGN
}

fn create_primary(tpm: &mut Tpm, template: &[u8], password: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&empty_sensitive());
    params.extend_from_slice(&tpm2b(template));
    params.extend_from_slice(&tpm2b(&[]));
    params.extend_from_slice(&0u32.to_be_bytes());
    let cmd = command(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_OWNER],
        &params,
        &[password_entry(password)],
    );
    run(tpm, &cmd)
}

fn create_primary_ok(tpm: &mut Tpm, template: &[u8]) -> (u32, PublicArea) {
    let response = create_primary(tpm, template, &[]);
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let handle = u32::from_be_bytes([response[10], response[11], response[12], response[13]]);
    let parameter_size =
        u32::from_be_bytes([response[14], response[15], response[16], response[17]]) as usize;
    let params = &response[18..18 + parameter_size];
    let mut reader = Reader::new(params);
    let public_raw = reader.tpm2b(1024).expect("outPublic");
    let public = PublicArea::parse(public_raw).expect("parse public");
    (handle, public)
}

fn create_child(tpm: &mut Tpm, parent: u32, template: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut params = Vec::new();
    params.extend_from_slice(&empty_sensitive());
    params.extend_from_slice(&tpm2b(template));
    params.extend_from_slice(&tpm2b(&[]));
    params.extend_from_slice(&0u32.to_be_bytes());
    let response = run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            TPM_CC_CREATE,
            &[parent],
            &params,
            &[password_entry(&[])],
        ),
    );
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let mut reader = Reader::new(response_parameters(&response));
    let private = reader.tpm2b(2048).expect("outPrivate").to_vec();
    let public = reader.tpm2b(1024).expect("outPublic").to_vec();
    (private, public)
}

fn load_child(tpm: &mut Tpm, parent: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&tpm2b(private));
    params.extend_from_slice(&tpm2b(public));
    run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            TPM_CC_LOAD,
            &[parent],
            &params,
            &[password_entry(&[])],
        ),
    )
}

fn read_public(tpm: &mut Tpm, handle: u32) -> Vec<u8> {
    run(
        tpm,
        &command(TPM_ST_NO_SESSIONS, TPM_CC_READ_PUBLIC, &[handle], &[], &[]),
    )
}

fn flush(tpm: &mut Tpm, handle: u32) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&handle.to_be_bytes());
    run(
        tpm,
        &command(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT, &[], &params, &[]),
    )
}

fn quote_params(indices: &[u8], scheme: Option<(u16, u16)>) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&tpm2b(b"qualifying"));
    match scheme {
        Some((scheme, hash)) => {
            params.extend_from_slice(&scheme.to_be_bytes());
            params.extend_from_slice(&hash.to_be_bytes());
        }
        None => params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()),
    }
    params.extend_from_slice(&pcr_selection(indices));
    params
}

fn quote_command(handle: u32, indices: &[u8]) -> Vec<u8> {
    let params = quote_params(indices, None);
    command(
        TPM_ST_SESSIONS,
        TPM_CC_QUOTE,
        &[handle],
        &params,
        &[password_entry(&[])],
    )
}

fn quote_command_no_sessions(handle: u32, indices: &[u8]) -> Vec<u8> {
    let params = quote_params(indices, None);
    command(TPM_ST_NO_SESSIONS, TPM_CC_QUOTE, &[handle], &params, &[])
}

fn quote_command_with_scheme(handle: u32, indices: &[u8], scheme: u16, hash: u16) -> Vec<u8> {
    let params = quote_params(indices, Some((scheme, hash)));
    command(
        TPM_ST_SESSIONS,
        TPM_CC_QUOTE,
        &[handle],
        &params,
        &[password_entry(&[])],
    )
}

fn quote_parts(response: &[u8]) -> (Vec<u8>, u16, Vec<u8>, Vec<u8>) {
    let tag = u16::from_be_bytes([response[0], response[1]]);
    let offset = if tag == TPM_ST_SESSIONS { 14 } else { 10 };
    let mut reader = Reader::new(&response[offset..]);
    let attest = reader.tpm2b(1024).expect("attest").to_vec();
    let signature_alg = reader.u16().expect("sig alg");
    if signature_alg == TPM_ALG_RSASSA {
        let signature = reader.tpm2b(512).expect("rsa signature").to_vec();
        (attest, signature_alg, signature, Vec::new())
    } else {
        let _hash = reader.u16().expect("ecdsa hash");
        let r = reader.tpm2b(64).expect("r").to_vec();
        let s = reader.tpm2b(64).expect("s").to_vec();
        (attest, signature_alg, r, s)
    }
}

fn response_parameters(response: &[u8]) -> &[u8] {
    let size =
        u32::from_be_bytes([response[10], response[11], response[12], response[13]]) as usize;
    &response[14..14 + size]
}

fn response_handles_and_parameters(response: &[u8]) -> (u32, &[u8]) {
    let handle = u32::from_be_bytes([response[10], response[11], response[12], response[13]]);
    let size =
        u32::from_be_bytes([response[14], response[15], response[16], response[17]]) as usize;
    (handle, &response[18..18 + size])
}

fn nv_public_with_attributes(index: u32, size: u16, attributes: u32) -> Vec<u8> {
    let mut public = Vec::new();
    public.extend_from_slice(&index.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    public.extend_from_slice(&attributes.to_be_bytes());
    public.extend_from_slice(&tpm2b(&[]));
    public.extend_from_slice(&size.to_be_bytes());
    public
}

fn nv_define_with_attributes(tpm: &mut Tpm, index: u32, size: u16, attributes: u32) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&tpm2b(&[]));
    params.extend_from_slice(&tpm2b(&nv_public_with_attributes(index, size, attributes)));
    run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            TPM_CC_NV_DEFINE_SPACE,
            &[TPM_RH_OWNER],
            &params,
            &[password_entry(&[])],
        ),
    )
}

fn nv_define(tpm: &mut Tpm, index: u32, size: u16) -> Vec<u8> {
    nv_define_with_attributes(tpm, index, size, nv_default_attributes())
}

fn nv_default_attributes() -> u32 {
    TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA
}

fn nv_write(tpm: &mut Tpm, auth_handle: u32, index: u32, offset: u16, data: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&tpm2b(data));
    params.extend_from_slice(&offset.to_be_bytes());
    run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            TPM_CC_NV_WRITE,
            &[auth_handle, index],
            &params,
            &[password_entry(&[])],
        ),
    )
}

fn nv_read(tpm: &mut Tpm, auth_handle: u32, index: u32, offset: u16, size: u16) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&size.to_be_bytes());
    params.extend_from_slice(&offset.to_be_bytes());
    run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            TPM_CC_NV_READ,
            &[auth_handle, index],
            &params,
            &[password_entry(&[])],
        ),
    )
}

fn nv_lock(tpm: &mut Tpm, code: u32, index: u32) -> Vec<u8> {
    run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            code,
            &[index, index],
            &[],
            &[password_entry(&[])],
        ),
    )
}

// ---------------------------------------------------------------------------
// Malformed command / parameter tests
// ---------------------------------------------------------------------------

#[test]
fn malformed_command_size_and_tag_are_rejected_with_exact_rc() {
    let mut tpm = started_tpm();
    let short = run(&mut tpm, &[0x80, 0x01, 0x00]);
    assert_eq!(rc(&short), TPM_RC_COMMAND_SIZE);

    let mut oversized = startup();
    oversized[2..6].copy_from_slice(&99u32.to_be_bytes());
    assert_eq!(rc(&run(&mut tpm, &oversized)), TPM_RC_COMMAND_SIZE);

    let mut bad_tag = startup();
    bad_tag[..2].copy_from_slice(&0x9999u16.to_be_bytes());
    assert_eq!(rc(&run(&mut tpm, &bad_tag)), TPM_RC_TAG);
}

#[test]
fn unknown_command_and_pre_startup_command_are_rejected() {
    let mut tpm = Tpm::new_with_seed([0x11; 32]);
    let get_random = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &16u16.to_be_bytes(),
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &get_random)), TPM_RC_INITIALIZE);

    let unknown = command(TPM_ST_NO_SESSIONS, 0xDEAD_BEEF, &[], &[], &[]);
    assert_eq!(rc(&run(&mut tpm, &unknown)), TPM_RC_COMMAND_CODE);
}

#[test]
fn malformed_parameter_size_and_auth_area_are_rejected() {
    let mut tpm = started_tpm();

    let short_startup = command(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP, &[], &[0x00], &[]);
    let response = run(&mut tpm, &short_startup);
    assert_eq!(rc(&response), TPM_RC_SIZE);

    let mut trailing = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &[0x00, 0x10, 0xAA],
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &trailing)), TPM_RC_SIZE);

    trailing = command(
        TPM_ST_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &[0x00, 0x10],
        &[password_entry(&[])],
    );
    let auth_size_offset = 10 + 2;
    trailing[auth_size_offset..auth_size_offset + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(rc(&run(&mut tpm, &trailing)), TPM_RC_AUTHSIZE);
}

// ---------------------------------------------------------------------------
// Authorization tests
// ---------------------------------------------------------------------------

#[test]
fn bad_password_and_bad_hmac_are_rejected_with_exact_rc() {
    let mut tpm = started_tpm();
    let mut params = Vec::new();
    params.extend_from_slice(&empty_sensitive());
    params.extend_from_slice(&tpm2b(&rsa_template(1024)));
    params.extend_from_slice(&tpm2b(&[]));
    params.extend_from_slice(&0u32.to_be_bytes());
    let bad_password = command(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_OWNER],
        &params,
        &[password_entry(b"wrong")],
    );
    let response = run(&mut tpm, &bad_password);
    assert_eq!(rc(&response), TPM_RC_BAD_AUTH);
    assert_eq!(tpm.transient_handles().len(), 0);

    // Establish an HMAC session, then deliberately corrupt its command HMAC.
    let nonce_caller = [0x5Au8; 32];
    let mut session_params = Vec::new();
    session_params.extend_from_slice(&tpm2b(&nonce_caller));
    session_params.extend_from_slice(&tpm2b(&[]));
    session_params.push(TPM_SE_HMAC);
    session_params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    session_params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let session_response = run(
        &mut tpm,
        &command(
            TPM_ST_NO_SESSIONS,
            TPM_CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, TPM_RH_NULL],
            &session_params,
            &[],
        ),
    );
    assert_eq!(rc(&session_response), TPM_RC_SUCCESS);
    let session_handle = u32::from_be_bytes([
        session_response[10],
        session_response[11],
        session_response[12],
        session_response[13],
    ]);
    let material = tpm
        .session_material(session_handle)
        .expect("session material");

    let create_params = params.clone();
    let cp_hash = session::cp_hash(
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_OWNER.to_be_bytes().to_vec()],
        &create_params,
    );
    let mut nonce = vec![0x33u8; 32];
    let good = session::auth_hmac(
        &material.session_key,
        &cp_hash,
        &nonce,
        &material.nonce_tpm,
        0,
    );
    let mut bad = good;
    bad[0] ^= 0xFF;
    let bad_hmac = command(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_OWNER],
        &create_params,
        &[hmac_entry(session_handle, &nonce, 0, &bad)],
    );
    assert_eq!(
        rc(&run(&mut tpm, &bad_hmac)),
        rc_session(TPM_RC_AUTH_FAIL, 1)
    );

    nonce[0] ^= 0x01;
    let good_hmac = command(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_OWNER],
        &create_params,
        &[hmac_entry(
            session_handle,
            &nonce,
            0,
            &session::auth_hmac(
                &material.session_key,
                &cp_hash,
                &nonce,
                &material.nonce_tpm,
                0,
            ),
        )],
    );
    let good_response = run(&mut tpm, &good_hmac);
    assert_eq!(rc(&good_response), TPM_RC_SUCCESS);

    let params = response_handles_and_parameters(&good_response).1;
    let mut auth = Reader::new(&good_response[18 + params.len()..]);
    assert_eq!(auth.u32().expect("session count"), 1);
    assert_eq!(auth.u32().expect("session handle"), session_handle);
    let response_nonce = auth.tpm2b(64).expect("response nonce").to_vec();
    let response_attributes = auth.u8().expect("response attributes");
    let response_hmac = auth.tpm2b(64).expect("response hmac").to_vec();
    let mut expected_data = Vec::new();
    expected_data.extend_from_slice(&session::rp_hash(
        TPM_CC_CREATE_PRIMARY,
        TPM_RC_SUCCESS,
        params,
    ));
    expected_data.extend_from_slice(&response_nonce);
    expected_data.extend_from_slice(&nonce);
    expected_data.push(response_attributes);
    assert_eq!(
        response_hmac,
        hmac_sha256(&material.session_key, &expected_data).to_vec()
    );
    assert_ne!(response_nonce, material.nonce_tpm.to_vec());
}

#[test]
fn hierarchy_change_auth_rejects_stale_auth_and_persists_new_auth() {
    let mut tpm = started_tpm();
    let mut params = Vec::new();
    params.extend_from_slice(&tpm2b(b"new-owner-secret"));
    let bad = command(
        TPM_ST_SESSIONS,
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[TPM_RH_OWNER],
        &params,
        &[password_entry(b"not-the-old-secret")],
    );
    assert_eq!(rc(&run(&mut tpm, &bad)), TPM_RC_BAD_AUTH);

    let good = command(
        TPM_ST_SESSIONS,
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[TPM_RH_OWNER],
        &params,
        &[password_entry(&[])],
    );
    assert_eq!(rc(&run(&mut tpm, &good)), TPM_RC_SUCCESS);
    assert_eq!(
        tpm.hierarchy_auth(super::state::Hierarchy::Owner),
        b"new-owner-secret"
    );

    let stale = command(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_OWNER],
        &{
            let mut params = Vec::new();
            params.extend_from_slice(&empty_sensitive());
            params.extend_from_slice(&tpm2b(&rsa_template(1024)));
            params.extend_from_slice(&tpm2b(&[]));
            params.extend_from_slice(&0u32.to_be_bytes());
            params
        },
        &[password_entry(&[])],
    );
    assert_eq!(rc(&run(&mut tpm, &stale)), TPM_RC_BAD_AUTH);
}

// ---------------------------------------------------------------------------
// PCR boundaries
// ---------------------------------------------------------------------------

#[test]
fn pcr_boundary_indices_are_rejected_with_exact_rc() {
    let mut tpm = started_tpm();
    let mut extend_params = Vec::new();
    extend_params.extend_from_slice(&1u32.to_be_bytes());
    extend_params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    extend_params.extend_from_slice(&[0x11u8; 32]);
    let out_of_range_extend = command(
        TPM_ST_SESSIONS,
        TPM_CC_PCR_EXTEND,
        &[PCR_COUNT as u32],
        &extend_params,
        &[password_entry(&[])],
    );
    assert_eq!(
        rc(&run(&mut tpm, &out_of_range_extend)),
        rc_handle(TPM_RC_VALUE, 1)
    );

    let mut read_params = Vec::new();
    read_params.extend_from_slice(&1u32.to_be_bytes());
    read_params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    read_params.push(4);
    read_params.extend_from_slice(&[0, 0, 0, 0x01]);
    let out_of_range_read = command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, &[], &read_params, &[]);
    assert_eq!(
        rc(&run(&mut tpm, &out_of_range_read)),
        rc_parameter(TPM_RC_VALUE, 1)
    );

    let mut wrong_hash = Vec::new();
    wrong_hash.extend_from_slice(&1u32.to_be_bytes());
    wrong_hash.extend_from_slice(&TPM_ALG_SHA1.to_be_bytes());
    wrong_hash.push(3);
    wrong_hash.extend_from_slice(&[0x01, 0, 0]);
    let wrong_hash_read = command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, &[], &wrong_hash, &[]);
    assert_eq!(rc(&run(&mut tpm, &wrong_hash_read)), TPM_RC_HASH);

    let mut sha1_extend = Vec::new();
    sha1_extend.extend_from_slice(&1u32.to_be_bytes());
    sha1_extend.extend_from_slice(&TPM_ALG_SHA1.to_be_bytes());
    sha1_extend.extend_from_slice(&[0x11u8; 20]);
    let unbanked_extend = command(
        TPM_ST_SESSIONS,
        TPM_CC_PCR_EXTEND,
        &[0],
        &sha1_extend,
        &[password_entry(&[])],
    );
    assert_eq!(rc(&run(&mut tpm, &unbanked_extend)), TPM_RC_HASH);

    let digest = [0xABu8; 32];
    let mut valid_extend_params = Vec::new();
    valid_extend_params.extend_from_slice(&1u32.to_be_bytes());
    valid_extend_params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    valid_extend_params.extend_from_slice(&digest);
    let valid_extend = command(
        TPM_ST_SESSIONS,
        TPM_CC_PCR_EXTEND,
        &[7],
        &valid_extend_params,
        &[password_entry(&[])],
    );
    assert_eq!(rc(&run(&mut tpm, &valid_extend)), TPM_RC_SUCCESS);
    let mut expected_input = [0u8; 64];
    expected_input[32..].copy_from_slice(&digest);
    assert_eq!(tpm.pcr(7), Some(super::crypto::sha256(&expected_input)));
    assert_eq!(tpm.pcr_update_counter(), 1);
}

#[test]
fn nv_define_rejects_duplicate_invalid_index_and_zero_size() {
    let mut tpm = started_tpm();
    assert_eq!(rc(&nv_define(&mut tpm, 0x0150_0020, 8)), TPM_RC_SUCCESS);
    assert_eq!(rc(&nv_define(&mut tpm, 0x0150_0020, 8)), TPM_RC_NV_DEFINED);
    assert_eq!(
        rc(&nv_define(&mut tpm, 0x0000_0001, 8)),
        rc_parameter(TPM_RC_VALUE, 2)
    );
    assert_eq!(rc(&nv_define(&mut tpm, 0x0150_0021, 0)), TPM_RC_NV_SIZE);
}

#[test]
fn nv_bounds_lock_and_uninitialized_reads_are_rejected() {
    let mut tpm = started_tpm();
    let index = 0x0150_0030;
    assert_eq!(rc(&nv_define(&mut tpm, index, 8)), TPM_RC_SUCCESS);
    assert_eq!(
        rc(&nv_read(&mut tpm, TPM_RH_OWNER, index, 0, 4)),
        TPM_RC_NV_UNINITIALIZED
    );
    assert_eq!(
        rc(&nv_write(&mut tpm, TPM_RH_OWNER, index, 0, b"abcd")),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_write(&mut tpm, TPM_RH_OWNER, index, 6, b"abcd")),
        TPM_RC_NV_RANGE
    );
    assert_eq!(
        rc(&nv_read(&mut tpm, TPM_RH_OWNER, index, 6, 4)),
        TPM_RC_NV_RANGE
    );
    assert_eq!(
        rc(&nv_read(&mut tpm, TPM_RH_OWNER, 0x0150_00FF, 0, 1)),
        rc_handle(TPM_RC_HANDLE, 2)
    );

    assert_eq!(
        rc(&nv_lock(&mut tpm, TPM_CC_NV_WRITE_LOCK, index)),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_write(&mut tpm, TPM_RH_OWNER, index, 0, b"wxyz")),
        TPM_RC_NV_LOCKED
    );
    assert_eq!(
        rc(&nv_write(&mut tpm, TPM_RH_ENDORSEMENT, index, 0, b"x")),
        TPM_RC_NV_AUTHORIZATION
    );

    let read_index = 0x0150_0031;
    assert_eq!(rc(&nv_define(&mut tpm, read_index, 8)), TPM_RC_SUCCESS);
    assert_eq!(
        rc(&nv_write(&mut tpm, TPM_RH_OWNER, read_index, 0, b"read")),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_lock(&mut tpm, TPM_CC_NV_READ_LOCK, read_index)),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_read(&mut tpm, TPM_RH_OWNER, read_index, 0, 4)),
        TPM_RC_NV_LOCKED
    );

    let unattributed = 0x0150_0032;
    assert_eq!(
        rc(&nv_define_with_attributes(&mut tpm, unattributed, 8, 0)),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_write(&mut tpm, TPM_RH_OWNER, unattributed, 0, b"nope")),
        TPM_RC_NV_AUTHORIZATION
    );
    assert_eq!(
        rc(&nv_read(&mut tpm, TPM_RH_OWNER, unattributed, 0, 1)),
        TPM_RC_NV_AUTHORIZATION
    );
}

// ---------------------------------------------------------------------------
// Persistence corruption
// ---------------------------------------------------------------------------

#[test]
fn persistence_corruption_is_rejected_and_never_reset() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("tpm2").join("state.bin");
    let persisted_public = {
        let mut tpm = Tpm::open(path.as_path()).expect("open fresh");
        assert_eq!(rc(&run(&mut tpm, &startup())), TPM_RC_SUCCESS);
        assert_eq!(rc(&nv_define(&mut tpm, 0x0150_0040, 8)), TPM_RC_SUCCESS);
        let (_, public) = create_primary_ok(&mut tpm, &ecc_template());
        tpm.save().expect("save");
        public
    };
    {
        let mut reopened = Tpm::open(path.as_path()).expect("clean reload");
        assert_eq!(reopened.nv_indices(), vec![0x0150_0040]);
        assert_eq!(rc(&run(&mut reopened, &startup())), TPM_RC_SUCCESS);
        let (_, reloaded) = create_primary_ok(&mut reopened, &ecc_template());
        assert_eq!(reloaded.raw, persisted_public.raw);
    }
    let mut bytes = fs::read(&path).expect("read state");
    let payload_start = 8 + 4 + 8 + 4;
    bytes[payload_start] ^= 0xFF;
    fs::write(&path, &bytes).expect("corrupt");

    let error = Tpm::open(path.as_path())
        .err()
        .expect("corrupt state must fail");
    assert_eq!(
        error,
        TpmError::Persist(PersistError::Corrupt(Corruption::ChecksumMismatch))
    );
    assert_eq!(fs::read(&path).expect("unchanged"), bytes);
    let again = Tpm::open(path.as_path()).err().expect("still corrupt");
    assert_eq!(
        again,
        TpmError::Persist(PersistError::Corrupt(Corruption::ChecksumMismatch))
    );
}

#[test]
fn persistence_rejects_valid_checksum_with_invalid_payload_shape() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("invalid.bin");
    let mut state = super::persist::PersistedState::fresh([0x5A; 32]);
    state.pcrs.pop();
    let bytes = super::persist::encode(&state).expect("encode mutated state");
    fs::write(&path, &bytes).expect("write payload");
    assert_eq!(
        Tpm::open(path.as_path()).err().expect("invalid payload"),
        TpmError::Persist(PersistError::Corrupt(Corruption::InvalidPcrCount(
            PCR_COUNT - 1
        )))
    );
}

#[test]
fn persistence_short_header_and_version_are_rejected() {
    let directory = tempfile::tempdir().expect("tempdir");
    let short = directory.path().join("short.bin");
    fs::write(&short, b"CASA1TPM").expect("write short");
    assert_eq!(
        Tpm::open(short.as_path()).err().expect("short header"),
        TpmError::Persist(PersistError::Corrupt(Corruption::ShortHeader))
    );

    let version = directory.path().join("version.bin");
    let mut bytes = vec![0u8; 8 + 4 + 8 + 32];
    bytes[..8].copy_from_slice(b"CASA1TPM");
    bytes[8..12].copy_from_slice(&7u32.to_be_bytes());
    fs::write(&version, bytes).expect("write version");
    assert_eq!(
        Tpm::open(version.as_path()).err().expect("version"),
        TpmError::Persist(PersistError::Corrupt(Corruption::UnsupportedVersion(7)))
    );
}

// ---------------------------------------------------------------------------
// Quote verification
// ---------------------------------------------------------------------------

#[test]
fn rsa_quote_signature_rejects_tampered_attest_and_pcr_digest_matches() {
    let mut tpm = started_tpm();
    let (handle, public) = create_primary_ok(&mut tpm, &rsa_template(1024));
    assert_eq!(
        rc(&run(&mut tpm, &quote_command_no_sessions(handle, &[3]))),
        TPM_RC_AUTH_MISSING
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &quote_command_with_scheme(handle, &[3], TPM_ALG_RSAPSS, TPM_ALG_SHA256)
        )),
        rc_parameter(TPM_RC_SCHEME, 2)
    );
    let digest = [0x77u8; 32];
    let mut extend_params = Vec::new();
    extend_params.extend_from_slice(&1u32.to_be_bytes());
    extend_params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    extend_params.extend_from_slice(&digest);
    let extend = command(
        TPM_ST_SESSIONS,
        TPM_CC_PCR_EXTEND,
        &[3],
        &extend_params,
        &[password_entry(&[])],
    );
    assert_eq!(rc(&run(&mut tpm, &extend)), TPM_RC_SUCCESS);

    let response = run(&mut tpm, &quote_command(handle, &[3]));
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let (attest, signature_alg, signature, _) = quote_parts(&response);
    assert_eq!(signature_alg, TPM_ALG_RSASSA);

    let mut reader = Reader::new(&attest);
    assert_eq!(reader.u32().expect("magic"), TPM_GENERATED_VALUE);
    assert_eq!(reader.u16().expect("type"), TPM_ST_ATTEST_QUOTE);
    let _signer = reader.tpm2b(64).expect("signer");
    let extra = reader.tpm2b(64).expect("extra");
    assert_eq!(extra, b"qualifying");
    let _clock = reader.bytes(8).expect("clock");
    let _reset = reader.u32().expect("reset");
    let _restart = reader.u32().expect("restart");
    let _safe = reader.u8().expect("safe");
    let _firmware = reader.bytes(8).expect("firmware");
    let selection_count = reader.u32().expect("selection count");
    assert_eq!(selection_count, 1);
    let _selection_hash = reader.u16().expect("selection hash");
    let selection_size = reader.u8().expect("selection size");
    let _selection_bytes = reader
        .bytes(selection_size as usize)
        .expect("selection bytes");
    let pcr_digest = reader.tpm2b(64).expect("pcr digest");

    let mut expected_input = [0u8; 64];
    expected_input[32..].copy_from_slice(&digest);
    let expected_pcr = super::crypto::sha256(&expected_input);
    assert_eq!(pcr_digest, super::crypto::sha256(&expected_pcr).as_slice());

    let exponent = if public.exponent == 0 {
        65537
    } else {
        public.exponent
    };
    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&public.rsa_modulus),
        rsa::BigUint::from(exponent),
    )
    .expect("public key");
    let verifying = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key);
    let signature =
        rsa::pkcs1v15::Signature::try_from(signature.as_slice()).expect("signature shape");
    use rsa::signature::{SignatureEncoding, Verifier};
    assert_eq!(verifying.verify(&attest, &signature).is_ok(), true);

    let mut tampered = attest.clone();
    tampered[0] ^= 0xFF;
    assert!(verifying.verify(&tampered, &signature).is_err());
    let mut bad_signature = signature.clone();
    let mut bad_bytes = bad_signature.to_bytes().to_vec();
    bad_bytes[0] ^= 0xFF;
    bad_signature =
        rsa::pkcs1v15::Signature::try_from(bad_bytes.as_slice()).expect("mutated signature shape");
    assert!(verifying.verify(&attest, &bad_signature).is_err());
}

#[test]
fn ecc_quote_signature_rejects_tampered_attest_and_attest_shape_is_exact() {
    let mut tpm = started_tpm();
    let (handle, public) = create_primary_ok(&mut tpm, &ecc_template());
    let response = run(&mut tpm, &quote_command(handle, &[0]));
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let (attest, signature_alg, r, s) = quote_parts(&response);
    assert_eq!(signature_alg, TPM_ALG_ECDSA);

    let mut encoded = Vec::with_capacity(65);
    encoded.push(0x04);
    encoded.extend_from_slice(&public.ecc_x);
    encoded.extend_from_slice(&public.ecc_y);
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded).expect("P-256 public key");
    let mut raw = Vec::with_capacity(64);
    raw.extend_from_slice(&r);
    raw.extend_from_slice(&s);
    let signature = p256::ecdsa::Signature::from_slice(&raw).expect("signature shape");
    use p256::ecdsa::signature::Verifier;
    assert_eq!(verifying.verify(&attest, &signature).is_ok(), true);
    let mut tampered = attest.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(verifying.verify(&tampered, &signature).is_err());

    let mut reader = Reader::new(&attest);
    assert_eq!(reader.u32().expect("magic"), TPM_GENERATED_VALUE);
    assert_eq!(reader.u16().expect("type"), TPM_ST_ATTEST_QUOTE);
}

// ---------------------------------------------------------------------------
// Object lifecycle
// ---------------------------------------------------------------------------

#[test]
fn repeated_create_flush_does_not_leak_handles() {
    let mut tpm = started_tpm();
    let mut seen = Vec::new();
    for _ in 0..3 {
        let (handle, _public) = create_primary_ok(&mut tpm, &rsa_template(1024));
        assert!(!seen.contains(&handle));
        seen.push(handle);
        assert_eq!(rc(&flush(&mut tpm, handle)), TPM_RC_SUCCESS);
        assert_eq!(tpm.transient_handles().len(), 0);
        assert_eq!(
            rc(&read_public(&mut tpm, handle)),
            rc_handle(TPM_RC_HANDLE, 1)
        );
    }
    assert_eq!(
        rc(&flush(&mut tpm, 0x8000_FFFF)),
        rc_parameter(TPM_RC_HANDLE, 1)
    );
}

#[test]
fn absent_objects_are_rejected_with_exact_handle_rc() {
    let mut tpm = started_tpm();
    assert_eq!(
        rc(&read_public(&mut tpm, 0x8000_0001)),
        rc_handle(TPM_RC_HANDLE, 1)
    );
    let quote = quote_command(0x8000_0001, &[0]);
    assert_eq!(rc(&run(&mut tpm, &quote)), rc_handle(TPM_RC_HANDLE, 1));

    let mut load_params = Vec::new();
    load_params.extend_from_slice(&tpm2b(&[]));
    load_params.extend_from_slice(&tpm2b(&rsa_template(1024)));
    let load = command(
        TPM_ST_SESSIONS,
        TPM_CC_LOAD,
        &[0x8000_0002],
        &load_params,
        &[password_entry(&[])],
    );
    assert_eq!(rc(&run(&mut tpm, &load)), rc_handle(TPM_RC_HANDLE, 1));

    let lockout_primary = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_LOCKOUT],
        &[],
        &[],
    );
    assert_eq!(
        rc(&run(&mut tpm, &lockout_primary)),
        rc_handle(TPM_RC_HIERARCHY, 1)
    );

    let mut null_params = Vec::new();
    null_params.extend_from_slice(&empty_sensitive());
    null_params.extend_from_slice(&tpm2b(&ecc_template()));
    null_params.extend_from_slice(&tpm2b(&[]));
    null_params.extend_from_slice(&0u32.to_be_bytes());
    let null_primary = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_NULL],
        &null_params,
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &null_primary)), TPM_RC_SUCCESS);
}

#[test]
fn load_rejects_tampered_private_blob_and_round_trips_exact_public_area() {
    let mut tpm = started_tpm();
    let (parent, _parent_public) = create_primary_ok(&mut tpm, &rsa_template(1024));
    let (private, public) = create_child(&mut tpm, parent, &ecc_template());

    let mut tampered = private.clone();
    tampered[4] ^= 0xFF;
    assert_eq!(
        rc(&load_child(&mut tpm, parent, &tampered, &public)),
        TPM_RC_INTEGRITY
    );

    let response = load_child(&mut tpm, parent, &private, &public);
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let (handle, params) = response_handles_and_parameters(&response);
    let mut reader = Reader::new(params);
    let name = reader.tpm2b(64).expect("loaded name");
    let mut expected = TPM_ALG_SHA256.to_be_bytes().to_vec();
    expected.extend_from_slice(&super::crypto::sha256(&public));
    assert_eq!(name, expected.as_slice());
    assert!(tpm.transient_handles().contains(&handle));
    assert_eq!(rc(&flush(&mut tpm, handle)), TPM_RC_SUCCESS);
    assert!(!tpm.transient_handles().contains(&handle));
}

#[test]
fn get_capability_rejects_unknown_capability_and_reports_commands() {
    let mut tpm = started_tpm();
    let mut params = Vec::new();
    params.extend_from_slice(&TPM_CAP_COMMANDS.to_be_bytes());
    params.extend_from_slice(&0u32.to_be_bytes());
    params.extend_from_slice(&256u32.to_be_bytes());
    let response = run(
        &mut tpm,
        &command(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY, &[], &params, &[]),
    );
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let mut reader = Reader::new(&response[10..]);
    let more = reader.u8().expect("moreData");
    assert_eq!(more, 0);
    let count = reader.u32().expect("count");
    assert!(count >= 20);
    let mut found_startup = false;
    for _ in 0..count {
        let command = reader.u32().expect("command");
        if command & 0xFFFF == TPM_CC_STARTUP {
            found_startup = true;
        }
    }
    assert!(found_startup);

    let mut handle_params = Vec::new();
    handle_params.extend_from_slice(&TPM_CAP_HANDLES.to_be_bytes());
    handle_params.extend_from_slice(&0x8000_0000u32.to_be_bytes());
    handle_params.extend_from_slice(&8u32.to_be_bytes());
    let handles = run(
        &mut tpm,
        &command(
            TPM_ST_NO_SESSIONS,
            TPM_CC_GET_CAPABILITY,
            &[],
            &handle_params,
            &[],
        ),
    );
    assert_eq!(rc(&handles), TPM_RC_SUCCESS);
    let mut handle_reader = Reader::new(&handles[10..]);
    assert_eq!(handle_reader.u8().expect("moreData"), 0);
    assert_eq!(handle_reader.u32().expect("handle count"), 0);

    let mut unknown_params = Vec::new();
    unknown_params.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    unknown_params.extend_from_slice(&0u32.to_be_bytes());
    unknown_params.extend_from_slice(&1u32.to_be_bytes());
    let unknown = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_GET_CAPABILITY,
        &[],
        &unknown_params,
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &unknown)), rc_parameter(TPM_RC_VALUE, 1));
}

#[test]
fn get_random_rejects_oversized_request_and_returns_exact_zero_length() {
    let mut tpm = started_tpm();
    let too_many = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &(MAX_DIGEST_SIZE as u16 + 1).to_be_bytes(),
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &too_many)), rc_parameter(TPM_RC_VALUE, 1));
    let zero = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &0u16.to_be_bytes(),
        &[],
    );
    let response = run(&mut tpm, &zero);
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    assert_eq!(&response[10..], &[0, 0]);
}

#[test]
fn stir_random_rejects_oversized_entropy_and_changes_the_next_output() {
    let mut tpm = started_tpm();
    let get_random = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &32u16.to_be_bytes(),
        &[],
    );
    let first = run(&mut tpm, &get_random).split_off(10);
    assert_eq!(first.len(), 34);

    let mut stir = tpm2b(&[0x5A; 16]);
    let response = run(
        &mut tpm,
        &command(TPM_ST_NO_SESSIONS, TPM_CC_STIR_RANDOM, &[], &stir, &[]),
    );
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let second = run(&mut tpm, &get_random).split_off(10);
    assert_ne!(first, second);

    stir = tpm2b(&[0xA5; 129]);
    assert_eq!(
        rc(&run(
            &mut tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_STIR_RANDOM, &[], &stir, &[]),
        )),
        TPM_RC_SIZE
    );
}

#[test]
fn startup_shutdown_state_machine_rejects_out_of_order_calls() {
    let mut tpm = started_tpm();
    assert_eq!(rc(&run(&mut tpm, &startup())), TPM_RC_INITIALIZE);
    let bad_self_test = command(TPM_ST_NO_SESSIONS, TPM_CC_SELF_TEST, &[], &[2], &[]);
    assert_eq!(
        rc(&run(&mut tpm, &bad_self_test)),
        rc_parameter(TPM_RC_VALUE, 1)
    );
    let full_self_test = command(TPM_ST_NO_SESSIONS, TPM_CC_SELF_TEST, &[], &[1], &[]);
    assert_eq!(rc(&run(&mut tpm, &full_self_test)), TPM_RC_SUCCESS);
    let mut shutdown_params = Vec::new();
    shutdown_params.extend_from_slice(&TPM_SU_CLEAR.to_be_bytes());
    let shutdown = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_SHUTDOWN,
        &[],
        &shutdown_params,
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &shutdown)), TPM_RC_SUCCESS);
    let get_random = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &8u16.to_be_bytes(),
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &get_random)), TPM_RC_INITIALIZE);
}

// ---------------------------------------------------------------------------
// TBS adapter
// ---------------------------------------------------------------------------

#[test]
fn tbs_context_lifecycle_and_buffer_errors_are_exact() {
    let mut adapter = TbsAdapter::new(Tpm::new_with_seed([0x99; 32]));
    let mut context = 0u64;
    assert_eq!(
        adapter.tbsi_context_create(&TbsContextParams::v1(), &mut context),
        TBS_SUCCESS
    );
    assert_ne!(context, 0);

    let startup_command = startup();
    let needed = startup_command.len() + 64;
    let mut response = vec![0u8; needed];
    let mut size = needed as u32;
    assert_eq!(
        adapter.tbsip_submit_command(
            context,
            0,
            TbsPriority::Normal.as_u32(),
            &startup_command,
            &mut response,
            &mut size,
        ),
        TBS_SUCCESS
    );
    assert_eq!(response_code(&response[..size as usize]), TPM_RC_SUCCESS);

    let mut tiny = [0u8; 4];
    let mut tiny_size = tiny.len() as u32;
    assert_eq!(
        adapter.tbsip_submit_command(
            context,
            0,
            TbsPriority::Normal.as_u32(),
            &startup_command,
            &mut tiny,
            &mut tiny_size,
        ),
        TBS_E_INSUFFICIENT_BUFFER
    );
    assert!(tiny_size as usize >= 10);

    assert_eq!(adapter.tbsip_context_close(context), TBS_SUCCESS);
    assert_eq!(adapter.tbsip_context_close(context), TBS_E_INVALID_CONTEXT);
}

#[test]
fn tbs_rejects_bad_locality_priority_and_context() {
    let mut adapter = TbsAdapter::new(Tpm::new_with_seed([0x22; 32]));
    let mut context = 0u64;
    assert_eq!(
        adapter.tbsi_context_create(&TbsContextParams::v1(), &mut context),
        TBS_SUCCESS
    );
    let startup_command = startup();
    let mut response = [0u8; 64];
    let mut size = response.len() as u32;
    assert_eq!(
        adapter.tbsip_submit_command(
            context,
            5,
            TbsPriority::Normal.as_u32(),
            &startup_command,
            &mut response,
            &mut size,
        ),
        TBS_E_BAD_PARAMETER
    );
    assert_eq!(
        adapter.tbsip_submit_command(context, 0, 999, &startup_command, &mut response, &mut size,),
        TBS_E_BAD_PARAMETER
    );
    assert_eq!(
        adapter.tbsip_submit_command(
            999,
            0,
            TbsPriority::Normal.as_u32(),
            &startup_command,
            &mut response,
            &mut size,
        ),
        TBS_E_INVALID_CONTEXT
    );

    let mut invalid_params = TbsContextParams {
        version: 99,
        flags: 0,
    };
    let mut ignored = 0u64;
    assert_eq!(
        adapter.tbsi_context_create(&invalid_params, &mut ignored),
        TBS_E_INVALID_CONTEXT_PARAM
    );
    invalid_params.version = TBS_CONTEXT_VERSION_ONE;
    invalid_params.flags = 1;
    assert_eq!(
        adapter.tbsi_context_create(&invalid_params, &mut ignored),
        TBS_E_INVALID_CONTEXT_PARAM
    );

    let oversized = vec![0u8; MAX_COMMAND_SIZE + 1];
    assert_eq!(
        adapter.tbsip_submit_command(
            context,
            0,
            TbsPriority::Normal.as_u32(),
            &oversized,
            &mut response,
            &mut size,
        ),
        TBS_E_BUFFER_TOO_LARGE
    );
    assert_eq!(TbsError::Io.code(), super::tbs::TBS_E_IOERROR);
}

// ---------------------------------------------------------------------------
// Coverage: primitives, wire, state, persistence
// ---------------------------------------------------------------------------

fn nv_entry(index: u32) -> NvPersisted {
    NvPersisted {
        index,
        name_alg: TPM_ALG_SHA256,
        attributes: TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD,
        auth_policy: Vec::new(),
        data_size: 8,
        auth: Vec::new(),
        data: Vec::new(),
        written: false,
        write_locked: false,
        read_locked: false,
    }
}

#[test]
fn crypto_rejects_unknown_hash_and_pads_short_moduli_exactly() {
    assert_eq!(super::crypto::hash(TPM_ALG_SHA1, b"abc").unwrap().len(), 20);
    assert_eq!(
        super::crypto::hash(TPM_ALG_SHA256, b"abc").unwrap().len(),
        32
    );
    assert_eq!(
        super::crypto::hash(TPM_ALG_SHA384, b"abc").unwrap().len(),
        48
    );
    assert_eq!(
        super::crypto::hash(TPM_ALG_SHA512, b"abc").unwrap().len(),
        64
    );
    assert_eq!(super::crypto::hash(TPM_ALG_ERROR, b"abc"), None);
    assert_eq!(super::crypto::hash_len(TPM_ALG_SHA1), Some(20));
    assert_eq!(super::crypto::hash_len(TPM_ALG_SHA256), Some(32));
    assert_eq!(super::crypto::hash_len(TPM_ALG_SHA384), Some(48));
    assert_eq!(super::crypto::hash_len(TPM_ALG_SHA512), Some(64));
    assert_eq!(super::crypto::hash_len(TPM_ALG_ERROR), None);
    assert_eq!(
        super::constants::is_session_handle(SESSION_HANDLE_BASE),
        true
    );
    assert_eq!(super::constants::is_session_handle(TPM_RH_OWNER), false);

    let key = rsa_from_seed(&[0x11; 32], 1024).expect("rsa key");
    let padded = rsa_modulus(&key, 2048);
    assert_eq!(padded.len(), 256);
    assert_eq!(&padded[..128], &[0u8; 128]);

    assert_eq!(Writer::default().into_vec(), Vec::<u8>::new());
    let overflow = super::wire::session_response(0, &[], &[0u8; MAX_RESPONSE_SIZE], &[]);
    assert_eq!(overflow.len(), 10);
    assert_eq!(rc(&overflow), TPM_RC_SIZE);
}

#[test]
fn state_hierarchy_roles_and_public_area_reject_invalid_encodings() {
    let mut state = PersistedState::fresh([0x31; 32]);
    assert_eq!(
        Hierarchy::from_handle(TPM_RH_PLATFORM),
        Some(Hierarchy::Platform)
    );
    assert_eq!(Hierarchy::Endorsement.handle(), TPM_RH_ENDORSEMENT);
    assert_eq!(Hierarchy::Lockout.handle(), TPM_RH_LOCKOUT);
    assert_eq!(Hierarchy::Platform.handle(), TPM_RH_PLATFORM);
    assert_eq!(Hierarchy::Endorsement.seed(&state), state.endorsement_seed);
    assert_eq!(Hierarchy::Lockout.seed(&state), state.lockout_seed);
    assert_eq!(Hierarchy::Platform.seed(&state), state.platform_seed);
    assert_eq!(
        Hierarchy::Endorsement.auth(&state),
        state.endorsement_auth.as_slice()
    );
    assert_eq!(
        Hierarchy::Lockout.auth(&state),
        state.lockout_auth.as_slice()
    );
    assert_eq!(
        Hierarchy::Platform.auth(&state),
        state.platform_auth.as_slice()
    );
    *Hierarchy::Endorsement.auth_mut(&mut state) = b"endorsement".to_vec();
    *Hierarchy::Lockout.auth_mut(&mut state) = b"lockout".to_vec();
    *Hierarchy::Platform.auth_mut(&mut state) = b"platform".to_vec();
    assert_eq!(state.endorsement_auth, b"endorsement");
    assert_eq!(state.lockout_auth, b"lockout");
    assert_eq!(state.platform_auth, b"platform");

    let invalid_name = rsa_public_raw(
        TPM_ALG_ERROR,
        default_signing_attributes(),
        None,
        Some((TPM_ALG_RSASSA, TPM_ALG_SHA256)),
        1024,
        0,
        &[],
    );
    assert_eq!(PublicArea::parse(&invalid_name).unwrap_err(), TPM_RC_HASH);

    let rsa_symmetric = rsa_public_raw(
        TPM_ALG_SHA256,
        default_signing_attributes(),
        Some((TPM_ALG_AES, 128, TPM_ALG_NULL)),
        Some((TPM_ALG_RSASSA, TPM_ALG_SHA256)),
        1024,
        0,
        &[],
    );
    assert!(PublicArea::parse(&rsa_symmetric).is_ok());

    let rsa_null_scheme = rsa_public_raw(
        TPM_ALG_SHA256,
        default_signing_attributes(),
        None,
        None,
        1024,
        0,
        &[],
    );
    let parsed = PublicArea::parse(&rsa_null_scheme).expect("rsa null scheme");
    assert_eq!(parsed.scheme, TPM_ALG_NULL);
    assert_eq!(parsed.scheme_hash, 0);

    let ecc_symmetric = ecc_public_raw(
        TPM_ALG_SHA256,
        default_signing_attributes(),
        Some((TPM_ALG_AES, 128, TPM_ALG_NULL)),
        Some((TPM_ALG_ECDSA, TPM_ALG_SHA256)),
        TPM_ECC_NIST_P256,
        None,
        &[],
        &[],
    );
    assert!(PublicArea::parse(&ecc_symmetric).is_ok());

    let ecc_null_scheme = ecc_public_raw(
        TPM_ALG_SHA256,
        default_signing_attributes(),
        None,
        None,
        TPM_ECC_NIST_P256,
        None,
        &[],
        &[],
    );
    let parsed = PublicArea::parse(&ecc_null_scheme).expect("ecc null scheme");
    assert_eq!(parsed.scheme_hash, 0);

    let ecc_kdf = ecc_public_raw(
        TPM_ALG_SHA256,
        default_signing_attributes(),
        None,
        Some((TPM_ALG_ECDSA, TPM_ALG_SHA256)),
        TPM_ECC_NIST_P256,
        Some((TPM_ALG_SHA256, TPM_ALG_SHA256)),
        &[],
        &[],
    );
    assert!(PublicArea::parse(&ecc_kdf).is_ok());

    let mut unsupported = Vec::new();
    unsupported.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
    unsupported.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    unsupported.extend_from_slice(&0u32.to_be_bytes());
    unsupported.extend_from_slice(&tpm2b(&[]));
    assert_eq!(PublicArea::parse(&unsupported).unwrap_err(), TPM_RC_TYPE);

    let nv = NvIndex::from_persisted(nv_entry(0x0150_0100));
    let public = nv.nv_public();
    let mut reader = Reader::new(&public);
    let raw = reader.tpm2b(1024).expect("nv public");
    assert_eq!(raw.len(), 4 + 2 + 4 + 2 + 2);
    assert_eq!(NvIndex::is_valid_index(0x0150_0100), true);
}

#[test]
fn persistence_validation_rejects_each_invalid_state_shape() {
    let fresh = || PersistedState::fresh([0x41; 32]);

    let mut state = fresh();
    state.format = 0;
    assert_eq!(state.validate(), Err(Corruption::StateVersion(0)));

    let mut state = fresh();
    state.pcrs.pop();
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidPcrCount(PCR_COUNT - 1))
    );

    let mut state = fresh();
    state.owner_auth = vec![0u8; MAX_DIGEST_SIZE + 1];
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidAuth(MAX_DIGEST_SIZE + 1))
    );

    let mut state = fresh();
    state.nv = (0..=MAX_NV_INDICES as u32)
        .map(|index| nv_entry(0x0150_0000 + index))
        .collect();
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidNvCount(MAX_NV_INDICES + 1))
    );

    let mut state = fresh();
    state.nv = vec![nv_entry(0x0000_0001)];
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidNvIndex(0x0000_0001))
    );

    let mut state = fresh();
    state.nv = vec![nv_entry(0x0150_0001), nv_entry(0x0150_0001)];
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidNvIndex(0x0150_0001))
    );

    let mut state = fresh();
    let mut entry = nv_entry(0x0150_0002);
    entry.data_size = 0;
    state.nv = vec![entry];
    assert_eq!(state.validate(), Err(Corruption::InvalidNvSize(0)));

    let mut state = fresh();
    let mut entry = nv_entry(0x0150_0003);
    entry.data_size = MAX_NV_SIZE as u16 + 1;
    state.nv = vec![entry];
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidNvSize(MAX_NV_SIZE as u16 + 1))
    );

    let mut state = fresh();
    let mut entry = nv_entry(0x0150_0004);
    entry.data = vec![0u8; entry.data_size as usize + 1];
    state.nv = vec![entry];
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidNvData {
            data: state.nv[0].data.len(),
            size: state.nv[0].data_size,
        })
    );

    let mut state = fresh();
    let mut entry = nv_entry(0x0150_0005);
    entry.auth = vec![0u8; MAX_DIGEST_SIZE + 1];
    state.nv = vec![entry];
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidAuth(MAX_DIGEST_SIZE + 1))
    );

    let mut state = fresh();
    let mut entry = nv_entry(0x0150_0006);
    entry.name_alg = TPM_ALG_ERROR;
    state.nv = vec![entry];
    assert_eq!(
        state.validate(),
        Err(Corruption::InvalidNameAlg(TPM_ALG_ERROR))
    );

    assert_eq!(format!("{}", Corruption::BadMagic), "BadMagic");
    assert_eq!(
        format!("{}", PersistError::Corrupt(Corruption::BadMagic)),
        "tpm state corrupt: BadMagic"
    );
    assert_eq!(
        format!("{}", PersistError::Io(std::io::ErrorKind::PermissionDenied)),
        "tpm state I/O error: PermissionDenied"
    );
}

#[test]
fn persistence_decode_io_and_atomic_cleanup_reject_bad_envelopes() {
    let state = PersistedState::fresh([0x51; 32]);
    let encoded = super::persist::encode(&state).expect("encode");
    let mut bad_magic = encoded.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        super::persist::decode(&bad_magic).unwrap_err(),
        PersistError::Corrupt(Corruption::BadMagic)
    );
    let mut bad_length = encoded.clone();
    let payload_len = (encoded.len() - 20 - 32) as u64;
    bad_length[12..20].copy_from_slice(&(payload_len + 1).to_be_bytes());
    assert_eq!(
        super::persist::decode(&bad_length).unwrap_err(),
        PersistError::Corrupt(Corruption::LengthMismatch {
            declared: payload_len + 1,
            actual: payload_len,
        })
    );

    let directory = tempfile::tempdir().expect("tempdir");
    let as_directory = directory.path().join("directory");
    fs::create_dir(&as_directory).expect("directory");
    match super::persist::load(&as_directory) {
        Err(PersistError::Io(kind)) => {
            assert_eq!(kind, std::io::ErrorKind::IsADirectory)
        }
        other => panic!("unexpected load result: {other:?}"),
    }

    let target = directory.path().join("blocked.bin");
    fs::create_dir(&target).expect("blocking directory");
    let error = super::persist::save(&target, &state).expect_err("rename over directory");
    assert_eq!(matches!(error, PersistError::Io(_)), true);
    let leftovers: Vec<String> = fs::read_dir(directory.path())
        .expect("read dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".blocked.bin.tmp."))
        .collect();
    assert_eq!(leftovers, Vec::<String>::new());
}

#[test]
fn session_authorize_rejects_each_malformed_auth_shape() {
    let mut tpm = Tpm::new_with_seed([0x61; 32]);
    let owner = AuthTarget::Hierarchy(Hierarchy::Owner);
    let pw = AuthCommand {
        handle: TPM_RS_PW,
        nonce: Vec::new(),
        attributes: 0,
        hmac: Vec::new(),
    };

    assert_eq!(
        session::authorize(&mut tpm, TPM_CC_GET_RANDOM, &[], &[], &[], &[owner]).unwrap_err(),
        TPM_RC_AUTH_MISSING
    );
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_GET_RANDOM,
            &[],
            &[],
            std::slice::from_ref(&pw),
            &[]
        )
        .unwrap_err(),
        TPM_RC_AUTHSIZE
    );
    assert_eq!(
        session::authorize(&mut tpm, TPM_CC_GET_RANDOM, &[], &[], &[], &[]).unwrap(),
        Vec::new()
    );

    let mut nonce_pw = pw.clone();
    nonce_pw.nonce = vec![0u8; 16];
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_GET_RANDOM,
            &[TPM_RH_OWNER],
            &[],
            std::slice::from_ref(&nonce_pw),
            &[owner]
        )
        .unwrap_err(),
        TPM_RC_SIZE
    );

    let mut attributed_pw = pw.clone();
    attributed_pw.attributes = 1;
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_GET_RANDOM,
            &[TPM_RH_OWNER],
            &[],
            std::slice::from_ref(&attributed_pw),
            &[owner]
        )
        .unwrap_err(),
        TPM_RC_ATTRIBUTES
    );

    let mut wrong_pw = pw.clone();
    wrong_pw.hmac = b"wrong".to_vec();
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_GET_RANDOM,
            &[TPM_RH_OWNER],
            &[],
            std::slice::from_ref(&wrong_pw),
            &[owner]
        )
        .unwrap_err(),
        TPM_RC_BAD_AUTH
    );

    let missing = AuthCommand {
        handle: SESSION_HANDLE_BASE + 99,
        nonce: vec![1u8; 16],
        attributes: 0,
        hmac: Vec::new(),
    };
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_GET_RANDOM,
            &[TPM_RH_OWNER],
            &[],
            std::slice::from_ref(&missing),
            &[owner]
        )
        .unwrap_err(),
        rc_session(TPM_RC_HANDLE, 1)
    );

    let nonce_tpm = [0x71u8; 32];
    let session_key = [0x72u8; 32];
    let handle = tpm
        .insert_session(nonce_tpm, session_key, TPM_ALG_SHA256, TPM_RH_NULL)
        .expect("session");
    let empty_nonce = AuthCommand {
        handle,
        nonce: Vec::new(),
        attributes: 0,
        hmac: Vec::new(),
    };
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_GET_RANDOM,
            &[TPM_RH_OWNER],
            &[],
            std::slice::from_ref(&empty_nonce),
            &[owner]
        )
        .unwrap_err(),
        TPM_RC_SIZE
    );

    let encrypted = AuthCommand {
        handle,
        nonce: vec![3u8; 16],
        attributes: 0x40,
        hmac: Vec::new(),
    };
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_GET_RANDOM,
            &[TPM_RH_OWNER],
            &[],
            std::slice::from_ref(&encrypted),
            &[owner]
        )
        .unwrap_err(),
        TPM_RC_ATTRIBUTES
    );

    let code = TPM_CC_GET_RANDOM;
    let owner_name = TPM_RH_OWNER.to_be_bytes().to_vec();
    let cp = session::cp_hash(code, &[owner_name.clone(), owner_name], &[]);
    let nonce = vec![4u8; 16];
    let valid = AuthCommand {
        handle,
        nonce: nonce.clone(),
        attributes: 0,
        hmac: session::auth_hmac(&session_key, &cp, &nonce, &nonce_tpm, 0).to_vec(),
    };
    let duplicated = vec![valid.clone(), valid];
    assert_eq!(
        session::authorize(
            &mut tpm,
            code,
            &[TPM_RH_OWNER, TPM_RH_OWNER],
            &[],
            &duplicated,
            &[owner, owner]
        )
        .unwrap_err(),
        rc_session(TPM_RC_HANDLE, 2)
    );

    let nv_index = 0x0150_0200;
    tpm.state.nv.push(nv_entry(nv_index));
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_NV_READ,
            &[nv_index],
            &[],
            std::slice::from_ref(&pw),
            &[AuthTarget::Nv(nv_index)]
        )
        .unwrap()
        .len(),
        0
    );
    let missing_nv = 0x0150_0999;
    assert_eq!(
        session::authorize(
            &mut tpm,
            TPM_CC_NV_READ,
            &[missing_nv],
            &[],
            std::slice::from_ref(&pw),
            &[AuthTarget::Nv(missing_nv)]
        )
        .unwrap()
        .len(),
        0
    );
}

#[test]
fn tpm_accessors_and_capacity_exhaustion_are_exact() {
    let tpm = Tpm::new();
    assert_eq!(tpm.state_path(), None);
    assert_eq!(tpm.is_started(), false);
    assert!(tpm.session_handles().is_empty());
    assert_eq!(tpm.pcr(PCR_COUNT), None);
    assert_eq!(tpm.pcr_update_counter(), 0);
    assert_eq!(format!("{:?}", tpm).contains("Tpm"), true);
    assert_eq!(Tpm::default().is_started(), false);
    assert_eq!(
        format!(
            "{}",
            TpmError::Persist(PersistError::Corrupt(Corruption::BadMagic))
        ),
        "tpm state corrupt: BadMagic"
    );

    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("state.bin");
    let opened = Tpm::open(&path).expect("open");
    assert_eq!(opened.state_path(), Some(path.as_path()));

    let template = PublicArea::parse(&ecc_template()).expect("template");
    let mut tpm = Tpm::new_with_seed([0x81; 32]);
    for counter in 0..MAX_TRANSIENT_OBJECTS {
        let key = KeyMaterial::Ecc(ecc_from_seed(&[counter as u8; 32]));
        tpm.insert_object(template.clone(), Vec::new(), key, [0u8; 32])
            .expect("object");
    }
    let key = KeyMaterial::Ecc(ecc_from_seed(&[0xFF; 32]));
    assert_eq!(
        tpm.insert_object(template.clone(), Vec::new(), key, [0u8; 32])
            .unwrap_err(),
        TPM_RC_INSUFFICIENT
    );

    let mut tpm = Tpm::new_with_seed([0x82; 32]);
    let key = KeyMaterial::Ecc(ecc_from_seed(&[1u8; 32]));
    tpm.next_object = TRANSIENT_HANDLE_LAST;
    assert_eq!(
        tpm.insert_object(template.clone(), Vec::new(), key, [0u8; 32])
            .unwrap(),
        TRANSIENT_HANDLE_LAST
    );
    tpm.next_object = TRANSIENT_HANDLE_LAST;
    let key = KeyMaterial::Ecc(ecc_from_seed(&[2u8; 32]));
    assert_eq!(
        tpm.insert_object(template.clone(), Vec::new(), key, [0u8; 32])
            .unwrap(),
        TRANSIENT_HANDLE_BASE
    );

    let mut tpm = Tpm::new_with_seed([0x85; 32]);
    let key = KeyMaterial::Ecc(ecc_from_seed(&[3u8; 32]));
    tpm.next_object = TRANSIENT_HANDLE_BASE;
    assert_eq!(
        tpm.insert_object(template.clone(), Vec::new(), key, [0u8; 32])
            .unwrap(),
        TRANSIENT_HANDLE_BASE
    );
    tpm.next_object = TRANSIENT_HANDLE_BASE;
    let key = KeyMaterial::Ecc(ecc_from_seed(&[4u8; 32]));
    assert_eq!(
        tpm.insert_object(template.clone(), Vec::new(), key, [0u8; 32])
            .unwrap(),
        TRANSIENT_HANDLE_BASE + 1
    );

    let mut tpm = Tpm::new_with_seed([0x83; 32]);
    for _ in 0..MAX_SESSIONS {
        tpm.insert_session([0u8; 32], [0u8; 32], TPM_ALG_SHA256, TPM_RH_NULL)
            .expect("session");
    }
    assert_eq!(
        tpm.insert_session([0u8; 32], [0u8; 32], TPM_ALG_SHA256, TPM_RH_NULL)
            .unwrap_err(),
        TPM_RC_INSUFFICIENT
    );

    let mut tpm = Tpm::new_with_seed([0x84; 32]);
    tpm.next_session = SESSION_HANDLE_BASE + 0x00FF_FFFF;
    assert_eq!(
        tpm.insert_session([0u8; 32], [0u8; 32], TPM_ALG_SHA256, TPM_RH_NULL)
            .unwrap(),
        SESSION_HANDLE_BASE + 0x00FF_FFFF
    );
    tpm.next_session = SESSION_HANDLE_BASE + 0x00FF_FFFF;
    assert_eq!(
        tpm.insert_session([0u8; 32], [0u8; 32], TPM_ALG_SHA256, TPM_RH_NULL)
            .unwrap(),
        SESSION_HANDLE_BASE
    );
    assert_eq!(tpm.session_handles().len(), 2);
}

#[test]
fn tbs_parameters_priorities_and_error_codes_are_exact() {
    assert_eq!(
        TbsContextParams::v2(3).version,
        super::tbs::TBS_CONTEXT_VERSION_TWO
    );
    assert_eq!(TbsContextParams::v2(3).flags, 3);
    assert_eq!(TbsPriority::from_u32(200), Some(TbsPriority::High));
    assert_eq!(TbsPriority::from_u32(300), Some(TbsPriority::System));
    assert_eq!(
        TbsPriority::from_u32(0x8000_0000),
        Some(TbsPriority::Maximum)
    );
    assert_eq!(TbsPriority::from_u32(1), None);
    assert_eq!(TbsPriority::High.as_u32(), 200);
    assert_eq!(TbsPriority::System.as_u32(), 300);
    assert_eq!(TbsPriority::Maximum.as_u32(), 0x8000_0000);

    let codes = [
        (TbsError::Internal, super::tbs::TBS_E_INTERNAL_ERROR),
        (TbsError::BadParameter, TBS_E_BAD_PARAMETER),
        (
            TbsError::InvalidOutputPointer,
            super::tbs::TBS_E_INVALID_OUTPUT_POINTER,
        ),
        (TbsError::InvalidContext, TBS_E_INVALID_CONTEXT),
        (TbsError::InsufficientBuffer, TBS_E_INSUFFICIENT_BUFFER),
        (TbsError::Io, super::tbs::TBS_E_IOERROR),
        (TbsError::InvalidContextParam, TBS_E_INVALID_CONTEXT_PARAM),
        (
            TbsError::ServiceNotRunning,
            super::tbs::TBS_E_SERVICE_NOT_RUNNING,
        ),
        (
            TbsError::TooManyContexts,
            super::tbs::TBS_E_TOO_MANY_TBS_CONTEXTS,
        ),
        (
            TbsError::TooManyResources,
            super::tbs::TBS_E_TOO_MANY_RESOURCES,
        ),
        (TbsError::BufferTooLarge, TBS_E_BUFFER_TOO_LARGE),
        (TbsError::TpmNotFound, super::tbs::TBS_E_TPM_NOT_FOUND),
        (TbsError::AccessDenied, super::tbs::TBS_E_ACCESS_DENIED),
    ];
    for (error, code) in codes {
        assert_eq!(error.code(), code);
    }
    assert_eq!(
        format!("{}", TbsError::AccessDenied),
        "TBS error 0x80284012"
    );
    assert_eq!(response_code(&[0u8; 9]), TPM_RC_SIZE);
}

#[test]
fn tbs_context_limit_and_malformed_submit_are_exact() {
    let mut adapter = TbsAdapter::new(Tpm::new_with_seed([0x91; 32]));
    assert_eq!(adapter.tpm().pcr(0).is_some(), true);
    assert_eq!(adapter.tpm_mut().is_started(), false);

    let mut first = 0u64;
    assert_eq!(
        adapter.tbsi_context_create(&TbsContextParams::v1(), &mut first),
        TBS_SUCCESS
    );
    for _ in 1..16 {
        let mut context = 0u64;
        assert_eq!(
            adapter.tbsi_context_create(&TbsContextParams::v2(0), &mut context),
            TBS_SUCCESS
        );
    }
    let mut overflow = 0u64;
    assert_eq!(
        adapter.tbsi_context_create(&TbsContextParams::v1(), &mut overflow),
        super::tbs::TBS_E_TOO_MANY_TBS_CONTEXTS
    );

    let startup_command = startup();
    let mut tiny = [0u8; 4];
    assert_eq!(
        adapter
            .submit_command(first, 0, TbsPriority::Normal, &startup_command, &mut tiny)
            .unwrap_err(),
        TbsError::InsufficientBuffer
    );

    let mut response = [0u8; 64];
    assert_eq!(
        adapter
            .submit_command(
                first,
                0,
                TbsPriority::Normal,
                b"\x80\x01\x00",
                &mut response
            )
            .unwrap_err(),
        TbsError::BadParameter
    );
}

#[test]
fn tbs_open_and_submit_map_persist_errors_to_exact_codes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("environment");
    let adapter = TbsAdapter::open_environment(&root).expect("open environment");
    assert_eq!(
        adapter.tpm().state_path(),
        Some(root.join("tpm2").join("state.bin").as_path())
    );

    let corrupt_root = directory.path().join("corrupt");
    fs::create_dir_all(corrupt_root.join("tpm2")).expect("corrupt dirs");
    fs::write(corrupt_root.join("tpm2").join("state.bin"), b"CASA1TPM").expect("corrupt file");
    assert_eq!(
        TbsAdapter::open_environment(&corrupt_root)
            .err()
            .expect("corrupt")
            .code(),
        super::tbs::TBS_E_INTERNAL_ERROR
    );

    let io_root = directory.path().join("io");
    fs::create_dir_all(&io_root).expect("io root");
    fs::write(io_root.join("tpm2"), b"not a directory").expect("blocking file");
    assert_eq!(
        TbsAdapter::open_environment(&io_root)
            .err()
            .expect("io")
            .code(),
        super::tbs::TBS_E_IOERROR
    );

    let state_dir = directory.path().join("submit");
    fs::create_dir_all(&state_dir).expect("submit dir");
    let path = state_dir.join("state.bin");
    let mut adapter = TbsAdapter::new(Tpm::open(&path).expect("open tpm"));
    let mut context = 0u64;
    assert_eq!(
        adapter.tbsi_context_create(&TbsContextParams::v1(), &mut context),
        TBS_SUCCESS
    );
    fs::create_dir(&path).expect("block state file");
    let startup_command = startup();
    let mut response = [0u8; 64];
    let mut size = response.len() as u32;
    assert_eq!(
        adapter.tbsip_submit_command(
            context,
            0,
            TbsPriority::Normal.as_u32(),
            &startup_command,
            &mut response,
            &mut size,
        ),
        super::tbs::TBS_E_IOERROR
    );
}

fn get_capability(tpm: &mut Tpm, capability: u32, property: u32, count: u32) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&capability.to_be_bytes());
    params.extend_from_slice(&property.to_be_bytes());
    params.extend_from_slice(&count.to_be_bytes());
    run(
        tpm,
        &command(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY, &[], &params, &[]),
    )
}

fn start_auth_session(tpm: &mut Tpm, nonce: &[u8]) -> u32 {
    let mut params = Vec::new();
    params.extend_from_slice(&tpm2b(nonce));
    params.extend_from_slice(&tpm2b(&[]));
    params.push(TPM_SE_HMAC);
    params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let response = run(
        tpm,
        &command(
            TPM_ST_NO_SESSIONS,
            TPM_CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, TPM_RH_NULL],
            &params,
            &[],
        ),
    );
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    u32::from_be_bytes([response[10], response[11], response[12], response[13]])
}

fn nv_define_with_hierarchy(
    tpm: &mut Tpm,
    hierarchy: u32,
    index: u32,
    size: u16,
    attributes: u32,
) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&tpm2b(&[]));
    params.extend_from_slice(&tpm2b(&nv_public_with_attributes(index, size, attributes)));
    run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            TPM_CC_NV_DEFINE_SPACE,
            &[hierarchy],
            &params,
            &[password_entry(&[])],
        ),
    )
}

fn nv_read_public(tpm: &mut Tpm, index: u32) -> Vec<u8> {
    run(
        tpm,
        &command(
            TPM_ST_NO_SESSIONS,
            TPM_CC_NV_READ_PUBLIC,
            &[index],
            &[],
            &[],
        ),
    )
}

fn nv_undefine(tpm: &mut Tpm, auth_handle: u32, index: u32) -> Vec<u8> {
    run(
        tpm,
        &command(
            TPM_ST_SESSIONS,
            TPM_CC_NV_UNDEFINE_SPACE,
            &[auth_handle, index],
            &[],
            &[password_entry(&[])],
        ),
    )
}

#[test]
fn engine_capability_pcr_and_state_machine_reject_invalid_parameters() {
    let mut tpm = started_tpm();
    let (_first, _) = create_primary_ok(&mut tpm, &ecc_template());
    let (_second, _) = create_primary_ok(&mut tpm, &ecc_template());
    let session_handle = start_auth_session(&mut tpm, &[0x33; 32]);
    assert_eq!(rc(&nv_define(&mut tpm, 0x0150_0300, 8)), TPM_RC_SUCCESS);

    let properties = get_capability(&mut tpm, TPM_CAP_TPM_PROPERTIES, 0, 1);
    assert_eq!(rc(&properties), TPM_RC_SUCCESS);
    assert_eq!(properties[10], 1);
    assert_eq!(
        u32::from_be_bytes([
            properties[11],
            properties[12],
            properties[13],
            properties[14]
        ]),
        1
    );

    let algorithms = get_capability(&mut tpm, TPM_CAP_ALGS, 0, 1);
    assert_eq!(rc(&algorithms), TPM_RC_SUCCESS);
    assert_eq!(algorithms[10], 1);
    assert_eq!(
        u32::from_be_bytes([
            algorithms[11],
            algorithms[12],
            algorithms[13],
            algorithms[14]
        ]),
        1
    );

    let commands = get_capability(&mut tpm, TPM_CAP_COMMANDS, 0, 1);
    assert_eq!(rc(&commands), TPM_RC_SUCCESS);
    assert_eq!(commands[10], 1);

    let transient = get_capability(&mut tpm, TPM_CAP_HANDLES, 0x8000_0000, 10);
    assert_eq!(rc(&transient), TPM_RC_SUCCESS);
    assert_eq!(
        u32::from_be_bytes([transient[11], transient[12], transient[13], transient[14]]),
        2
    );
    let persistent = get_capability(&mut tpm, TPM_CAP_HANDLES, 0x8100_0000, 10);
    assert_eq!(
        u32::from_be_bytes([
            persistent[11],
            persistent[12],
            persistent[13],
            persistent[14]
        ]),
        0
    );
    let sessions = get_capability(&mut tpm, TPM_CAP_HANDLES, 0x0200_0000, 10);
    assert_eq!(
        u32::from_be_bytes([sessions[11], sessions[12], sessions[13], sessions[14]]),
        1
    );
    assert_eq!(
        u32::from_be_bytes([sessions[15], sessions[16], sessions[17], sessions[18]]),
        session_handle
    );
    let nv = get_capability(&mut tpm, TPM_CAP_HANDLES, 0x0100_0000, 10);
    assert_eq!(u32::from_be_bytes([nv[11], nv[12], nv[13], nv[14]]), 1);
    let unknown_kind = get_capability(&mut tpm, TPM_CAP_HANDLES, 0x0000_0000, 10);
    assert_eq!(
        u32::from_be_bytes([
            unknown_kind[11],
            unknown_kind[12],
            unknown_kind[13],
            unknown_kind[14]
        ]),
        0
    );
    let zero = get_capability(&mut tpm, TPM_CAP_HANDLES, 0x8000_0000, 0);
    assert_eq!(
        u32::from_be_bytes([zero[11], zero[12], zero[13], zero[14]]),
        0
    );
    let truncated = get_capability(&mut tpm, TPM_CAP_HANDLES, 0x8000_0000, 1);
    assert_eq!(truncated[10], 1);
    assert_eq!(
        u32::from_be_bytes([truncated[11], truncated[12], truncated[13], truncated[14]]),
        1
    );

    let pcrs = get_capability(&mut tpm, TPM_CAP_PCRS, 0, 1);
    assert_eq!(
        u32::from_be_bytes([pcrs[11], pcrs[12], pcrs[13], pcrs[14]]),
        1
    );
    let no_pcrs = get_capability(&mut tpm, TPM_CAP_PCRS, 0, 0);
    assert_eq!(
        u32::from_be_bytes([no_pcrs[11], no_pcrs[12], no_pcrs[13], no_pcrs[14]]),
        0
    );
    let curves = get_capability(&mut tpm, TPM_CAP_ECC_CURVES, 0, 1);
    assert_eq!(
        u32::from_be_bytes([curves[11], curves[12], curves[13], curves[14]]),
        1
    );
    let no_curves = get_capability(&mut tpm, TPM_CAP_ECC_CURVES, 0, 0);
    assert_eq!(
        u32::from_be_bytes([no_curves[11], no_curves[12], no_curves[13], no_curves[14]]),
        0
    );
    assert_eq!(
        rc(&get_capability(&mut tpm, TPM_CAP_TPM_PROPERTIES, 0, 1025)),
        rc_parameter(TPM_RC_VALUE, 3)
    );

    let read = run(
        &mut tpm,
        &command(
            TPM_ST_NO_SESSIONS,
            TPM_CC_PCR_READ,
            &[],
            &pcr_selection(&[0]),
            &[],
        ),
    );
    assert_eq!(rc(&read), TPM_RC_SUCCESS);
    let mut reader = Reader::new(&read[10..]);
    assert_eq!(reader.u32().expect("counter"), 0);
    assert_eq!(reader.u32().expect("selection count"), 1);
    assert_eq!(reader.u16().expect("selection alg"), TPM_ALG_SHA256);
    let selection_size = reader.u8().expect("selection size");
    reader.bytes(selection_size as usize).expect("selection");
    assert_eq!(reader.u32().expect("digest count"), 1);
    assert_eq!(reader.tpm2b(64).expect("digest").len(), 32);

    let mut too_many = Vec::new();
    too_many.extend_from_slice(&17u32.to_be_bytes());
    assert_eq!(
        rc(&run(
            &mut tpm,
            &command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, &[], &too_many, &[],)
        )),
        TPM_RC_SIZE
    );
    let mut oversized_select = Vec::new();
    oversized_select.extend_from_slice(&1u32.to_be_bytes());
    oversized_select.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    oversized_select.push(5);
    oversized_select.extend_from_slice(&[0u8; 5]);
    assert_eq!(
        rc(&run(
            &mut tpm,
            &command(
                TPM_ST_NO_SESSIONS,
                TPM_CC_PCR_READ,
                &[],
                &oversized_select,
                &[],
            )
        )),
        TPM_RC_SIZE
    );

    for count in [0u32, 9] {
        let mut params = Vec::new();
        params.extend_from_slice(&count.to_be_bytes());
        assert_eq!(
            rc(&run(
                &mut tpm,
                &command(
                    TPM_ST_SESSIONS,
                    TPM_CC_PCR_EXTEND,
                    &[0],
                    &params,
                    &[password_entry(&[])],
                )
            )),
            rc_parameter(TPM_RC_VALUE, 1)
        );
    }

    let mut fresh = Tpm::new_with_seed([0x92; 32]);
    let bad_startup = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_STARTUP,
        &[],
        &2u16.to_be_bytes(),
        &[],
    );
    assert_eq!(
        rc(&run(&mut fresh, &bad_startup)),
        rc_parameter(TPM_RC_VALUE, 1)
    );
    let bad_shutdown = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_SHUTDOWN,
        &[],
        &2u16.to_be_bytes(),
        &[],
    );
    assert_eq!(
        rc(&run(&mut tpm, &bad_shutdown)),
        rc_parameter(TPM_RC_VALUE, 1)
    );
}

#[test]
fn engine_persist_failure_and_malformed_auth_areas_are_exact() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("state.bin");
    let mut tpm = Tpm::open(&path).expect("open tpm");
    fs::create_dir(&path).expect("block state path");
    let failure = tpm.execute(&startup(), 0);
    assert_eq!(matches!(failure, Err(PersistError::Io(_))), true);

    let mut tpm = started_tpm();
    let mut short_handles = Vec::new();
    short_handles.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    short_handles.extend_from_slice(&12u32.to_be_bytes());
    short_handles.extend_from_slice(&TPM_CC_CREATE_PRIMARY.to_be_bytes());
    short_handles.extend_from_slice(&[0, 0]);
    assert_eq!(rc(&run(&mut tpm, &short_handles)), TPM_RC_SIZE);

    let mut missing_auth_size = Vec::new();
    missing_auth_size.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    missing_auth_size.extend_from_slice(&12u32.to_be_bytes());
    missing_auth_size.extend_from_slice(&TPM_CC_GET_RANDOM.to_be_bytes());
    missing_auth_size.extend_from_slice(&8u16.to_be_bytes());
    assert_eq!(rc(&run(&mut tpm, &missing_auth_size)), TPM_RC_AUTHSIZE);

    let mut too_many_sessions = Vec::new();
    too_many_sessions.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    too_many_sessions.extend_from_slice(&20u32.to_be_bytes());
    too_many_sessions.extend_from_slice(&TPM_CC_GET_RANDOM.to_be_bytes());
    too_many_sessions.extend_from_slice(&8u16.to_be_bytes());
    too_many_sessions.extend_from_slice(&4u32.to_be_bytes());
    too_many_sessions.extend_from_slice(&(MAX_SESSIONS as u32 + 1).to_be_bytes());
    assert_eq!(rc(&run(&mut tpm, &too_many_sessions)), TPM_RC_AUTHSIZE);

    let rejected_sessions = command(
        TPM_ST_SESSIONS,
        TPM_CC_GET_RANDOM,
        &[],
        &8u16.to_be_bytes(),
        &[password_entry(&[])],
    );
    assert_eq!(rc(&run(&mut tpm, &rejected_sessions)), TPM_RC_AUTHSIZE);
}

#[test]
fn engine_template_validation_rejects_each_invalid_field() {
    let mut tpm = started_tpm();
    let cases = [
        (
            rsa_public_raw(
                TPM_ALG_SHA384,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_RSASSA, TPM_ALG_SHA256)),
                1024,
                0,
                &[],
            ),
            TPM_RC_HASH,
        ),
        (
            rsa_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_RSASSA, TPM_ALG_SHA256)),
                1024,
                0,
                &[0x01, 0x02],
            ),
            rc_parameter(TPM_RC_KEY, 2),
        ),
        (
            rsa_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_RSASSA, TPM_ALG_SHA256)),
                512,
                0,
                &[],
            ),
            rc_parameter(TPM_RC_KEY_SIZE, 2),
        ),
        (
            rsa_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_RSASSA, TPM_ALG_SHA256)),
                1024,
                3,
                &[],
            ),
            rc_parameter(TPM_RC_KEY, 2),
        ),
        (
            rsa_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_ECDSA, TPM_ALG_SHA256)),
                1024,
                0,
                &[],
            ),
            rc_parameter(TPM_RC_SCHEME, 2),
        ),
        (
            rsa_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_RSASSA, TPM_ALG_SHA1)),
                1024,
                0,
                &[],
            ),
            rc_parameter(TPM_RC_HASH, 2),
        ),
        (
            ecc_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_ECDSA, TPM_ALG_SHA256)),
                4,
                None,
                &[],
                &[],
            ),
            rc_parameter(TPM_RC_CURVE, 2),
        ),
        (
            ecc_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_RSASSA, TPM_ALG_SHA256)),
                TPM_ECC_NIST_P256,
                None,
                &[],
                &[],
            ),
            rc_parameter(TPM_RC_SCHEME, 2),
        ),
        (
            ecc_public_raw(
                TPM_ALG_SHA256,
                default_signing_attributes(),
                None,
                Some((TPM_ALG_ECDSA, TPM_ALG_SHA1)),
                TPM_ECC_NIST_P256,
                None,
                &[],
                &[],
            ),
            rc_parameter(TPM_RC_HASH, 2),
        ),
    ];
    for (template, expected) in cases {
        assert_eq!(rc(&create_primary(&mut tpm, &template, &[])), expected);
    }

    let mut template = PublicArea::parse(&ecc_template()).expect("ecc template");
    template.object_type = TPM_ALG_KEYEDHASH;
    assert_eq!(
        super::engine::validate_template(&template).unwrap_err(),
        rc_parameter(TPM_RC_TYPE, 2)
    );
    assert_eq!(
        super::engine::key_from_seed(&[0u8; 32], &template).err(),
        Some(TPM_RC_TYPE)
    );

    let mut out_of_range = Vec::new();
    out_of_range.extend_from_slice(&1u32.to_be_bytes());
    out_of_range.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out_of_range.push(4);
    out_of_range.extend_from_slice(&[0u8, 0, 0, 0x01]);
    assert_eq!(
        super::engine::selected_indices(&out_of_range, 1).unwrap_err(),
        rc_parameter(TPM_RC_VALUE, 1)
    );
}

#[test]
fn engine_quote_rejects_unsupported_schemes_and_non_signing_keys() {
    let mut tpm = started_tpm();
    let rsa_null = rsa_public_raw(
        TPM_ALG_SHA256,
        default_signing_attributes(),
        None,
        None,
        1024,
        0,
        &[],
    );
    let (rsa_handle, _) = create_primary_ok(&mut tpm, &rsa_null);
    assert_eq!(
        rc(&run(&mut tpm, &quote_command(rsa_handle, &[0]))),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &quote_command_with_scheme(rsa_handle, &[0], TPM_ALG_RSASSA, TPM_ALG_SHA256)
        )),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &quote_command_with_scheme(rsa_handle, &[0], TPM_ALG_RSASSA, TPM_ALG_SHA1)
        )),
        rc_parameter(TPM_RC_HASH, 2)
    );

    let ecc_null = ecc_public_raw(
        TPM_ALG_SHA256,
        default_signing_attributes(),
        None,
        None,
        TPM_ECC_NIST_P256,
        None,
        &[],
        &[],
    );
    let (ecc_handle, _) = create_primary_ok(&mut tpm, &ecc_null);
    assert_eq!(
        rc(&run(&mut tpm, &quote_command(ecc_handle, &[0]))),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &quote_command_with_scheme(ecc_handle, &[0], TPM_ALG_ECDSA, TPM_ALG_SHA256)
        )),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &quote_command_with_scheme(ecc_handle, &[0], TPM_ALG_RSASSA, TPM_ALG_SHA256)
        )),
        rc_parameter(TPM_RC_SCHEME, 2)
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &quote_command_with_scheme(ecc_handle, &[0], TPM_ALG_ECDSA, TPM_ALG_SHA1)
        )),
        rc_parameter(TPM_RC_HASH, 2)
    );

    let non_signing = ecc_public_raw(
        TPM_ALG_SHA256,
        TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_NO_DA,
        None,
        None,
        TPM_ECC_NIST_P256,
        None,
        &[],
        &[],
    );
    let (non_signing_handle, _) = create_primary_ok(&mut tpm, &non_signing);
    assert_eq!(
        rc(&run(&mut tpm, &quote_command(non_signing_handle, &[0]))),
        TPM_RC_ATTRIBUTES
    );
}

#[test]
fn engine_create_load_flush_and_read_public_errors_are_exact() {
    let mut tpm = started_tpm();
    let missing_parent = command(
        TPM_ST_SESSIONS,
        TPM_CC_CREATE,
        &[0x8000_FFFF],
        &[],
        &[password_entry(&[])],
    );
    assert_eq!(
        rc(&run(&mut tpm, &missing_parent)),
        rc_handle(TPM_RC_HANDLE, 1)
    );

    let (parent, _) = create_primary_ok(&mut tpm, &rsa_template(1024));
    assert_eq!(
        rc(&load_child(&mut tpm, parent, &[], &ecc_template())),
        TPM_RC_INTEGRITY
    );

    let (private, public) = create_child(&mut tpm, parent, &ecc_template());
    assert_eq!(&private[..4], b"CPK1");
    let child_seed: [u8; 32] = private[8..40].try_into().expect("child seed");
    let auth_len = u16::from_be_bytes([private[40], private[41]]) as usize;
    let auth = private[42..42 + auth_len].to_vec();
    let hash_start = 42 + auth_len;
    let public_hash: [u8; 32] = private[hash_start..hash_start + 32]
        .try_into()
        .expect("public hash");
    let parent_seed = tpm.objects.get(&parent).expect("parent").child_seed;
    let integrity_key = derive_seed(&parent_seed, b"casa1-tpm-private-integrity-v1");
    let build_private = |stored_parent: u32, stored_hash: &[u8; 32]| {
        let mut signed = Vec::new();
        signed.extend_from_slice(b"CPK1");
        signed.extend_from_slice(&stored_parent.to_be_bytes());
        signed.extend_from_slice(&child_seed);
        signed.extend_from_slice(&tpm2b(&auth));
        signed.extend_from_slice(stored_hash);
        let hmac = hmac_sha256(&integrity_key, &signed);
        signed.extend_from_slice(&hmac);
        signed
    };
    assert_eq!(
        rc(&load_child(
            &mut tpm,
            parent,
            &build_private(parent + 1, &public_hash),
            &public
        )),
        TPM_RC_INTEGRITY
    );
    assert_eq!(
        rc(&load_child(
            &mut tpm,
            parent,
            &build_private(parent, &[0u8; 32]),
            &public
        )),
        TPM_RC_INTEGRITY
    );

    let session_handle = start_auth_session(&mut tpm, &[0x44; 32]);
    assert_eq!(rc(&flush(&mut tpm, session_handle)), TPM_RC_SUCCESS);
    assert_eq!(tpm.session_handles().contains(&session_handle), false);

    let (read_handle, _) = create_primary_ok(&mut tpm, &ecc_template());
    let response = read_public(&mut tpm, read_handle);
    assert_eq!(rc(&response), TPM_RC_SUCCESS);
    let mut reader = Reader::new(&response[10..]);
    assert_ne!(reader.tpm2b(1024).expect("public").len(), 0);
    let first_name = reader.tpm2b(64).expect("name").to_vec();
    let second_name = reader.tpm2b(64).expect("qualified name").to_vec();
    assert_eq!(first_name, second_name);
}

#[test]
fn engine_nv_role_permission_and_lifecycle_reject_invalid_auth() {
    let mut tpm = started_tpm();
    let invalid_lockout = command(
        TPM_ST_SESSIONS,
        TPM_CC_NV_DEFINE_SPACE,
        &[TPM_RH_LOCKOUT],
        &[],
        &[password_entry(&[])],
    );
    assert_eq!(
        rc(&run(&mut tpm, &invalid_lockout)),
        rc_handle(TPM_RC_HIERARCHY, 1)
    );
    let invalid_endorsement = command(
        TPM_ST_SESSIONS,
        TPM_CC_NV_DEFINE_SPACE,
        &[TPM_RH_ENDORSEMENT],
        &[],
        &[password_entry(&[])],
    );
    assert_eq!(
        rc(&run(&mut tpm, &invalid_endorsement)),
        rc_handle(TPM_RC_HIERARCHY, 1)
    );
    let invalid_null = command(
        TPM_ST_SESSIONS,
        TPM_CC_NV_DEFINE_SPACE,
        &[TPM_RH_NULL],
        &[],
        &[password_entry(&[])],
    );
    assert_eq!(
        rc(&run(&mut tpm, &invalid_null)),
        rc_handle(TPM_RC_HIERARCHY, 1)
    );

    let invalid_hierarchy_auth = command(
        TPM_ST_SESSIONS,
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[TPM_RH_NULL],
        &tpm2b(b"x"),
        &[password_entry(&[])],
    );
    assert_eq!(
        rc(&run(&mut tpm, &invalid_hierarchy_auth)),
        rc_handle(TPM_RC_HIERARCHY, 1)
    );

    let invalid_name_index = 0x0150_0401u32;
    let mut invalid_name_public = Vec::new();
    invalid_name_public.extend_from_slice(&invalid_name_index.to_be_bytes());
    invalid_name_public.extend_from_slice(&TPM_ALG_SHA384.to_be_bytes());
    invalid_name_public.extend_from_slice(&(TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD).to_be_bytes());
    invalid_name_public.extend_from_slice(&tpm2b(&[]));
    invalid_name_public.extend_from_slice(&8u16.to_be_bytes());
    let mut invalid_name_params = Vec::new();
    invalid_name_params.extend_from_slice(&tpm2b(&[]));
    invalid_name_params.extend_from_slice(&tpm2b(&invalid_name_public));
    assert_eq!(
        rc(&run(
            &mut tpm,
            &command(
                TPM_ST_SESSIONS,
                TPM_CC_NV_DEFINE_SPACE,
                &[TPM_RH_OWNER],
                &invalid_name_params,
                &[password_entry(&[])],
            )
        )),
        rc_parameter(TPM_RC_HASH, 2)
    );

    let platform_index = 0x0150_0402;
    let platform_attributes = TPMA_NV_PPWRITE | TPMA_NV_PPREAD;
    assert_eq!(
        rc(&nv_define_with_hierarchy(
            &mut tpm,
            TPM_RH_PLATFORM,
            platform_index,
            8,
            platform_attributes
        )),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_write(
            &mut tpm,
            TPM_RH_PLATFORM,
            platform_index,
            0,
            b"plat"
        )),
        TPM_RC_SUCCESS
    );
    let platform_read = nv_read(&mut tpm, TPM_RH_PLATFORM, platform_index, 0, 4);
    assert_eq!(rc(&platform_read), TPM_RC_SUCCESS);
    let mut platform_reader = Reader::new(response_parameters(&platform_read));
    assert_eq!(
        platform_reader.tpm2b(MAX_NV_SIZE).expect("platform data"),
        b"plat"
    );
    assert_eq!(
        rc(&nv_write(
            &mut tpm,
            TPM_RH_OWNER,
            platform_index,
            0,
            b"nope"
        )),
        TPM_RC_NV_AUTHORIZATION
    );
    assert_eq!(
        super::engine::nv_allows(
            platform_attributes,
            TPM_RH_ENDORSEMENT,
            platform_index,
            true
        ),
        false
    );

    let write_lock_index = 0x0150_0403;
    assert_eq!(
        rc(&nv_define_with_attributes(
            &mut tpm,
            write_lock_index,
            8,
            TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD
        )),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_write(
            &mut tpm,
            TPM_RH_OWNER,
            write_lock_index,
            0,
            b"lock"
        )),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_lock(&mut tpm, TPM_CC_NV_WRITE_LOCK, write_lock_index)),
        TPM_RC_NV_AUTHORIZATION
    );

    let read_lock_index = 0x0150_0404;
    assert_eq!(
        rc(&nv_define_with_attributes(
            &mut tpm,
            read_lock_index,
            8,
            TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD
        )),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_write(
            &mut tpm,
            TPM_RH_OWNER,
            read_lock_index,
            0,
            b"lock"
        )),
        TPM_RC_SUCCESS
    );
    assert_eq!(
        rc(&nv_lock(&mut tpm, TPM_CC_NV_READ_LOCK, read_lock_index)),
        TPM_RC_NV_AUTHORIZATION
    );

    let read_index = 0x0150_0405;
    assert_eq!(rc(&nv_define(&mut tpm, read_index, 8)), TPM_RC_SUCCESS);
    assert_eq!(
        rc(&nv_write(&mut tpm, TPM_RH_OWNER, read_index, 0, b"data")),
        TPM_RC_SUCCESS
    );
    let read = nv_read(&mut tpm, TPM_RH_OWNER, read_index, 0, 4);
    assert_eq!(rc(&read), TPM_RC_SUCCESS);
    let mut read_reader = Reader::new(response_parameters(&read));
    assert_eq!(read_reader.tpm2b(MAX_NV_SIZE).expect("data"), b"data");

    let public_response = nv_read_public(&mut tpm, read_index);
    assert_eq!(rc(&public_response), TPM_RC_SUCCESS);
    let mut public_reader = Reader::new(&public_response[10..]);
    let raw_public = public_reader.tpm2b(1024).expect("nv public");
    assert_eq!(&raw_public[..4], &read_index.to_be_bytes());
    assert_eq!(
        public_reader.tpm2b(64).expect("nv name").len(),
        TPM_ALG_SHA256.to_be_bytes().len() + 32
    );
    assert_eq!(
        rc(&nv_read_public(&mut tpm, 0x0150_0999)),
        rc_handle(TPM_RC_HANDLE, 1)
    );

    assert_eq!(
        rc(&nv_undefine(&mut tpm, TPM_RH_OWNER, read_index)),
        TPM_RC_SUCCESS
    );
    assert_eq!(tpm.nv_indices().contains(&read_index), false);

    let mut tpm = Tpm::new_with_seed([0xA1; 32]);
    assert_eq!(rc(&run(&mut tpm, &startup())), TPM_RC_SUCCESS);
    tpm.state.nv = (0..MAX_NV_INDICES as u32)
        .map(|index| nv_entry(0x0150_1000 + index))
        .collect();
    assert_eq!(rc(&nv_define(&mut tpm, 0x0150_2000, 8)), TPM_RC_NV_SPACE);
}

#[test]
fn engine_start_auth_session_rejects_each_bad_parameter() {
    let mut tpm = started_tpm();
    let bad_in = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_START_AUTH_SESSION,
        &[TPM_RH_OWNER, TPM_RH_NULL],
        &[],
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &bad_in)), rc_handle(TPM_RC_HANDLE, 1));
    let bad_out = command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_START_AUTH_SESSION,
        &[TPM_RH_NULL, TPM_RH_OWNER],
        &[],
        &[],
    );
    assert_eq!(rc(&run(&mut tpm, &bad_out)), rc_handle(TPM_RC_HANDLE, 2));

    let build = |nonce: &[u8],
                 salt: &[u8],
                 session_type: u8,
                 symmetric: Option<(u16, u16, u16)>,
                 auth_hash: u16| {
        let mut params = Vec::new();
        params.extend_from_slice(&tpm2b(nonce));
        params.extend_from_slice(&tpm2b(salt));
        params.push(session_type);
        match symmetric {
            Some((algorithm, bits, mode)) => {
                params.extend_from_slice(&algorithm.to_be_bytes());
                params.extend_from_slice(&bits.to_be_bytes());
                params.extend_from_slice(&mode.to_be_bytes());
            }
            None => params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()),
        }
        params.extend_from_slice(&auth_hash.to_be_bytes());
        command(
            TPM_ST_NO_SESSIONS,
            TPM_CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, TPM_RH_NULL],
            &params,
            &[],
        )
    };

    assert_eq!(
        rc(&run(
            &mut tpm,
            &build(&[0x11; 16], &[0x22], TPM_SE_HMAC, None, TPM_ALG_SHA256)
        )),
        rc_parameter(TPM_RC_SIZE, 2)
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &build(
                &[0x11; 16],
                &[],
                TPM_SE_HMAC,
                Some((TPM_ALG_AES, 128, TPM_ALG_NULL)),
                TPM_ALG_SHA256
            )
        )),
        rc_parameter(TPM_RC_SYMMETRIC, 4)
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &build(&[0x11; 16], &[], TPM_SE_POLICY, None, TPM_ALG_SHA256)
        )),
        rc_parameter(TPM_RC_VALUE, 3)
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &build(&[0x11; 16], &[], TPM_SE_HMAC, None, TPM_ALG_SHA1)
        )),
        rc_parameter(TPM_RC_HASH, 5)
    );
    assert_eq!(
        rc(&run(
            &mut tpm,
            &build(&[0x11; 15], &[], TPM_SE_HMAC, None, TPM_ALG_SHA256)
        )),
        rc_parameter(TPM_RC_SIZE, 1)
    );
}

#[test]
fn self_test_failure_is_reported_as_exact_tpm_rc() {
    let mut tpm = started_tpm();
    super::engine::FORCE_SELF_TEST_FAILURE.with(|flag| flag.set(true));
    let response = run(
        &mut tpm,
        &command(TPM_ST_NO_SESSIONS, TPM_CC_SELF_TEST, &[], &[1], &[]),
    );
    super::engine::FORCE_SELF_TEST_FAILURE.with(|flag| flag.set(false));
    assert_eq!(rc(&response), TPM_RC_FAILURE);
}

#[test]
fn engine_creation_and_quote_reject_out_of_range_pcr_selections() {
    let mut tpm = started_tpm();
    let mut selection = Vec::new();
    selection.extend_from_slice(&1u32.to_be_bytes());
    selection.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    selection.push(4);
    selection.extend_from_slice(&[0u8, 0, 0, 0x01]);

    let mut create_params = Vec::new();
    create_params.extend_from_slice(&empty_sensitive());
    create_params.extend_from_slice(&tpm2b(&ecc_template()));
    create_params.extend_from_slice(&tpm2b(&[]));
    create_params.extend_from_slice(&selection);
    assert_eq!(
        rc(&run(
            &mut tpm,
            &command(
                TPM_ST_SESSIONS,
                TPM_CC_CREATE_PRIMARY,
                &[TPM_RH_OWNER],
                &create_params,
                &[password_entry(&[])],
            )
        )),
        rc_parameter(TPM_RC_VALUE, 4)
    );

    let (parent, _) = create_primary_ok(&mut tpm, &ecc_template());
    assert_eq!(
        rc(&run(
            &mut tpm,
            &command(
                TPM_ST_SESSIONS,
                TPM_CC_CREATE,
                &[parent],
                &create_params,
                &[password_entry(&[])],
            )
        )),
        rc_parameter(TPM_RC_VALUE, 4)
    );

    assert_eq!(
        rc(&run(
            &mut tpm,
            &command(
                TPM_ST_SESSIONS,
                TPM_CC_QUOTE,
                &[parent],
                &{
                    let mut params = Vec::new();
                    params.extend_from_slice(&tpm2b(b"qualifying"));
                    params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                    params.extend_from_slice(&selection);
                    params
                },
                &[password_entry(&[])],
            )
        )),
        rc_parameter(TPM_RC_VALUE, 3)
    );
}

#[test]
fn engine_quote_rejects_unsupported_key_object_type() {
    let mut tpm = started_tpm();
    let mut public = PublicArea::parse(&ecc_template()).expect("ecc template");
    public.object_type = TPM_ALG_KEYEDHASH;
    public.object_attributes |= TPMA_OBJECT_SIGN;
    let key = KeyMaterial::Ecc(ecc_from_seed(&[0xAA; 32]));
    let handle = tpm
        .insert_object(public, Vec::new(), key, [0u8; 32])
        .expect("crafted object");
    assert_eq!(
        rc(&run(&mut tpm, &quote_command(handle, &[0]))),
        rc_parameter(TPM_RC_TYPE, 1)
    );
}
