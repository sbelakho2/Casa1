//! TPM 2.0 authorization: password sessions and HMAC sessions.
//!
//! The cpHash covers the command code, the names of every handle in the
//! command handle area, and the command parameters.  HMAC sessions verify
//! `HMAC(sessionKey, cpHash || nonceCaller || nonceTPM || attributes)` and
//! produce the matching response HMAC over the rpHash.  Password sessions
//! (`TPM_RS_PW`) compare the supplied auth value directly.

use super::Tpm;
use super::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_AUTH_FAIL, TPM_RC_AUTH_MISSING, TPM_RC_AUTHSIZE, TPM_RC_BAD_AUTH,
    TPM_RC_HANDLE, TPM_RC_SIZE, TPM_RS_PW, is_nv_index, is_transient_handle, rc_session,
};
use super::crypto::{ct_eq, hmac_sha256, sha256};
use super::state::{AuthCommand, AuthTarget, ResponseSession};
use super::wire::Writer;

/// Hash command-code + handle names + parameters.
pub(crate) fn cp_hash(code: u32, names: &[Vec<u8>], params: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(4 + names.iter().map(Vec::len).sum::<usize>() + params.len());
    data.extend_from_slice(&code.to_be_bytes());
    for name in names {
        data.extend_from_slice(name);
    }
    data.extend_from_slice(params);
    sha256(&data)
}

/// Hash response code + command code + response parameters.
pub(crate) fn rp_hash(code: u32, response_code: u32, params: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(8 + params.len());
    data.extend_from_slice(&response_code.to_be_bytes());
    data.extend_from_slice(&code.to_be_bytes());
    data.extend_from_slice(params);
    sha256(&data)
}

/// Compute the command-authorization HMAC carried by an HMAC session.
pub fn auth_hmac(
    session_key: &[u8],
    cp_hash: &[u8],
    nonce_caller: &[u8],
    nonce_tpm: &[u8],
    attributes: u8,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(cp_hash.len() + nonce_caller.len() + nonce_tpm.len() + 1);
    data.extend_from_slice(cp_hash);
    data.extend_from_slice(nonce_caller);
    data.extend_from_slice(nonce_tpm);
    data.push(attributes);
    hmac_sha256(session_key, &data)
}

fn handle_name(tpm: &Tpm, handle: u32) -> Vec<u8> {
    if let Some(object) = tpm.objects.get(&handle) {
        return object.name.clone();
    }
    if is_nv_index(handle) {
        if let Some(entry) = tpm.state.nv.iter().find(|entry| entry.index == handle) {
            let nv = super::state::NvIndex::from_persisted(entry.clone());
            return nv.name();
        }
    }
    let _ = is_transient_handle(handle);
    handle.to_be_bytes().to_vec()
}

/// Verify every authorization session and return the response sessions that
/// must be marshaled into the response authorization area.
pub(crate) fn authorize(
    tpm: &mut Tpm,
    code: u32,
    handles: &[u32],
    params: &[u8],
    sessions: &[AuthCommand],
    targets: &[AuthTarget],
) -> Result<Vec<ResponseSession>, u32> {
    if sessions.len() != targets.len() {
        return Err(if sessions.is_empty() {
            TPM_RC_AUTH_MISSING
        } else {
            TPM_RC_AUTHSIZE
        });
    }
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<Vec<u8>> = handles
        .iter()
        .map(|handle| handle_name(tpm, *handle))
        .collect();
    let cp_hash = cp_hash(code, &names, params);
    let mut verified = Vec::with_capacity(sessions.len());
    for (position, (session, target)) in sessions.iter().zip(targets.iter()).enumerate() {
        let expected = target.expected_auth(&tpm.state, &tpm.objects);
        if session.handle == TPM_RS_PW {
            if !session.nonce.is_empty() {
                return Err(TPM_RC_SIZE);
            }
            if session.attributes != 0 {
                return Err(TPM_RC_ATTRIBUTES);
            }
            if !ct_eq(expected, &session.hmac) {
                return Err(TPM_RC_BAD_AUTH);
            }
            continue;
        }
        let Some(stored) = tpm.sessions.get(&session.handle) else {
            return Err(rc_session(TPM_RC_HANDLE, position as u32 + 1));
        };
        if session.nonce.is_empty() || session.nonce.len() > 64 {
            return Err(TPM_RC_SIZE);
        }
        if session.attributes & 0xC0 != 0 {
            return Err(TPM_RC_ATTRIBUTES);
        }
        let expected_hmac = auth_hmac(
            &stored.session_key,
            &cp_hash,
            &session.nonce,
            &stored.nonce_tpm,
            session.attributes,
        );
        if !ct_eq(&expected_hmac, &session.hmac) {
            return Err(rc_session(TPM_RC_AUTH_FAIL, position as u32 + 1));
        }
        verified.push((
            stored.handle,
            stored.session_key,
            session.nonce.clone(),
            session.attributes,
            session.attributes & 0x01 == 0,
        ));
    }
    let mut response_sessions = Vec::with_capacity(verified.len());
    for (handle, session_key, nonce_caller, attributes, flush) in verified {
        let nonce_tpm = tpm.random_bytes(32);
        {
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&nonce_tpm);
            if let Some(session) = tpm.sessions.get_mut(&handle) {
                session.nonce_tpm = nonce;
            } else {
                return Err(rc_session(
                    TPM_RC_HANDLE,
                    response_sessions.len() as u32 + 1,
                ));
            }
            response_sessions.push(ResponseSession {
                handle,
                nonce_tpm: nonce,
                session_key,
                nonce_caller,
                attributes,
            });
        }
        if flush {
            tpm.sessions.remove(&handle);
        }
    }
    Ok(response_sessions)
}

/// Marshal the response authorization area for successful HMAC sessions.
pub(crate) fn response_auth_area(
    code: u32,
    response_code: u32,
    params: &[u8],
    sessions: &[ResponseSession],
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.u32(sessions.len() as u32);
    if sessions.is_empty() {
        return writer.into_vec();
    }
    let rp_hash = rp_hash(code, response_code, params);
    for session in sessions {
        writer.u32(session.handle);
        writer.tpm2b(&session.nonce_tpm);
        writer.u8(session.attributes);
        let mut data = Vec::with_capacity(32 + 32 + session.nonce_caller.len() + 1);
        data.extend_from_slice(&rp_hash);
        data.extend_from_slice(&session.nonce_tpm);
        data.extend_from_slice(&session.nonce_caller);
        data.push(session.attributes);
        let hmac = hmac_sha256(&session.session_key, &data);
        writer.tpm2b(&hmac);
    }
    writer.into_vec()
}
