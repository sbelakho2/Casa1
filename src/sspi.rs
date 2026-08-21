//! secur32.dll SSPI surface — credentials, security contexts, the NTLM and
//! Negotiate handshake envelopes, and message protection.
//!
//! # Handshake model
//!
//! The guest workload that reaches SSPI (the winhttp/wininet authentication
//! paths and any direct SSPI consumers) needs the negotiation to MAKE
//! PROGRESS and the message envelopes to be structurally correct.  This
//! subsystem models the documented NTLM/Negotiate envelope semantics:
//!
//! - Client [`initialize_security_context`](SspiSubsystem::initialize_security_context):
//!   call 1 produces the NTLM NEGOTIATE message (type 1) and returns
//!   `SEC_I_CONTINUE_NEEDED`; call 2 consumes the server's CHALLENGE
//!   (type 2), produces the AUTHENTICATE message (type 3) and returns
//!   `SEC_E_OK`.
//! - Server [`accept_security_context`](SspiSubsystem::accept_security_context):
//!   call 1 consumes the NEGOTIATE, produces the CHALLENGE and returns
//!   `SEC_I_CONTINUE_NEEDED`; call 2 consumes the AUTHENTICATE and returns
//!   `SEC_E_OK`.
//!
//! The token envelopes are built on the stack's existing NTLM machinery
//! ([`crate::winhttp`]: `ntlm_create_negotiate_msg` /
//! `ntlm_create_authenticate_msg` plus this module's challenge encoder and
//! type-3 parser).  The "Negotiate" package selects NTLM in this model.
//!
//! # Session key and message protection (documented internal PRF)
//!
//! The real NTLM chain derives the session key from DES-encrypted password
//! hashes; this runtime models the CONTRACT — both handshake sides derive
//! the SAME key from the two challenges — with a documented internal PRF:
//! `HMAC-SHA256(server_challenge || client_challenge, "casa1-sspi-session-key")`.
//! The signature envelope follows the NTLMSSP_MESSAGE_SIGNATURE layout:
//! `{ u32 signature (0x1 = sign, 0x10 = seal); u32 seqnum; u8[8] checksum }`
//! with the checksum as `HMAC-SHA256(session_key, seqnum_le || message)[0..8]`
//! (the real package uses HMAC-MD5; the broken MD5 primitive is deliberately
//! not used — the envelope is what the guest observes).  `EncryptMessage`
//! seals the payload with an XOR keystream derived from the same PRF so the
//! cipher is invertible and the envelope stays structurally correct.

use crate::error::AppResult;
use crate::winhttp::{
    ntlm_create_authenticate_msg, ntlm_create_challenge_msg, ntlm_create_negotiate_msg,
    ntlm_parse_authenticate_msg, ntlm_parse_challenge_msg, sspi_derive_session_key,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Documented SSPI status codes
// ---------------------------------------------------------------------------

pub const SEC_E_OK: u32 = 0x0000_0000;
pub const SEC_I_CONTINUE_NEEDED: u32 = 0x0009_0312;
pub const SEC_E_INVALID_HANDLE: u32 = 0x8009_0301;
pub const SEC_E_UNSUPPORTED_FUNCTION: u32 = 0x8009_0302;
pub const SEC_E_BUFFER_TOO_SMALL: u32 = 0x8009_0305;
pub const SEC_E_INVALID_TOKEN: u32 = 0x8009_0308;
pub const SEC_E_MESSAGE_ALTERED: u32 = 0x8009_030F;
pub const SEC_E_OUT_OF_SEQ: u32 = 0x8009_0311;

/// `SecPkgContext_Sizes` attribute values the package reports.
pub const SSPI_CB_MAX_TOKEN: u32 = 0x0001_0000;
pub const SSPI_CB_MAX_SIGNATURE: u32 = 16;
pub const SSPI_CB_BLOCK_SIZE: u32 = 0;
pub const SSPI_CB_SECURITY_TRAILER: u32 = 16;

/// Documented `SecBufferType` values.
pub const SECBUFFER_DATA: u32 = 1;
pub const SECBUFFER_TOKEN: u32 = 2;

/// Documented `SECPKG_ATTR_*` attribute ids (the subset the guest reaches).
pub const SECPKG_ATTR_SIZES: u32 = 0;
pub const SECPKG_ATTR_NAMES: u32 = 1;
pub const SECPKG_ATTR_SESSION_KEY: u32 = 9;
pub const SECPKG_ATTR_PACKAGE_INFO: u32 = 10;

// ---------------------------------------------------------------------------
// State records
// ---------------------------------------------------------------------------

/// The identity a credential handle was acquired with.
#[derive(Debug, Clone)]
pub struct SspiIdentity {
    pub user: String,
    pub domain: String,
    pub password: String,
}

#[derive(Debug, Clone)]
struct SspiCredRecord {
    package: String,
    identity: SspiIdentity,
}

#[derive(Debug, Clone)]
struct SspiContextRecord {
    package: String,
    /// `true` for the AcceptSecurityContext (server) side.
    server: bool,
    /// 0 = fresh, 1 = handshake in progress, 2 = complete.
    phase: u32,
    target: String,
    server_challenge: [u8; 8],
    client_challenge: [u8; 8],
    session_key: [u8; 32],
    /// Package-maintained send sequence number: the value used in the
    /// NEXT signature/seal this context produces.  NTLM ignores the
    /// per-call `MessageSeqNo` parameter and tracks its own per-direction
    /// counters.
    send_seqnum: u32,
    /// Package-maintained receive sequence number: the value expected in
    /// the NEXT signature/seal this context verifies.
    recv_seqnum: u32,
    /// Token received out-of-band (CompleteAuthToken).
    token_in: Vec<u8>,
    /// Last token produced for the guest.
    token_out: Vec<u8>,
}

/// The secur32.dll SSPI state machine.
#[derive(Debug, Default)]
pub struct SspiSubsystem {
    next_handle: u64,
    credentials: BTreeMap<u64, SspiCredRecord>,
    contexts: BTreeMap<u64, SspiContextRecord>,
}

impl SspiSubsystem {
    pub fn new() -> Self {
        Self {
            // Handles live far above the win32 handle space (4..) and the
            // network id space (0x1000..) so the namespaces can never
            // collide in guest-visible values.  The base fits the x86 guest
            // pointer width and stays clear of the CRT data (0x72000000),
            // CRT heap (0x73000000) and private-page (0x74000000) regions.
            next_handle: 0x6000_0000,
            credentials: BTreeMap::new(),
            contexts: BTreeMap::new(),
        }
    }

    fn mint_handle(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        handle
    }

    fn resolve_package(package: &str) -> String {
        let lower = package.to_ascii_lowercase();
        if lower.contains("negotiate") {
            "Negotiate".to_string()
        } else {
            "NTLM".to_string()
        }
    }

    // ── Credentials ────────────────────────────────────────────────────────

    /// Acquire a credential handle for `package` with the given identity.
    /// Returns the handle; the caller writes it into the guest's SecHandle.
    pub fn acquire_credentials(&mut self, package: &str, identity: SspiIdentity) -> u64 {
        let handle = self.mint_handle();
        self.credentials.insert(
            handle,
            SspiCredRecord {
                package: Self::resolve_package(package),
                identity,
            },
        );
        handle
    }

    pub fn free_credentials(&mut self, handle: u64) -> bool {
        self.credentials.remove(&handle).is_some()
    }

    pub fn has_credential(&self, handle: u64) -> bool {
        self.credentials.contains_key(&handle)
    }

    // ── Handshake ──────────────────────────────────────────────────────────

    /// Client side: `InitializeSecurityContextW`.
    ///
    /// Returns `(status, context_handle, output_token)`.  On the first call
    /// (`context == None`) the NEGOTIATE message is produced with
    /// `SEC_I_CONTINUE_NEEDED`; the second call consumes the server's
    /// CHALLENGE and produces the AUTHENTICATE message with `SEC_E_OK`.
    pub fn initialize_security_context(
        &mut self,
        cred: u64,
        context: Option<u64>,
        target: &str,
        input_token: Option<Vec<u8>>,
    ) -> (u32, u64, Vec<u8>) {
        let Some(credential) = self.credentials.get(&cred) else {
            return (SEC_E_INVALID_HANDLE, 0, Vec::new());
        };
        let package = credential.package.clone();
        let identity = credential.identity.clone();
        let Some(handle) = context else {
            // First call: produce the NEGOTIATE message.
            let handle = self.mint_handle();
            let workstation = "CASA1";
            let token_out = ntlm_create_negotiate_msg(&identity.domain, workstation);
            let record = SspiContextRecord {
                package,
                server: false,
                phase: 1,
                target: target.to_string(),
                server_challenge: [0; 8],
                client_challenge: [0; 8],
                session_key: [0; 32],
                send_seqnum: 0,
                recv_seqnum: 0,
                token_in: Vec::new(),
                token_out: token_out.clone(),
            };
            self.contexts.insert(handle, record);
            return (SEC_I_CONTINUE_NEEDED, handle, token_out);
        };
        let Some(record) = self.contexts.get_mut(&handle) else {
            return (SEC_E_INVALID_HANDLE, 0, Vec::new());
        };
        let Some(input) = input_token else {
            // The caller re-issued without a token — keep the handshake
            // position and let it retry with the challenge.
            return (SEC_I_CONTINUE_NEEDED, handle, record.token_out.clone());
        };
        let Some(server_challenge_vec) = ntlm_parse_challenge_msg(&input) else {
            return (SEC_E_INVALID_TOKEN, 0, Vec::new());
        };
        let server_challenge: [u8; 8] = server_challenge_vec[..8]
            .try_into()
            .expect("NTLM challenge is 8 bytes");
        let token_out = ntlm_create_authenticate_msg(
            &server_challenge,
            &identity.user,
            &identity.password,
            &identity.domain,
        );
        let client_challenge = ntlm_parse_authenticate_msg(&token_out)
            .map(|(_, _, nonce)| nonce)
            .unwrap_or([0; 8]);
        let key = sspi_derive_session_key(&server_challenge, &client_challenge);
        record.server_challenge = server_challenge;
        record.client_challenge = client_challenge;
        record.session_key = key[..32].try_into().expect("32-byte session key");
        record.phase = 2;
        record.token_in = input;
        record.token_out = token_out.clone();
        (SEC_E_OK, handle, token_out)
    }

    /// Server side: `AcceptSecurityContext`.
    ///
    /// Call 1 consumes the NEGOTIATE and produces the CHALLENGE with
    /// `SEC_I_CONTINUE_NEEDED`; call 2 consumes the AUTHENTICATE and
    /// completes with `SEC_E_OK`.
    pub fn accept_security_context(
        &mut self,
        cred: u64,
        context: Option<u64>,
        input_token: Vec<u8>,
    ) -> (u32, u64, Vec<u8>) {
        let Some(credential) = self.credentials.get(&cred) else {
            return (SEC_E_INVALID_HANDLE, 0, Vec::new());
        };
        let package = credential.package.clone();
        let identity_domain = credential.identity.domain.clone();
        let Some(handle) = context else {
            // First call: the input must be the client's NEGOTIATE message.
            if input_token.len() < 12
                || &input_token[..8] != b"NTLMSSP\x00"
                || u32::from_le_bytes([
                    input_token[8],
                    input_token[9],
                    input_token[10],
                    input_token[11],
                ]) != 1
            {
                return (SEC_E_INVALID_TOKEN, 0, Vec::new());
            }
            let handle = self.mint_handle();
            // Deterministic per-context server challenge (documented
            // internal PRF — the real package uses a random challenge; the
            // guest only observes it as opaque bytes).
            let mut seed = [0_u8; 8];
            seed.copy_from_slice(&handle.to_le_bytes());
            let server_challenge: [u8; 8] =
                crate::network::hmac_sha256(&seed, b"casa1-ntlm-server-challenge")
                    .expect("HMAC-SHA256 accepts any key length")[..8]
                    .try_into()
                    .expect("8-byte challenge");
            let token_out = ntlm_create_challenge_msg(server_challenge, &identity_domain);
            let record = SspiContextRecord {
                package,
                server: true,
                phase: 1,
                target: String::new(),
                server_challenge,
                client_challenge: [0; 8],
                session_key: [0; 32],
                send_seqnum: 0,
                recv_seqnum: 0,
                token_in: input_token,
                token_out: token_out.clone(),
            };
            self.contexts.insert(handle, record);
            return (SEC_I_CONTINUE_NEEDED, handle, token_out);
        };
        let Some(record) = self.contexts.get_mut(&handle) else {
            return (SEC_E_INVALID_HANDLE, 0, Vec::new());
        };
        let Some((domain, _user, client_challenge)) = ntlm_parse_authenticate_msg(&input_token)
        else {
            return (SEC_E_INVALID_TOKEN, 0, Vec::new());
        };
        let key = sspi_derive_session_key(&record.server_challenge, &client_challenge);
        record.client_challenge = client_challenge;
        record.session_key = key[..32].try_into().expect("32-byte session key");
        record.phase = 2;
        record.token_in = input_token;
        record.target = domain;
        (SEC_E_OK, handle, record.token_out.clone())
    }

    /// CompleteAuthToken: park the token received out-of-band.  The model
    /// never returns SEC_I_COMPLETE_NEEDED (tokens arrive whole), so this
    /// records the token and reports success when the context exists.
    pub fn complete_auth_token(&mut self, handle: u64, token: Vec<u8>) -> bool {
        let Some(record) = self.contexts.get_mut(&handle) else {
            return false;
        };
        record.token_in = token;
        true
    }

    pub fn delete_security_context(&mut self, handle: u64) -> bool {
        self.contexts.remove(&handle).is_some()
    }

    /// ImpersonateSecurityContext / RevertSecurityContext: the guest runs as
    /// the guest user already — the impersonation contract is satisfied by
    /// validating the context handle.
    pub fn impersonate(&self, handle: u64) -> bool {
        self.contexts.contains_key(&handle)
    }

    pub fn has_context(&self, handle: u64) -> bool {
        self.contexts.contains_key(&handle)
    }

    pub fn context_is_complete(&self, handle: u64) -> bool {
        self.contexts
            .get(&handle)
            .is_some_and(|record| record.phase == 2)
    }

    /// The 16-byte NTLMSSP_MESSAGE_SIGNATURE for a signed message.
    fn sign_envelope(
        record: &mut SspiContextRecord,
        seal: bool,
        message: &[u8],
    ) -> AppResult<Vec<u8>> {
        let seqnum = record.send_seqnum.to_le_bytes();
        let checksum = crate::network::hmac_sha256(
            &record.session_key,
            &[seqnum.as_slice(), message].concat(),
        )?;
        let mut envelope = Vec::with_capacity(16);
        envelope.extend_from_slice(
            &(if seal {
                0x0000_0010_u32
            } else {
                0x0000_0001_u32
            })
            .to_le_bytes(),
        );
        envelope.extend_from_slice(&seqnum);
        envelope.extend_from_slice(&checksum[..8]);
        Ok(envelope)
    }

    /// PRF keystream for the seal cipher: `HMAC-SHA256(session_key,
    /// seqnum_le || "casa1-sspi-seal" || block_le)` concatenated in 32-byte
    /// blocks (documented internal PRF stream — the real package uses RC4).
    /// The keystream is derived from the envelope's sequence number so the
    /// sealing and unsealing sides agree on the same stream.
    fn seal_keystream(
        record: &SspiContextRecord,
        seqnum: u32,
        length: usize,
    ) -> AppResult<Vec<u8>> {
        let mut keystream = Vec::with_capacity(length);
        let mut block = 0_u32;
        while keystream.len() < length {
            let mut material = seqnum.to_le_bytes().to_vec();
            material.extend_from_slice(b"casa1-sspi-seal");
            material.extend_from_slice(&block.to_le_bytes());
            let chunk = crate::network::hmac_sha256(&record.session_key, &material)?;
            keystream.extend_from_slice(&chunk);
            block = block.wrapping_add(1);
        }
        keystream.truncate(length);
        Ok(keystream)
    }

    /// MakeSignature: returns `(status, signature)`; the signature is the
    /// 16-byte NTLMSSP_MESSAGE_SIGNATURE over the data buffers.
    pub fn make_signature(&mut self, handle: u64, data: &[u8]) -> AppResult<(u32, Vec<u8>)> {
        let Some(record) = self.contexts.get_mut(&handle) else {
            return Ok((SEC_E_INVALID_HANDLE, Vec::new()));
        };
        if record.phase != 2 {
            return Ok((SEC_E_INVALID_HANDLE, Vec::new()));
        }
        let envelope = Self::sign_envelope(record, false, data)?;
        record.send_seqnum = record.send_seqnum.wrapping_add(1);
        Ok((SEC_E_OK, envelope))
    }

    /// VerifySignature: `(status, qop_out)`; validates the envelope
    /// sequence number and checksum over the data buffers.
    pub fn verify_signature(
        &mut self,
        handle: u64,
        signature: &[u8],
        data: &[u8],
    ) -> AppResult<(u32, u32)> {
        let Some(record) = self.contexts.get_mut(&handle) else {
            return Ok((SEC_E_INVALID_HANDLE, 0));
        };
        if record.phase != 2 {
            return Ok((SEC_E_INVALID_HANDLE, 0));
        }
        if signature.len() < 16 {
            return Ok((SEC_E_INVALID_TOKEN, 0));
        }
        let sig_word = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        let seqnum = u32::from_le_bytes([signature[4], signature[5], signature[6], signature[7]]);
        if sig_word != 0x0000_0001 {
            // Seal-mode envelopes are consumed by DecryptMessage.
            return Ok((SEC_E_INVALID_TOKEN, 0));
        }
        if seqnum != record.recv_seqnum {
            return Ok((SEC_E_OUT_OF_SEQ, 0));
        }
        // Per MS-NLMP the receive sequence number advances even when the
        // checksum verification fails.
        record.recv_seqnum = record.recv_seqnum.wrapping_add(1);
        let expected = crate::network::hmac_sha256(
            &record.session_key,
            &[seqnum.to_le_bytes().as_slice(), data].concat(),
        )?;
        if expected[..8] != signature[8..16] {
            return Ok((SEC_E_MESSAGE_ALTERED, 0));
        }
        Ok((SEC_E_OK, 0))
    }

    /// EncryptMessage: returns `(status, signature, ciphertext)`.  The
    /// data buffers are sealed in place by the guest arm; here the
    /// plaintext is transformed with the PRF keystream and the seal
    /// envelope (signature word 0x10) is produced.
    pub fn encrypt_message(
        &mut self,
        handle: u64,
        plaintext: &[u8],
    ) -> AppResult<(u32, Vec<u8>, Vec<u8>)> {
        let Some(record) = self.contexts.get_mut(&handle) else {
            return Ok((SEC_E_INVALID_HANDLE, Vec::new(), Vec::new()));
        };
        if record.phase != 2 {
            return Ok((SEC_E_INVALID_HANDLE, Vec::new(), Vec::new()));
        }
        let envelope = Self::sign_envelope(record, true, plaintext)?;
        let keystream = Self::seal_keystream(record, record.send_seqnum, plaintext.len())?;
        let ciphertext = plaintext
            .iter()
            .zip(keystream.iter())
            .map(|(byte, key)| byte ^ key)
            .collect::<Vec<_>>();
        record.send_seqnum = record.send_seqnum.wrapping_add(1);
        Ok((SEC_E_OK, envelope, ciphertext))
    }

    /// DecryptMessage: returns `(status, plaintext, qop_out)`.  The seal
    /// envelope is verified (seqnum + checksum over the recovered
    /// plaintext) and the payload unsealed in place by the guest arm.
    pub fn decrypt_message(
        &mut self,
        handle: u64,
        signature: &[u8],
        ciphertext: &[u8],
    ) -> AppResult<(u32, Vec<u8>, u32)> {
        let Some(record) = self.contexts.get_mut(&handle) else {
            return Ok((SEC_E_INVALID_HANDLE, Vec::new(), 0));
        };
        if record.phase != 2 {
            return Ok((SEC_E_INVALID_HANDLE, Vec::new(), 0));
        }
        if signature.len() < 16 {
            return Ok((SEC_E_INVALID_TOKEN, Vec::new(), 0));
        }
        let sig_word = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        let seqnum = u32::from_le_bytes([signature[4], signature[5], signature[6], signature[7]]);
        if sig_word != 0x0000_0010 {
            return Ok((SEC_E_INVALID_TOKEN, Vec::new(), 0));
        }
        if seqnum != record.recv_seqnum {
            return Ok((SEC_E_OUT_OF_SEQ, Vec::new(), 0));
        }
        // The receive sequence number advances even when the checksum
        // verification fails (MS-NLMP).
        record.recv_seqnum = record.recv_seqnum.wrapping_add(1);
        let keystream = Self::seal_keystream(record, seqnum, ciphertext.len())?;
        let plaintext = ciphertext
            .iter()
            .zip(keystream.iter())
            .map(|(byte, key)| byte ^ key)
            .collect::<Vec<_>>();
        let expected = crate::network::hmac_sha256(
            &record.session_key,
            &[seqnum.to_le_bytes().as_slice(), plaintext.as_slice()].concat(),
        )?;
        if expected[..8] != signature[8..16] {
            return Ok((SEC_E_MESSAGE_ALTERED, Vec::new(), 0));
        }
        Ok((SEC_E_OK, plaintext, 0))
    }

    // ── Context attributes ─────────────────────────────────────────────────

    /// `SecPkgContext_Sizes` for the package behind the context.
    pub fn query_sizes(&self, handle: u64) -> Option<(u32, u32, u32, u32)> {
        self.contexts.get(&handle).map(|_| {
            (
                SSPI_CB_MAX_TOKEN,
                SSPI_CB_MAX_SIGNATURE,
                SSPI_CB_BLOCK_SIZE,
                SSPI_CB_SECURITY_TRAILER,
            )
        })
    }

    /// The 32-byte session key (SECPKG_ATTR_SESSION_KEY).
    pub fn query_session_key(&self, handle: u64) -> Option<Vec<u8>> {
        self.contexts
            .get(&handle)
            .filter(|record| record.phase == 2)
            .map(|record| record.session_key.to_vec())
    }

    /// The user name the context authenticated as (SECPKG_ATTR_NAMES).
    pub fn context_user(&self, handle: u64) -> Option<String> {
        self.contexts.get(&handle).map(|record| {
            if record.server {
                record.target.clone()
            } else {
                record
                    .target
                    .split('\\')
                    .next_back()
                    .unwrap_or("user")
                    .to_string()
            }
        })
    }

    /// The package behind the context (SECPKG_ATTR_PACKAGE_INFO).
    pub fn context_package(&self, handle: u64) -> Option<String> {
        self.contexts
            .get(&handle)
            .map(|record| record.package.clone())
    }

    /// The identity a credential handle was acquired with.
    pub fn credential_identity(&self, handle: u64) -> Option<&SspiIdentity> {
        self.credentials.get(&handle).map(|record| &record.identity)
    }

    // ── Package enumeration ────────────────────────────────────────────────

    /// The packages EnumerateSecurityPackagesW reports: (name, comment,
    /// cbMaxToken).
    pub fn enumerate_packages(&self) -> Vec<(&'static str, &'static str, u32)> {
        vec![
            ("Negotiate", "Microsoft Negotiate SSP", SSPI_CB_MAX_TOKEN),
            ("NTLM", "Microsoft NTLM SSP", SSPI_CB_MAX_TOKEN),
        ]
    }
}
