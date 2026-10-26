//! Cryptographic primitives for the software TPM.
//!
//! All signing is real: RSA PKCS#1 v1.5 / ECDSA P-256 through the `rsa` and
//! `p256` crates.  Keys are derived deterministically from persisted hierarchy
//! seeds, so a game environment sees stable primary keys across restarts
//! without a host Keychain dependency.  Randomness comes from a persisted
//! SHA-256 DRBG that `TPM2_StirRandom` can stir.

use hmac::{Hmac, Mac};
use p256::SecretKey;
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::traits::PublicKeyParts;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::constants::{TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_RC_KEY};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Digest `data` with the named TPM hash algorithm.
pub fn hash(algorithm: u16, data: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        TPM_ALG_SHA1 => Some(Sha1::digest(data).to_vec()),
        TPM_ALG_SHA256 => Some(Sha256::digest(data).to_vec()),
        TPM_ALG_SHA384 => Some(Sha384::digest(data).to_vec()),
        TPM_ALG_SHA512 => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

/// Digest length in bytes for a TPM hash algorithm.
pub fn hash_len(algorithm: u16) -> Option<usize> {
    match algorithm {
        TPM_ALG_SHA1 => Some(20),
        TPM_ALG_SHA256 => Some(32),
        TPM_ALG_SHA384 => Some(48),
        TPM_ALG_SHA512 => Some(64),
        _ => None,
    }
}

/// HMAC-SHA-256 with an arbitrary key length.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derive a 256-bit seed from a persisted seed and a domain label.
pub fn derive_seed(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    hmac_sha256(seed, label)
}

/// TPM 2.0 `KDFa` (SP800-108 counter mode) for HMAC-SHA-256.
///
/// `label` must include its trailing NUL byte, matching the wire strings
/// (`"ATH\0"`, `"INT\0"`, `"PROOF\0"`, ...).
pub fn kdfa(label: &[u8], context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes);
    let mut counter: u32 = 0;
    while out.len() < bytes {
        counter += 1;
        let mut mac = HmacSha256::new_from_slice(&[]).expect("HMAC accepts any key length");
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0u8]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&bits.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out.truncate(bytes);
    out
}

/// Constant-time equality for authorization secrets and HMACs.
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Persisted SHA-256 DRBG state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Drbg {
    pub state: [u8; 32],
    pub counter: u64,
}

impl Drbg {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            state: seed,
            counter: 0,
        }
    }

    /// Generate `count` bytes, ratcheting the state forward afterwards.
    pub fn generate(&mut self, count: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(count);
        while out.len() < count {
            let mut hasher = Sha256::new();
            hasher.update(b"casa1-tpm-drbg");
            hasher.update(self.state);
            hasher.update(self.counter.to_be_bytes());
            out.extend_from_slice(&hasher.finalize());
            self.counter = self.counter.wrapping_add(1);
        }
        out.truncate(count);
        let mut ratchet = Sha256::new();
        ratchet.update(b"casa1-tpm-drbg-ratchet");
        ratchet.update(self.state);
        ratchet.update(&out);
        let digest = ratchet.finalize();
        self.state.copy_from_slice(&digest);
        self.counter = 0;
        out
    }

    /// Mix additional entropy into the DRBG state.
    pub fn stir(&mut self, entropy: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(b"casa1-tpm-drbg-stir");
        hasher.update(self.state);
        hasher.update(self.counter.to_be_bytes());
        hasher.update(entropy);
        let digest = hasher.finalize();
        self.state.copy_from_slice(&digest);
        self.counter = 0;
    }
}

/// Deterministically generate an RSA key from a 256-bit seed.
pub fn rsa_from_seed(seed: &[u8; 32], bits: u16) -> Result<RsaPrivateKey, u32> {
    let mut rng = StdRng::from_seed(*seed);
    RsaPrivateKey::new(&mut rng, bits as usize).map_err(|_| TPM_RC_KEY)
}

/// Deterministically derive a P-256 key from a 256-bit seed.
pub fn ecc_from_seed(seed: &[u8; 32]) -> SecretKey {
    let mut rng = StdRng::from_seed(*seed);
    SecretKey::random(&mut rng)
}

/// Big-endian RSA modulus, left-padded to the key size in bytes.
pub fn rsa_modulus(key: &RsaPrivateKey, bits: u16) -> Vec<u8> {
    let width = bits as usize / 8;
    let mut modulus = key.n().to_bytes_be();
    if modulus.len() < width {
        let mut padded = vec![0u8; width - modulus.len()];
        padded.extend_from_slice(&modulus);
        modulus = padded;
    }
    modulus
}

/// Uncompressed P-256 point as `(x, y)` big-endian coordinates.
pub fn ecc_point(key: &SecretKey) -> (Vec<u8>, Vec<u8>) {
    let encoded = key.public_key().to_encoded_point(false);
    let bytes = encoded.as_bytes();
    (bytes[1..33].to_vec(), bytes[33..65].to_vec())
}

/// RSASSA-PKCS1-v1_5 with SHA-256 over the supplied message.
pub fn rsa_sign(key: &RsaPrivateKey, message: &[u8]) -> Vec<u8> {
    use rsa::signature::SignatureEncoding;
    let signing_key = RsaSigningKey::<Sha256>::new(key.clone());
    signing_key.sign(message).to_bytes().to_vec()
}

/// ECDSA P-256 with SHA-256 over the supplied message, returning `(r, s)`.
pub fn ecdsa_sign(key: &SecretKey, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let signing_key = EcdsaSigningKey::from(key);
    let signature: p256::ecdsa::Signature = signing_key.sign(message);
    let bytes = signature.to_bytes();
    (bytes[..32].to_vec(), bytes[32..].to_vec())
}
