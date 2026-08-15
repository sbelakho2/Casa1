//! Section 36 — Authenticode signature verification (WinVerifyTrust backing).
//!
//! These tests build a real, cryptographically valid Authenticode signature
//! (RSA + SHA-256 over a synthetic PE image) using the RustCrypto `cms` and
//! `x509-cert` builders, embed it in a minimal-but-structurally-valid PE, and
//! assert that [`casa1::security::verify_pe_authenticode`] accepts it, rejects
//! a tampered copy, and reports unsigned images as `NoSignature`.

use std::str::FromStr;
use std::time::Duration;

use casa1::security::{AuthenticodeVerdict, verify_pe_authenticode};

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};

use der::asn1::ObjectIdentifier;
use der::{Any, Decode, Encode};

use rand::SeedableRng;
use rand::rngs::StdRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};

use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::certificate::Certificate;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

// --- Fixed PE layout offsets for the synthetic image -----------------------
const E_LFANEW: usize = 0x40;
const COFF: usize = E_LFANEW + 4; // 0x44
const OPT: usize = COFF + 20; // 0x58
const SIZE_OF_OPTIONAL: usize = 0xF0; // 240
const CHECKSUM_OFF: usize = OPT + 64; // 0x98
const DD_OFF: usize = OPT + 96; // 0xB8
const SEC_ENTRY: usize = DD_OFF + 4 * 8; // 0xD8 (IMAGE_DIRECTORY_ENTRY_SECURITY)
const BODY_LEN: usize = OPT + SIZE_OF_OPTIONAL; // 0x148 == cert table offset

const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
const OID_SPC_PE_IMAGE_DATA: &str = "1.3.6.1.4.1.311.2.1.15";

/// Encode a DER TLV with short/long-form length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// Encode an OID's content octets from a dotted string.
fn oid_content(dotted: &str) -> Vec<u8> {
    let parts: Vec<u64> = dotted.split('.').map(|p| p.parse().unwrap()).collect();
    let mut out = vec![(parts[0] * 40 + parts[1]) as u8];
    for &arc in &parts[2..] {
        let mut stack = vec![(arc & 0x7f) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            stack.push((v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        stack.reverse();
        out.extend_from_slice(&stack);
    }
    out
}

fn der_oid(dotted: &str) -> Vec<u8> {
    tlv(0x06, &oid_content(dotted))
}

/// Compute the Authenticode SHA-256 hash over the fixed synthetic PE layout.
fn authenticode_hash(file: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for &(start, end) in &[
        (0usize, CHECKSUM_OFF),
        (CHECKSUM_OFF + 4, SEC_ENTRY),
        (SEC_ENTRY + 8, BODY_LEN),
    ] {
        hasher.update(&file[start..end]);
    }
    hasher.finalize().to_vec()
}

/// Build the synthetic PE body (everything before the certificate table).
fn build_pe_body() -> Vec<u8> {
    let mut pe = vec![0u8; BODY_LEN];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C..0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());
    pe[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");
    pe[COFF + 16..COFF + 18].copy_from_slice(&(SIZE_OF_OPTIONAL as u16).to_le_bytes());
    pe[OPT..OPT + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    // Some recognizable bytes inside a hashed region (used by the tamper test).
    pe[0x10] = 0xAB;
    pe
}

/// Build SpcIndirectDataContent (the Authenticode eContent) over `pe_hash`.
fn build_spc_indirect_data(pe_hash: &[u8]) -> Vec<u8> {
    let data = tlv(0x30, &der_oid(OID_SPC_PE_IMAGE_DATA));
    let mut alg = der_oid(OID_SHA256);
    alg.extend_from_slice(&[0x05, 0x00]); // NULL parameters
    let digest_algo = tlv(0x30, &alg);
    let mut digest_info = digest_algo;
    digest_info.extend_from_slice(&tlv(0x04, pe_hash));
    let digest_info = tlv(0x30, &digest_info);
    let mut spc = data;
    spc.extend_from_slice(&digest_info);
    tlv(0x30, &spc)
}

fn sha256_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::from_str(OID_SHA256).unwrap(),
        parameters: None,
    }
}

/// Build a self-signed RSA certificate for the signer.
fn build_certificate(signer: &SigningKey<Sha256>, private_key: &RsaPrivateKey) -> Certificate {
    let public_key = RsaPublicKey::from(private_key);
    let spki_der = public_key.to_public_key_der().unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).unwrap();

    let serial = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(3600, 0)).unwrap();
    let subject = Name::from_str("CN=Casa1 Authenticode Test").unwrap();

    let builder =
        CertificateBuilder::new(Profile::Root, serial, validity, subject, pub_key, signer).unwrap();
    builder.build().unwrap()
}

/// Produce a fully signed synthetic PE image.
fn build_signed_pe() -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let signer = SigningKey::<Sha256>::new(private_key.clone());

    let body = build_pe_body();
    let pe_hash = authenticode_hash(&body);

    let spc_der = build_spc_indirect_data(&pe_hash);
    let econtent = EncapsulatedContentInfo {
        econtent_type: ObjectIdentifier::from_str(OID_SPC_INDIRECT_DATA).unwrap(),
        econtent: Some(Any::from_der(&spc_der).unwrap()),
    };

    let certificate = build_certificate(&signer, &private_key);
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: certificate.tbs_certificate.issuer.clone(),
        serial_number: certificate.tbs_certificate.serial_number.clone(),
    });

    let signer_info_builder =
        SignerInfoBuilder::new(&signer, sid, sha256_alg_id(), &econtent, None).unwrap();

    let mut builder = SignedDataBuilder::new(&econtent);
    let content_info: ContentInfo = builder
        .add_digest_algorithm(sha256_alg_id())
        .unwrap()
        .add_certificate(CertificateChoices::Certificate(certificate))
        .unwrap()
        .add_signer_info::<SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info_builder)
        .unwrap()
        .build()
        .unwrap();

    let pkcs7 = content_info.to_der().unwrap();

    // Wrap the PKCS#7 blob in a WIN_CERTIFICATE structure.
    let mut win_cert = Vec::new();
    let dw_length = (8 + pkcs7.len()) as u32;
    win_cert.extend_from_slice(&dw_length.to_le_bytes());
    win_cert.extend_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    win_cert.extend_from_slice(&0x0002u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    win_cert.extend_from_slice(&pkcs7);
    while win_cert.len() % 8 != 0 {
        win_cert.push(0);
    }

    let mut file = body;
    file[SEC_ENTRY..SEC_ENTRY + 4].copy_from_slice(&(BODY_LEN as u32).to_le_bytes());
    file[SEC_ENTRY + 4..SEC_ENTRY + 8].copy_from_slice(&(win_cert.len() as u32).to_le_bytes());
    file.extend_from_slice(&win_cert);
    file
}

#[test]
fn authenticode_accepts_valid_signature() {
    let pe = build_signed_pe();
    assert_eq!(verify_pe_authenticode(&pe), AuthenticodeVerdict::Valid);
}

#[test]
fn authenticode_rejects_tampered_image() {
    let mut pe = build_signed_pe();
    // Flip a byte inside a hashed region; the PE hash must no longer match.
    pe[0x10] ^= 0xFF;
    match verify_pe_authenticode(&pe) {
        AuthenticodeVerdict::Invalid(_) => {}
        other => panic!("expected Invalid for tampered image, got {other:?}"),
    }
}

#[test]
fn authenticode_reports_unsigned_image() {
    // A well-formed PE with an empty security data directory is unsigned.
    let pe = build_pe_body();
    assert_eq!(
        verify_pe_authenticode(&pe),
        AuthenticodeVerdict::NoSignature
    );
}

#[test]
fn authenticode_rejects_garbage_certificate_table() {
    let mut pe = build_pe_body();
    let garbage = [0xDEu8; 64];
    pe[SEC_ENTRY..SEC_ENTRY + 4].copy_from_slice(&(BODY_LEN as u32).to_le_bytes());
    pe[SEC_ENTRY + 4..SEC_ENTRY + 8].copy_from_slice(&(garbage.len() as u32).to_le_bytes());
    pe.extend_from_slice(&garbage);
    match verify_pe_authenticode(&pe) {
        AuthenticodeVerdict::Invalid(_) => {}
        other => panic!("expected Invalid for garbage cert table, got {other:?}"),
    }
}

#[test]
fn authenticode_rejects_malformed_pe_headers() {
    let pe = vec![0u8; 8]; // far too small to contain PE headers
    match verify_pe_authenticode(&pe) {
        AuthenticodeVerdict::Invalid(_) => {}
        other => panic!("expected Invalid for malformed PE, got {other:?}"),
    }
}
