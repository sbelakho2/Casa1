//! Classic symmetric-cipher primitives for the CryptoAPI surface
//! (advapi32 `CryptEncrypt`/`CryptDecrypt`).
//!
//! Casa1's BCrypt layer covers SHA-2/AES; the legacy CryptoAPI ciphers
//! (RC2, RC4, 3DES) are implemented here with their documented
//! algorithms:
//!
//! - **RC4** — the classic KSA/PRGA stream cipher (an involution: the
//!   same function encrypts and decrypts).
//! - **DES / 3DES** — FIPS 46-3: the Data Encryption Standard Feistel
//!   network (IP/FP permutations, E expansion, S-boxes, P permutation,
//!   PC-1/PC-2 key schedule, EDE triple encryption).  `CALG_3DES` is the
//!   documented 8-byte-block CBC mode.
//! - **RC2** — RFC 2268: the PITABLE key expansion (with the effective
//!   key-length mask) and the 5+6+5 mixing rounds with the two mashing
//!   rounds.  `CALG_RC2` uses the full key length as the effective
//!   length; the RFC test vectors pin the implementation.
//!
//! MD5/SHA-1 digests ride the same crates the BCrypt layer already uses
//! (`md5`, `sha1`), so `CryptHashData`/`CryptGetHashParam` share the
//! hash machinery with the CNG surface.

/// RC4 key schedule (KSA) + PRGA applied to `data`.
///
/// The same function serves both directions: RC4 is an involution, so
/// encrypting with a key yields the plaintext when applied again.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j = 0u8;
    for i in 0..256 {
        let key_byte = if key.is_empty() {
            0
        } else {
            key[i % key.len()]
        };
        j = j.wrapping_add(s[i]).wrapping_add(key_byte);
        s.swap(i, j as usize);
    }
    let mut i = 0u8;
    j = 0;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        out.push(byte ^ k);
    }
    out
}

// ---------------------------------------------------------------------------
// DES / 3DES (FIPS 46-3)
// ---------------------------------------------------------------------------

/// DES initial permutation (IP), indexed by output bit position.
const IP_TABLE: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// DES final permutation (FP = IP⁻¹).
const FP_TABLE: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// DES expansion permutation (E): 32 → 48 bits.
const E_TABLE: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// DES S-boxes (8 boxes × 64 entries).
const S_BOXES: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// DES permutation P: 32 → 32 bits.
const P_TABLE: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

/// DES key schedule: PC-1 (64 → 56 bits).
const PC1_TABLE: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// DES key schedule: PC-2 (56 → 48 bits per round key).
const PC2_TABLE: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// DES key-schedule left shifts per round (1 or 2 positions).
const KEY_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// Apply a bit-permutation table to `input` (`input_width` bits, MSB-first
/// numbering — bit 1 is the most significant bit of the input).
fn des_permute(input: u64, input_width: u8, table: &[u8]) -> u64 {
    let mut output = 0u64;
    for (out_pos, &src_pos) in table.iter().enumerate() {
        let bit = (input >> (input_width as u32 - src_pos as u32)) & 1;
        output |= bit << (table.len() as u32 - 1 - out_pos as u32);
    }
    output
}

/// Expand a 64-bit key into the 16 round keys (each 48 bits).
fn des_key_schedule(key: u64) -> [u64; 16] {
    let permuted = des_permute(key, 64, &PC1_TABLE);
    let mut c = (permuted >> 28) & 0x0FFF_FFFF;
    let mut d = permuted & 0x0FFF_FFFF;
    let mut round_keys = [0u64; 16];
    for (round, shifts) in KEY_SHIFTS.iter().enumerate() {
        c = rotate_left28(c, *shifts);
        d = rotate_left28(d, *shifts);
        let cd = (c << 28) | d;
        round_keys[round] = des_permute(cd, 56, &PC2_TABLE);
    }
    round_keys
}

fn rotate_left28(value: u64, shifts: u8) -> u64 {
    ((value << shifts) | (value >> (28 - shifts as u32))) & 0x0FFF_FFFF
}

/// One DES block encryption (16 Feistel rounds), `encrypt = true` for
/// encryption (round keys in order), `false` for decryption (reversed).
fn des_block(block: u64, round_keys: &[u64; 16], encrypt: bool) -> u64 {
    let permuted = des_permute(block, 64, &IP_TABLE);
    let mut left = (permuted >> 32) & 0xFFFF_FFFF;
    let mut right = permuted & 0xFFFF_FFFF;
    for round in 0..16 {
        let key_index = if encrypt { round } else { 15 - round };
        let expanded = des_permute(right, 32, &E_TABLE) ^ round_keys[key_index];
        let mut s_output = 0u64;
        for (box_index, s_box) in S_BOXES.iter().enumerate() {
            let six = (expanded >> (42 - box_index as u32 * 6)) & 0x3F;
            let row = (((six >> 4) & 2) | (six & 1)) as usize;
            let column = ((six >> 1) & 0x0F) as usize;
            let value = s_box[row * 16 + column];
            s_output |= (value as u64) << (28 - box_index as u32 * 4);
        }
        let f = des_permute(s_output, 32, &P_TABLE);
        let new_right = left ^ f;
        left = right;
        right = new_right;
    }
    // Final swap: the last round leaves L16/R16; the preoutput is R16|L16.
    let preoutput = (right << 32) | left;
    des_permute(preoutput, 64, &FP_TABLE)
}

/// Single-DES CBC block operation on a full-block `data` (multiple of 8).
fn des_cbc(key: &[u8], iv: &[u8; 8], data: &[u8], encrypt: bool) -> Vec<u8> {
    debug_assert!(data.len().is_multiple_of(8));
    let mut key_64 = 0u64;
    for (index, &byte) in key.iter().take(8).enumerate() {
        key_64 |= (byte as u64) << (56 - index as u32 * 8);
    }
    let round_keys = des_key_schedule(key_64);
    let mut chain = u64::from_be_bytes(*iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let block = u64::from_be_bytes(chunk.try_into().expect("8-byte DES block"));
        let result = if encrypt {
            let xored = block ^ chain;
            let encrypted = des_block(xored, &round_keys, true);
            chain = encrypted;
            encrypted
        } else {
            let decrypted = des_block(block, &round_keys, false);
            let plain = decrypted ^ chain;
            chain = block;
            plain
        };
        out.extend_from_slice(&result.to_be_bytes());
    }
    out
}

/// Single-DES CBC (`CALG_DES`): 8-byte blocks, PKCS#7-style padding is
/// handled by the CryptoAPI layer (data must be a multiple of 8 here).
pub fn des_cbc_public(key: &[u8], iv: &[u8; 8], data: &[u8], encrypt: bool) -> Vec<u8> {
    des_cbc(key, iv, data, encrypt)
}

/// 3DES-EDE-CBC (FIPS 46-3): encrypt with K1, decrypt with K2, encrypt
/// with K3.  A 24-byte key supplies K1/K2/K3; a 16-byte key uses
/// K3 = K1 (`CALG_3DES` accepts both).  `data` must be a multiple of the
/// 8-byte block size (the CryptoAPI layer pads).
pub fn triple_des_cbc(key: &[u8], iv: &[u8; 8], data: &[u8], encrypt: bool) -> Vec<u8> {
    let k1 = &key[..8];
    let k2 = &key[8..16];
    let k3 = if key.len() >= 24 { &key[16..24] } else { k1 };
    if encrypt {
        let first = des_cbc(k1, iv, data, true);
        let middle = des_cbc(k2, iv, &first, false);
        des_cbc(k3, iv, &middle, true)
    } else {
        let first = des_cbc(k3, iv, data, false);
        let middle = des_cbc(k2, iv, &first, true);
        des_cbc(k1, iv, &middle, false)
    }
}

// ---------------------------------------------------------------------------
// RC2 (RFC 2268)
// ---------------------------------------------------------------------------

/// RC2 PITABLE (RFC 2268 §2) — a random permutation of 0..255 derived
/// from the digits of π.
const RC2_PITABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

/// RC2 key expansion (RFC 2268 §2): 128 bytes of key buffer viewed as
/// the 64 little-endian words K[0..63].  `effective_bits` is the T1
/// parameter (1..=1024; the full key length for `CALG_RC2`).
fn rc2_expand(key: &[u8], effective_bits: u32) -> [u16; 64] {
    let mut l = [0u8; 128];
    let t = key.len().min(128);
    l[..t].copy_from_slice(&key[..t]);
    for index in t..128 {
        l[index] = RC2_PITABLE[(l[index - 1].wrapping_add(l[index - t])) as usize];
    }
    let t1 = effective_bits.clamp(1, 1024);
    let t8 = t1.div_ceil(8) as usize;
    // TM = 255 MOD 2^(8 + T1 - 8*T8): the low (8 - (8*T8 - T1)) bits are
    // set; when 8*T8 == T1 the mask is all bits set.
    let clear_bits = 8 * t8 as u32 - t1;
    let tm = if clear_bits == 0 {
        0xFFu8
    } else {
        0xFFu8 >> clear_bits
    };
    l[128 - t8] = RC2_PITABLE[(l[128 - t8] & tm) as usize];
    for index in (0..128 - t8).rev() {
        l[index] = RC2_PITABLE[(l[index + 1] ^ l[index + t8]) as usize];
    }
    let mut k = [0u16; 64];
    for (word_index, word) in k.iter_mut().enumerate() {
        *word = l[word_index * 2] as u16 | ((l[word_index * 2 + 1] as u16) << 8);
    }
    k
}

/// RC2 rotation of the shifts s[0..3] = 1, 2, 3, 5.
const RC2_SHIFTS: [u16; 4] = [1, 2, 3, 5];

/// One RC2 block (8 bytes) — `encrypt` selects the forward (RFC 2268 §3)
/// or reverse (§4) round sequence.
fn rc2_block(expanded: &[u16; 64], input: &[u8; 8], encrypt: bool) -> [u8; 8] {
    let mut r = [
        u16::from_le_bytes([input[0], input[1]]),
        u16::from_le_bytes([input[2], input[3]]),
        u16::from_le_bytes([input[4], input[5]]),
        u16::from_le_bytes([input[6], input[7]]),
    ];

    // The RFC 2268 composite word (R[i-1] & R[i-2]) + ((~R[i-1]) & R[i-3])
    // with the R indices taken modulo 4.
    let composite = |r: &[u16; 4], i: usize| {
        (r[(i + 3) % 4] & r[(i + 2) % 4]).wrapping_add(!r[(i + 3) % 4] & r[(i + 1) % 4])
    };

    let mix = |r: &mut [u16; 4], j: &mut isize| {
        if encrypt {
            for i in 0..4 {
                r[i] = r[i]
                    .wrapping_add(expanded[*j as usize])
                    .wrapping_add(composite(r, i));
                *j += 1;
                r[i] = r[i].rotate_left(RC2_SHIFTS[i].into());
            }
        } else {
            for i in (0..4).rev() {
                r[i] = r[i].rotate_right(RC2_SHIFTS[i].into());
                // RFC 2268 §4.1: subtract K[j] with the CURRENT j, then
                // decrement — j runs 63 down to 0 across the 64 r-mixes.
                r[i] = r[i]
                    .wrapping_sub(expanded[*j as usize])
                    .wrapping_sub(composite(r, i));
                *j -= 1;
            }
        }
    };

    if encrypt {
        let mut j = 0isize;
        // 5 mixing rounds.
        for _ in 0..5 {
            mix(&mut r, &mut j);
        }
        // 1 mashing round.
        for i in 0..4 {
            r[i] = r[i].wrapping_add(expanded[(r[(i + 3) % 4] & 63) as usize]);
        }
        // 6 mixing rounds.
        for _ in 0..6 {
            mix(&mut r, &mut j);
        }
        // 1 mashing round.
        for i in 0..4 {
            r[i] = r[i].wrapping_add(expanded[(r[(i + 3) % 4] & 63) as usize]);
        }
        // 5 mixing rounds.
        for _ in 0..5 {
            mix(&mut r, &mut j);
        }
        debug_assert_eq!(j, 64);
    } else {
        let mut j = 63isize;
        // 5 r-mixing rounds.
        for _ in 0..5 {
            mix(&mut r, &mut j);
        }
        // 1 r-mashing round.
        for i in (0..4).rev() {
            r[i] = r[i].wrapping_sub(expanded[(r[(i + 3) % 4] & 63) as usize]);
        }
        // 6 r-mixing rounds.
        for _ in 0..6 {
            mix(&mut r, &mut j);
        }
        // 1 r-mashing round.
        for i in (0..4).rev() {
            r[i] = r[i].wrapping_sub(expanded[(r[(i + 3) % 4] & 63) as usize]);
        }
        // 5 r-mixing rounds.
        for _ in 0..5 {
            mix(&mut r, &mut j);
        }
        debug_assert_eq!(j, -1);
    }

    [
        r[0].to_le_bytes()[0],
        r[0].to_le_bytes()[1],
        r[1].to_le_bytes()[0],
        r[1].to_le_bytes()[1],
        r[2].to_le_bytes()[0],
        r[2].to_le_bytes()[1],
        r[3].to_le_bytes()[0],
        r[3].to_le_bytes()[1],
    ]
}

/// RC2-CBC (RFC 2268 with the §6 CBC parameterization).  `data` must be
/// a multiple of the 8-byte block size (the CryptoAPI layer pads).
pub fn rc2_cbc(
    key: &[u8],
    effective_bits: u32,
    iv: &[u8; 8],
    data: &[u8],
    encrypt: bool,
) -> Vec<u8> {
    let expanded = rc2_expand(key, effective_bits);
    let mut chain = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let block: [u8; 8] = chunk.try_into().expect("8-byte RC2 block");
        let result = if encrypt {
            let xored: [u8; 8] = std::array::from_fn(|index| block[index] ^ chain[index]);
            let encrypted = rc2_block(&expanded, &xored, true);
            chain = encrypted;
            encrypted
        } else {
            let decrypted = rc2_block(&expanded, &block, false);
            let plain: [u8; 8] = std::array::from_fn(|index| decrypted[index] ^ chain[index]);
            chain = block;
            plain
        };
        out.extend_from_slice(&result);
    }
    out
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// MD5 digest (16 bytes) — the `md5` crate the BCrypt layer already uses.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut context = md5::Context::new();
    context.consume(data);
    let digest = context.compute();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..]);
    out
}

/// SHA-1 digest (20 bytes) — the `sha1` crate.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest as _;
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_known_vector() {
        // Wikipedia RC4 test vector: key "Key", plaintext "Plaintext".
        let ciphertext = rc4(b"Key", b"Plaintext");
        assert_eq!(
            ciphertext,
            vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
        );
        assert_eq!(rc4(b"Key", &ciphertext), b"Plaintext");
    }

    #[test]
    fn rc4_round_trip_and_involution() {
        let key = b"casa1-secret";
        let plain = b"the quick brown fox jumps over the lazy dog";
        let cipher = rc4(key, plain);
        assert_ne!(cipher, plain.to_vec());
        assert_eq!(rc4(key, &cipher), plain);
        assert_eq!(rc4(b"", b""), Vec::<u8>::new());
    }

    #[test]
    fn des_known_vector() {
        // FIPS 81 / NIST test: key 0x133457799BBCDFF1, block 0x0123456789ABCDEF
        // encrypts to 0x85E813540F0AB405.
        let key_bytes = 0x1334_5779_9BBC_DFF1u64;
        let block = 0x0123_4567_89AB_CDEFu64;
        let mut key_arr = [0u8; 8];
        key_arr.copy_from_slice(&key_bytes.to_be_bytes());
        let iv = [0u8; 8];
        let mut input = [0u8; 8];
        input.copy_from_slice(&block.to_be_bytes());
        let out = des_cbc(&key_arr, &iv, &input, true);
        assert_eq!(
            u64::from_be_bytes(out.as_slice().try_into().unwrap()),
            0x85E8_1354_0F0A_B405
        );
        let back = des_cbc(&key_arr, &iv, &out, false);
        assert_eq!(back, input);
    }

    #[test]
    fn triple_des_round_trip() {
        let key = b"0123456789abcdef01234567"; // 24 bytes: K1 K2 K3
        let mut iv = [0xAA; 8];
        iv[0] = 0;
        let plain = b"blockdat"; // 8 bytes
        let cipher = triple_des_cbc(key, &iv, plain, true);
        assert_ne!(cipher, plain.to_vec());
        assert_eq!(triple_des_cbc(key, &iv, &cipher, false), plain);
        // 16-byte key form (K3 = K1).
        let short_key = b"0123456789abcdef";
        let cipher16 = triple_des_cbc(short_key, &iv, plain, true);
        assert_eq!(triple_des_cbc(short_key, &iv, &cipher16, false), plain);
    }

    #[test]
    fn rc2_matches_rfc2268_test_vectors() {
        // RFC 2268 §5 vectors (single block, CBC with a zero IV).
        let zero_iv = [0u8; 8];
        type Vector = (&'static [u8], u32, &'static [u8; 8], &'static [u8; 8]);
        let vectors: &[Vector] = &[
            (
                &[0u8; 8],
                63,
                &[0u8; 8],
                &[0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff],
            ),
            (
                &[0xff; 8],
                64,
                &[0xff; 8],
                &[0x27, 0x8b, 0x27, 0xe4, 0x2e, 0x2f, 0x0d, 0x49],
            ),
            (
                &[0x30, 0, 0, 0, 0, 0, 0, 0],
                64,
                &[0x10, 0, 0, 0, 0, 0, 0, 1],
                &[0x30, 0x64, 0x9e, 0xdf, 0x9b, 0xe7, 0xd2, 0xc2],
            ),
            (
                &[0x88],
                64,
                &[0u8; 8],
                &[0x61, 0xa8, 0xa2, 0x44, 0xad, 0xac, 0xcc, 0xf0],
            ),
            (
                &[0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a],
                64,
                &[0u8; 8],
                &[0x6c, 0xcf, 0x43, 0x08, 0x97, 0x4c, 0x26, 0x7f],
            ),
            (
                &[
                    0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f, 0x79, 0xc3, 0x84, 0x62,
                    0x7b, 0xaf, 0xb2,
                ],
                64,
                &[0u8; 8],
                &[0x1a, 0x80, 0x7d, 0x27, 0x2b, 0xbe, 0x5d, 0xb1],
            ),
            (
                &[
                    0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f, 0x79, 0xc3, 0x84, 0x62,
                    0x7b, 0xaf, 0xb2,
                ],
                128,
                &[0u8; 8],
                &[0x22, 0x69, 0x55, 0x2a, 0xb0, 0xf8, 0x5c, 0xa6],
            ),
        ];
        for (key, effective, plaintext, expected) in vectors {
            let ciphertext = rc2_cbc(key, *effective, &zero_iv, *plaintext, true);
            assert_eq!(&ciphertext, expected, "RFC 2268 vector (T1 = {effective})");
            let back = rc2_cbc(key, *effective, &zero_iv, &ciphertext, false);
            assert_eq!(&back, *plaintext);
        }
    }

    #[test]
    fn rc2_round_trip_and_iv_behavior() {
        let key = b"rc2key";
        let iv = [0x10; 8];
        let plain = b"12345678";
        let cipher = rc2_cbc(key, 40, &iv, plain, true);
        assert_ne!(cipher, plain.to_vec());
        assert_eq!(rc2_cbc(key, 40, &iv, &cipher, false), plain);
        // Different IV → different ciphertext (CBC chaining is live).
        let mut other_iv = iv;
        other_iv[0] ^= 0xFF;
        let other = rc2_cbc(key, 40, &other_iv, plain, true);
        assert_ne!(other, cipher);
    }

    #[test]
    fn rc2_cbc_multiblock_chaining() {
        let key = b"k";
        let iv = [0u8; 8];
        let plain = b"abcdefghijklmnop"; // 2 blocks
        let cipher = rc2_cbc(key, 40, &iv, plain, true);
        assert_eq!(cipher.len(), 16);
        assert_eq!(rc2_cbc(key, 40, &iv, &cipher, false), plain);
    }

    #[test]
    fn md5_and_sha1_known_digests() {
        // RFC 1321: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
        // FIPS 180-1: SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        assert_eq!(md5(b"").len(), 16);
        assert_eq!(sha1(b"").len(), 20);
    }
}
