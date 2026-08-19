//! The Windows differential-oracle reference executable.
//!
//! Usage: `casa1-windows-reference <vectors.json> <results.json>`
//!
//! Reads a schema-version-1 vector file, executes every vector with REAL
//! Win32/CRT calls (never reimplemented semantics — this binary IS Windows),
//! and writes a canonical results file with a capture header recording the
//! ACTUAL capture provenance: os edition/build/architecture from
//! RtlGetVersion/GetNativeSystemInfo/the registry, plus the SHA-256 of the
//! reference executable itself and of the vector corpus. Vectors are
//! executed strictly in file order (the `crt_printf` corpus depends on the
//! UCRT invalid-parameter handler and %n state evolving across vectors).

mod exec;
mod schema;

use schema::{CaptureHeader, CaptureProvenance, Result, ResultsFile, SCHEMA_VERSION, VectorFile};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "usage: {} <vectors.json> <results.json>",
            args.first()
                .map(String::as_str)
                .unwrap_or("casa1-windows-reference")
        );
        std::process::exit(2);
    }
    let vectors_bytes = std::fs::read(&args[1]).unwrap_or_else(|error| {
        eprintln!("failed to read vectors file {}: {error}", args[1]);
        std::process::exit(2);
    });
    let vector_file: VectorFile = serde_json::from_slice(&vectors_bytes).unwrap_or_else(|error| {
        eprintln!("failed to parse vectors file {}: {error}", args[1]);
        std::process::exit(2);
    });
    if vector_file.schema_version != SCHEMA_VERSION {
        eprintln!(
            "vector file schema_version {} does not match protocol version {}",
            vector_file.schema_version, SCHEMA_VERSION
        );
        std::process::exit(2);
    }
    let results: Vec<Result> = vector_file
        .vectors
        .iter()
        .map(|vector| Result {
            id: vector.id.clone(),
            category: vector.category.clone(),
            output: exec::execute(&vector.category, &vector.input),
        })
        .collect();
    let out = ResultsFile {
        schema_version: SCHEMA_VERSION,
        capture: CaptureHeader::windows_capture(capture_provenance(&vectors_bytes)),
        results,
    };
    let json = serde_json::to_string_pretty(&out).expect("encode results");
    std::fs::write(&args[2], format!("{json}\n")).unwrap_or_else(|error| {
        eprintln!("failed to write results file {}: {error}", args[2]);
        std::process::exit(2);
    });
    eprintln!("wrote {} results to {}", out.results.len(), args[2]);
}

/// Actual capture provenance: the machine's os edition/build/arch plus the
/// SHA-256s of the reference executable and the input corpus.
fn capture_provenance(corpus_bytes: &[u8]) -> CaptureProvenance {
    let reference_sha256 = std::fs::read(std::env::current_exe().expect("current exe path"))
        .map(|bytes| sha256_hex(&bytes))
        .unwrap_or_default();
    CaptureProvenance {
        os_edition: os_edition(),
        os_build: os_build(),
        arch: arch_name(),
        reference_sha256,
        corpus_sha256: sha256_hex(corpus_bytes),
    }
}

#[cfg(windows)]
fn os_edition() -> String {
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EditionID, e.g.
    // "Professional" / "Home" / "Enterprise".
    use std::ffi::c_void;
    type HKEY = *mut c_void;
    type DWORD = u32;
    type LPCWSTR = *const u16;
    type LPBYTE = *mut u8;
    type LPDWORD = *mut u32;
    type LONG = i32;
    const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002usize as HKEY;
    const KEY_READ: DWORD = 0x20019;
    const ERROR_SUCCESS: LONG = 0;
    const ERROR_MORE_DATA: DWORD = 234;

    #[link(name = "advapi32")]
    unsafe extern "C" {
        fn RegOpenKeyExW(
            key: HKEY,
            sub_key: LPCWSTR,
            reserved: DWORD,
            desired_access: DWORD,
            result: *mut HKEY,
        ) -> LONG;
        fn RegQueryValueExW(
            key: HKEY,
            value_name: LPCWSTR,
            reserved: *mut DWORD,
            value_type: *mut DWORD,
            data: LPBYTE,
            data_size: *mut DWORD,
        ) -> LONG;
        fn RegCloseKey(key: HKEY) -> LONG;
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let mut key: HKEY = std::ptr::null_mut();
    let path = wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
    if status != ERROR_SUCCESS || key.is_null() {
        return "unknown".to_string();
    }
    let name = wide("EditionID");
    let mut buffer = vec![0_u16; 64];
    let mut size = (buffer.len() * 2) as DWORD;
    let mut value_type: DWORD = 0;
    let query_status = unsafe {
        RegQueryValueExW(
            key,
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut value_type,
            buffer.as_mut_ptr() as LPBYTE,
            &mut size,
        )
    };
    let mut edition = String::new();
    if query_status == ERROR_SUCCESS {
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(buffer.len());
        edition = String::from_utf16_lossy(&buffer[..end]);
    } else if query_status as u32 == ERROR_MORE_DATA && size > 0 {
        // Retry with the required size.
        let mut buffer = vec![0_u16; ((size as usize + 1) / 2).max(1)];
        let mut retry_size = size;
        let retry_status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut value_type,
                buffer.as_mut_ptr() as LPBYTE,
                &mut retry_size,
            )
        };
        if retry_status == ERROR_SUCCESS {
            let end = buffer
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(buffer.len());
            edition = String::from_utf16_lossy(&buffer[..end]);
        }
    }
    unsafe {
        RegCloseKey(key);
    }
    if edition.is_empty() {
        "unknown".to_string()
    } else {
        edition
    }
}

#[cfg(not(windows))]
fn os_edition() -> String {
    "unknown".to_string()
}

#[cfg(windows)]
fn os_build() -> String {
    // RtlGetVersion (ntdll) — the real NT version, unaffected by
    // compatibility shims that GetVersionExW would report.
    #[repr(C)]
    struct RtlOsVersionInfoW {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform_id: u32,
        csd: [u16; 128],
    }
    #[link(name = "ntdll")]
    unsafe extern "C" {
        fn RtlGetVersion(info: *mut RtlOsVersionInfoW) -> i32;
    }
    let mut info = RtlOsVersionInfoW {
        size: std::mem::size_of::<RtlOsVersionInfoW>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform_id: 0,
        csd: [0; 128],
    };
    let status = unsafe { RtlGetVersion(&mut info) };
    if status == 0 {
        format!("{}.{}.{}", info.major, info.minor, info.build)
    } else {
        "unknown".to_string()
    }
}

#[cfg(not(windows))]
fn os_build() -> String {
    "unknown".to_string()
}

#[cfg(windows)]
fn arch_name() -> String {
    #[repr(C)]
    struct SystemInfo {
        processor_architecture: u16,
        reserved: u16,
        page_size: u32,
        minimum_application_address: *mut std::ffi::c_void,
        maximum_application_address: *mut std::ffi::c_void,
        active_processor_mask: usize,
        number_of_processors: u32,
        processor_type: u32,
        allocation_granularity: u32,
        processor_level: u16,
        processor_revision: u16,
    }
    #[link(name = "kernel32")]
    unsafe extern "C" {
        fn GetNativeSystemInfo(info: *mut SystemInfo);
    }
    const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
    const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
    const PROCESSOR_ARCHITECTURE_ARM64: u16 = 12;
    let mut info = SystemInfo {
        processor_architecture: 0,
        reserved: 0,
        page_size: 0,
        minimum_application_address: std::ptr::null_mut(),
        maximum_application_address: std::ptr::null_mut(),
        active_processor_mask: 0,
        number_of_processors: 0,
        processor_type: 0,
        allocation_granularity: 0,
        processor_level: 0,
        processor_revision: 0,
    };
    unsafe { GetNativeSystemInfo(&mut info) };
    match info.processor_architecture {
        PROCESSOR_ARCHITECTURE_INTEL => "x86".to_string(),
        PROCESSOR_ARCHITECTURE_AMD64 => "x64".to_string(),
        PROCESSOR_ARCHITECTURE_ARM64 => "arm64".to_string(),
        other => format!("unknown-{other}"),
    }
}

#[cfg(not(windows))]
fn arch_name() -> String {
    std::env::consts::ARCH.to_string()
}

/// SHA-256 (lowercase hex) — self-contained so the standalone reference
/// crate keeps its zero-dependency guarantee.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut message = data.to_vec();
    let bit_len = (message.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut hash = H0;
    for chunk in message.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (index, word) in chunk.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }
    hash.iter().map(|word| format!("{word:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
