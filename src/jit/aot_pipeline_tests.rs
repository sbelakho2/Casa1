//! Adversarial coverage for the persistent AOT install/update pipeline.

use super::*;
use crate::cpu::IrInstruction;
use crate::jit::aot_profile::{profile_file_path, profile_fnv1a, write_atomic_failing_for_test};
use std::assert_matches;
use std::fs;
use std::path::{Path, PathBuf};

fn pipeline_key(image_hash: &str) -> ProfileKey {
    ProfileKey::new(image_hash, AOT_TRANSLATOR_VERSION, aot_target_cpu_profile())
}

fn populated_targets() -> ProfileTargets {
    let mut targets = ProfileTargets::default();
    targets.record(ProfileTargetKind::HotBlock, 0x1000, 3);
    targets.record(ProfileTargetKind::DirectCall, 0x1010, 2);
    targets.record(ProfileTargetKind::IndirectCall, 0x1020, 5);
    targets.record(ProfileTargetKind::FunctionEntry, 0x1030, 1);
    targets
}

#[test]
fn profile_round_trip_and_corrupt_copy_rejected_with_exact_checksum_error() {
    let directory = tempfile::tempdir().expect("tempdir");
    let key = pipeline_key("image-round-trip");
    let targets = populated_targets();
    let path = profile_file_path(directory.path(), &key);
    store_profile_file(&path, &key, &targets).expect("store profile");
    let loaded = load_profile_file(&path, &key)
        .expect("load profile")
        .expect("profile exists");
    assert_eq!(loaded, targets);
    assert_eq!(loaded.address_count(), 4);

    let mut bytes = fs::read(&path).expect("read profile");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&path, &bytes).expect("corrupt profile");
    let error = load_profile_file(&path, &key).expect_err("corrupt profile must be rejected");
    assert_matches!(error, ProfileError::ChecksumMismatch { .. });
}

#[test]
fn runtime_profile_persistence_round_trips_targets_and_rejects_wrong_key() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut writer = JitRuntime::new(GuestArch::X64);
    writer
        .configure_aot_pipeline(directory.path(), "image-runtime")
        .expect("configure writer");
    writer.record_profile_execution(
        0x1000,
        &[
            IrInstruction::Call {
                target: 0x1010,
                return_address: 0x1005,
            },
            IrInstruction::CallRegister {
                src: crate::cpu::Register::Rax,
                return_address: 0x1020,
            },
        ],
        0x2020,
    );
    assert_eq!(writer.persist_aot_profile(&[(0x1000, 9)]), Ok(3));

    let mut reader = JitRuntime::new(GuestArch::X64);
    reader
        .configure_aot_pipeline(directory.path(), "image-runtime")
        .expect("configure reader");
    assert_eq!(reader.load_aot_profile(), Ok(3));
    let targets = reader.aot_profile_targets();
    assert_eq!(targets.get(ProfileTargetKind::HotBlock, 0x1000), Some(9));
    assert_eq!(targets.get(ProfileTargetKind::DirectCall, 0x1010), Some(1));
    assert_eq!(
        targets.get(ProfileTargetKind::FunctionEntry, 0x1010),
        Some(1)
    );
    assert_eq!(
        targets.get(ProfileTargetKind::IndirectCall, 0x2020),
        Some(1)
    );

    let mut stale = JitRuntime::new(GuestArch::X64);
    stale
        .configure_aot_pipeline(directory.path(), "image-different")
        .expect("configure stale reader");
    // Point the stale reader at the valid record: its key must reject the
    // matching checksum instead of loading it.
    stale.aot_profile_path = Some(profile_file_path(
        directory.path(),
        &pipeline_key("image-runtime"),
    ));
    assert_matches!(
        stale.load_aot_profile(),
        Err(ProfileError::ImageHashMismatch { .. })
    );
}

#[test]
fn stale_profile_wrong_image_translator_and_cpu_are_rejected_with_exact_reasons() {
    let directory = tempfile::tempdir().expect("tempdir");
    let key = pipeline_key("image-stale");
    let path = profile_file_path(directory.path(), &key);
    store_profile_file(&path, &key, &populated_targets()).expect("store profile");

    let wrong_image = pipeline_key("image-other");
    assert_eq!(
        load_profile_file(&path, &wrong_image),
        Err(ProfileError::ImageHashMismatch {
            found: "image-stale".to_string(),
            expected: "image-other".to_string(),
        })
    );

    let wrong_translator = ProfileKey::new(
        "image-stale",
        AOT_TRANSLATOR_VERSION + 1,
        aot_target_cpu_profile(),
    );
    assert_eq!(
        load_profile_file(&path, &wrong_translator),
        Err(ProfileError::TranslatorMismatch {
            found: AOT_TRANSLATOR_VERSION,
            expected: AOT_TRANSLATOR_VERSION + 1,
        })
    );

    let wrong_cpu = ProfileKey::new(
        "image-stale",
        AOT_TRANSLATOR_VERSION,
        aot_target_cpu_profile() ^ 0x5a5a,
    );
    assert_eq!(
        load_profile_file(&path, &wrong_cpu),
        Err(ProfileError::CpuProfileMismatch {
            found: aot_target_cpu_profile(),
            expected: aot_target_cpu_profile() ^ 0x5a5a,
        })
    );
}

#[test]
fn truncated_profile_record_is_rejected_with_exact_truncated_error() {
    let key = pipeline_key("image-truncated");
    let mut bytes = populated_targets().encode(&key).expect("encode profile");
    // Drop four bytes of a record table and re-seal, isolating the structural
    // truncation check from the checksum check.
    let mut body = bytes[..bytes.len() - 8].to_vec();
    body.truncate(body.len() - 4);
    let checksum = profile_fnv1a(&body);
    body.extend_from_slice(&checksum.to_le_bytes());
    bytes = body;
    assert_eq!(
        ProfileTargets::decode(&bytes, &key),
        Err(ProfileError::Truncated("records"))
    );
}

fn reseal(bytes: &mut [u8]) {
    let payload = bytes.len() - 8;
    let checksum = profile_fnv1a(&bytes[..payload]);
    bytes[payload..].copy_from_slice(&checksum.to_le_bytes());
}

#[test]
fn malformed_profile_bad_magic_format_kind_and_trailing_bytes_are_rejected_exactly() {
    let key = pipeline_key("image-malformed");
    let valid = populated_targets().encode(&key).expect("encode profile");

    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    assert_eq!(
        ProfileTargets::decode(&bad_magic, &key),
        Err(ProfileError::BadMagic)
    );

    let mut bad_format = valid.clone();
    bad_format[8..12].copy_from_slice(&(AOT_PROFILE_FORMAT_VERSION + 1).to_le_bytes());
    reseal(&mut bad_format);
    assert_eq!(
        ProfileTargets::decode(&bad_format, &key),
        Err(ProfileError::UnsupportedFormat {
            found: AOT_PROFILE_FORMAT_VERSION + 1,
            expected: AOT_PROFILE_FORMAT_VERSION,
        })
    );

    // Records begin after magic+format+translator+cpu+hash length+hash+count.
    let records = 8 + 4 + 4 + 8 + 2 + key.image_hash.len() + 4;
    let mut bad_kind = valid.clone();
    bad_kind[records] = 9;
    reseal(&mut bad_kind);
    assert_eq!(
        ProfileTargets::decode(&bad_kind, &key),
        Err(ProfileError::UnknownTargetKind(9))
    );

    let count_offset = 8 + 4 + 4 + 8 + 2 + key.image_hash.len();
    let mut trailing = valid.clone();
    trailing[count_offset..count_offset + 4].copy_from_slice(&3u32.to_le_bytes());
    reseal(&mut trailing);
    assert_eq!(
        ProfileTargets::decode(&trailing, &key),
        Err(ProfileError::TrailingBytes)
    );

    assert_eq!(
        ProfileTargets::default().encode(&ProfileKey::new("bad/hash", 1, 2)),
        Err(ProfileError::InvalidImageHash("bad/hash".to_string()))
    );
    let sanitized = profile_file_path(
        Path::new("/tmp/casa1-profile"),
        &ProfileKey::new("bad/hash", 1, 2),
    );
    let expected = format!("bad_hash-t1-c{:016x}", 2);
    assert_eq!(
        sanitized
            .parent()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str()),
        Some(expected.as_str())
    );
}

#[test]
fn partial_profile_write_keeps_previous_record_and_never_leaves_temporary() {
    let directory = tempfile::tempdir().expect("tempdir");
    let key = pipeline_key("image-atomic");
    let path = profile_file_path(directory.path(), &key);
    let original = populated_targets();
    store_profile_file(&path, &key, &original).expect("store original");
    let before = fs::read(&path).expect("read original");

    let mut replacement = ProfileTargets::default();
    replacement.record(ProfileTargetKind::HotBlock, 0x9000, 1);
    let encoded = replacement.encode(&key).expect("encode replacement");
    let error = write_atomic_failing_for_test(&path, &encoded, 3)
        .expect_err("injected partial write must fail");
    assert_matches!(error, ProfileError::Io(_));
    assert_eq!(fs::read(&path).expect("read after failure"), before);
    let leftovers = fs::read_dir(path.parent().expect("parent"))
        .expect("list cache")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
        .count();
    assert_eq!(
        leftovers, 0,
        "a failed atomic write must leave no temp file"
    );
}

#[test]
fn smc_invalidation_clears_profile_targets_and_never_reseeds_stale_code() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut runtime = JitRuntime::new(GuestArch::X64);
    runtime
        .configure_aot_pipeline(directory.path(), "image-smc")
        .expect("configure pipeline");
    runtime.record_profile_execution(
        0x1000,
        &[
            IrInstruction::Call {
                target: 0x1010,
                return_address: 0x1005,
            },
            IrInstruction::Nop,
        ],
        0x1010,
    );
    assert_eq!(
        runtime
            .aot_profile_targets()
            .get(ProfileTargetKind::DirectCall, 0x1010),
        Some(1)
    );
    assert_eq!(
        runtime
            .aot_profile_targets()
            .get(ProfileTargetKind::FunctionEntry, 0x1010),
        Some(1)
    );

    let mut dirty = std::collections::BTreeSet::new();
    dirty.insert(0x1000_u64);
    runtime.invalidate_blocks_on_pages(&dirty);
    assert_eq!(
        runtime
            .aot_profile_targets()
            .get(ProfileTargetKind::DirectCall, 0x1010),
        None
    );
    assert_eq!(
        runtime
            .aot_profile_targets()
            .get(ProfileTargetKind::FunctionEntry, 0x1010),
        None
    );
    assert_eq!(runtime.aot_profile_targets().contains(0x1000), false);
}

#[test]
fn concurrent_profile_readers_never_observe_a_partial_record() {
    let directory = tempfile::tempdir().expect("tempdir");
    let key = pipeline_key("image-concurrent");
    let path = profile_file_path(directory.path(), &key);
    let first = populated_targets();
    let mut second = ProfileTargets::default();
    second.record(ProfileTargetKind::HotBlock, 0x7000, 7);
    store_profile_file(&path, &key, &first).expect("seed profile");

    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..64 {
                store_profile_file(&path, &key, &first).expect("atomic store first");
                store_profile_file(&path, &key, &second).expect("atomic store second");
            }
        });
        for _ in 0..4 {
            let path = &path;
            let key = &key;
            scope.spawn(move || {
                for _ in 0..128 {
                    let loaded = load_profile_file(path, key)
                        .expect("concurrent read must never fail")
                        .expect("concurrent read must see a complete record");
                    assert_eq!(loaded.address_count() > 0, true);
                }
            });
        }
    });
}

/// Build a minimal PE32+ image with one executable section.
fn synthetic_image(path: &Path) -> u64 {
    let mut code = Vec::new();
    // 0x1000: call 0x1010; 0x1005: ret
    code.extend_from_slice(&[0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3]);
    // 0x1006..0x100F: nops
    code.extend_from_slice(&[0x90; 10]);
    // 0x1010: nop; ret
    code.extend_from_slice(&[0x90, 0xC3]);

    let mut pe = vec![0u8; 0x200];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    pe[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    pe[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
    pe[coff + 16..coff + 18].copy_from_slice(&0xF0_u16.to_le_bytes());
    pe[coff + 18..coff + 20].copy_from_slice(&0x0022_u16.to_le_bytes());
    let opt = coff + 20;
    pe[opt..opt + 2].copy_from_slice(&0x020B_u16.to_le_bytes());
    pe[opt + 16..opt + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    pe[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    pe[opt + 32..opt + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    pe[opt + 36..opt + 40].copy_from_slice(&0x200_u32.to_le_bytes());
    pe[opt + 56..opt + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
    pe[opt + 60..opt + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    pe[opt + 68..opt + 70].copy_from_slice(&3_u16.to_le_bytes());
    pe[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());
    let section = opt + 0xF0;
    pe[section..section + 8].copy_from_slice(b".text\0\0\0");
    pe[section + 8..section + 12].copy_from_slice(&(code.len() as u32).to_le_bytes());
    pe[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
    pe[section + 16..section + 20].copy_from_slice(&0x200_u32.to_le_bytes());
    pe[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
    pe[section + 36..section + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    pe.resize(0x200, 0);
    pe.extend_from_slice(&code);
    pe.resize(0x400, 0);
    fs::write(path, &pe).expect("write synthetic image");
    0x1_4000_0000_u64 + 0x1000
}

#[test]
fn precompile_only_builds_exact_cache_without_guest_entry_and_warm_run_avoids_fallback() {
    let directory = tempfile::tempdir().expect("tempdir");
    let program = directory.path().join("synthetic.exe");
    synthetic_image(&program);
    let cache_root = directory.path().join("cache");

    let cold = crate::pe_runtime::precompile_only_image(&program, &cache_root, true)
        .expect("precompile-only cold pass");
    assert_eq!(cold.image_hash.len(), 64);
    assert_eq!(cold.blocks_precompiled, 3);
    assert_eq!(cold.aot_hits, 0);
    assert_eq!(cold.aot_misses, 3);
    assert_eq!(cold.aot_rejected, 0);
    assert_eq!(Path::new(&cold.profile_path).is_file(), true);

    let warm = crate::pe_runtime::precompile_only_image(&program, &cache_root, true)
        .expect("precompile-only warm pass");
    assert_eq!(warm.blocks_precompiled, 3);
    assert_eq!(warm.aot_hits, 3);
    assert_eq!(warm.aot_misses, 0);
    let ratio = warm.aot_hits as f64 / (warm.aot_hits + warm.aot_misses) as f64;
    assert_eq!(ratio >= 0.90, true, "warm-run AOT hit ratio {ratio}");

    // A cache record copied under another image key is rejected before its
    // code is installed.
    let cache_dir = PathBuf::from(&cold.cache_dir);
    let record_path = fs::read_dir(&cache_dir)
        .expect("cache dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|extension| extension == "bin"))
        .expect("persisted block record");
    let record_bytes = fs::read(&record_path).expect("read block record");
    let record = super::aot::AotRecord::decode(&record_bytes).expect("decode block record");
    let mut wrong_image = JitRuntime::new(GuestArch::X64);
    wrong_image.set_aot_cache_dir(Some(cache_dir));
    wrong_image.aot_image_hash = Some("different-image".to_string());
    let error = match wrong_image.load_aot_slice_block(
        &[],
        record.guest_address,
        record.code_hash,
        GuestArch::X64,
    ) {
        Ok(_) => panic!("wrong image hash must be rejected"),
        Err(error) => error,
    };
    assert_eq!(
        error.message,
        format!(
            "AOT cache record image hash mismatch: found {}, expected different-image",
            record.image_hash
        )
    );
}
