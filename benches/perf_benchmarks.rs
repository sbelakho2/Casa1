//! Criterion benchmarks for the Casa1 performance infrastructure.
//!
//! Covers block chaining, address translation, GPU upload streaming,
//! frame pacing, and file caching subsystems.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// ---------------------------------------------------------------------------
// Block Chaining Benchmarks
// ---------------------------------------------------------------------------

fn bench_block_chaining_register(c: &mut Criterion) {
    let mut group = c.benchmark_group("block-chaining/register");

    for chain_len in [10usize, 100, 1000] {
        group.bench_function(format!("{chain_len}_blocks"), |b| {
            b.iter_with_setup(
                || {
                    let cache = casa1::perf::BlockChainingCache::new();
                    cache
                },
                |mut cache| {
                    for i in 0..chain_len {
                        let ga = 0x1000u64 + (i as u64 * 0x100);
                        let ha = 0x8000_0000u64 + (i as u64 * 0x100);
                        cache.register_block(black_box(ga), black_box(ha), black_box(64), black_box(10));
                    }
                    black_box(cache.block_count());
                },
            )
        });
    }
    group.finish();
}

fn bench_block_chaining_resolve(c: &mut Criterion) {
    let mut group = c.benchmark_group("block-chaining/resolve");

    for chain_len in [10usize, 100, 1000] {
        group.bench_function(format!("{chain_len}_blocks"), |b| {
            // Set up a cache with chain_len blocks pre-registered
            let mut cache = casa1::perf::BlockChainingCache::new();
            for i in 0..chain_len {
                let ga = 0x1000u64 + (i as u64 * 0x100);
                let ha = 0x8000_0000u64 + (i as u64 * 0x100);
                cache.register_block(ga, ha, 64, 10);
                // Make each block hot so it can be chained
                if i > 0 {
                    for _ in 0..10 {
                        cache.record_execution(ga, ga + 0x100).unwrap();
                    }
                    cache.try_chain(ga);
                }
            }

            b.iter(|| {
                // Resolve a chain from the middle block
                let mid = chain_len / 2;
                let ga = 0x1000u64 + (mid as u64 * 0x100);
                let block = cache.get_block(black_box(ga));
                black_box(block)
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Address Translation Benchmarks
// ---------------------------------------------------------------------------

fn bench_address_translation_translate(c: &mut Criterion) {
    let mut group = c.benchmark_group("address-translation/translate");

    for (name, hit_rate, total_entries) in [
        ("50pct_hit", 0.5f64, 200usize),
        ("90pct_hit", 0.9, 200),
    ] {
        group.bench_function(name, |b| {
            let mut cache = casa1::perf::AddressTranslationCache::new(total_entries);

            // Pre-populate with entries
            for i in 0..total_entries {
                cache.insert(i as u64 * 0x1000, (i as u64 + 0x8000_0000) * 0x1000, 4096, 0x07);
            }

            // Determine the lookup sequence to achieve the desired hit rate
            let lookups: Vec<u64> = (0..1000)
                .map(|i| {
                    if (i as f64) < hit_rate * 1000.0 {
                        // Hit: addresses that are already cached
                        (i % total_entries) as u64 * 0x1000
                    } else {
                        // Miss: addresses outside the cache
                        0xF000_0000u64 + (i as u64 * 0x1000)
                    }
                })
                .collect();

            b.iter(|| {
                for &addr in &lookups {
                    let _ = black_box(cache.lookup(addr));
                }
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// GPU Upload Streaming Benchmarks
// ---------------------------------------------------------------------------

fn bench_gpu_upload_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("gpu-upload-streaming/allocate");

    for (name, alloc_size) in [("1KB", 1024usize), ("64KB", 65_536), ("1MB", 1_048_576)] {
        group.bench_function(name, |b| {
            // Create a streamer with a very large ring buffer to avoid wrapping
            let ring_size = alloc_size * 100;
            let mut streamer = casa1::perf::GpuUploadStreamer::new(ring_size);
            let buf_id = streamer.create_streaming_buffer(ring_size);

            b.iter(|| {
                let offset = streamer.allocate(black_box(buf_id), black_box(alloc_size));
                black_box(offset)
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Frame Pacing Benchmarks
// ---------------------------------------------------------------------------

fn bench_frame_pacing_60fps(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame-pacing/60fps");

    let config = casa1::perf::FramePacingConfig {
        target_fps: 60,
        vsync_enabled: true,
        max_frame_latency: 2,
    };

    group.bench_function("begin_frame", |b| {
        let mut pacer = casa1::perf::FramePacer::new(config);
        b.iter(|| {
            pacer.begin_frame();
            black_box(());
        })
    });

    group.bench_function("end_frame", |b| {
        let mut pacer = casa1::perf::FramePacer::new(config);
        pacer.begin_frame();
        b.iter(|| {
            pacer.end_frame();
            black_box(());
        })
    });

    group.bench_function("begin_end_pair", |b| {
        let mut pacer = casa1::perf::FramePacer::new(config);
        b.iter(|| {
            pacer.begin_frame();
            pacer.end_frame();
            black_box(());
        })
    });

    group.finish();
}

fn bench_frame_pacing_120fps(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame-pacing/120fps");

    let config = casa1::perf::FramePacingConfig {
        target_fps: 120,
        vsync_enabled: true,
        max_frame_latency: 2,
    };

    group.bench_function("begin_frame", |b| {
        let mut pacer = casa1::perf::FramePacer::new(config);
        b.iter(|| {
            pacer.begin_frame();
            black_box(());
        })
    });

    group.bench_function("end_frame", |b| {
        let mut pacer = casa1::perf::FramePacer::new(config);
        pacer.begin_frame();
        b.iter(|| {
            pacer.end_frame();
            black_box(());
        })
    });

    group.bench_function("begin_end_pair", |b| {
        let mut pacer = casa1::perf::FramePacer::new(config);
        b.iter(|| {
            pacer.begin_frame();
            pacer.end_frame();
            black_box(());
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// File Cache Benchmarks
// ---------------------------------------------------------------------------

fn bench_file_cache_hot(c: &mut Criterion) {
    let mut group = c.benchmark_group("file-cache/hot");

    group.bench_function("all_hits", |b| {
        let mut cache = casa1::perf::FileCache::new(1_000_000);
        // Insert 100 entries
        for i in 0..100 {
            let path = format!("/game/data/file_{i}.bin");
            cache.insert(&path, vec![0u8; 1024]).unwrap();
        }

        let paths: Vec<String> = (0..100).map(|i| format!("/game/data/file_{i}.bin")).collect();

        b.iter(|| {
            for p in &paths {
                let result = cache.get(black_box(p));
                black_box(result);
            }
        })
    });

    group.finish();
}

fn bench_file_cache_cold(c: &mut Criterion) {
    let mut group = c.benchmark_group("file-cache/cold");

    group.bench_function("all_misses", |b| {
        let mut cache = casa1::perf::FileCache::new(1_000_000);
        // Insert some entries but look up different ones
        for i in 0..50 {
            let path = format!("/game/data/existing_{i}.bin");
            cache.insert(&path, vec![0u8; 1024]).unwrap();
        }

        let paths: Vec<String> = (0..100).map(|i| format!("/game/data/missing_{i}.bin")).collect();

        b.iter(|| {
            for p in &paths {
                let result = cache.get(black_box(p));
                black_box(result);
            }
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion groups
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_block_chaining_register,
    bench_block_chaining_resolve,
    bench_address_translation_translate,
    bench_gpu_upload_streaming,
    bench_frame_pacing_60fps,
    bench_frame_pacing_120fps,
    bench_file_cache_hot,
    bench_file_cache_cold,
);

criterion_main!(benches);
