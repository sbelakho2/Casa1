# Performance Targets and KPI Gate

This document is the executable performance contract for Casa1. It replaces
the previous absolute-microbenchmark target list. Every number below maps to a
gate entry in `ci/check_perf.py` and a checked-in baseline in
`ci/perf-baseline.json`; numbers that cannot be measured with the current
runtime are listed as unavailable with an exact reason instead of being
fabricated.

## Target model

Casa1 is a compatibility layer, so the primary CPU target is **relative to
native ARM64 execution**, not to a legacy absolute instruction rate:

| Target | Model | Enforcement |
|---|---|---|
| Translation-friendly guest code | CPU time **≤10–20 % over the native ARM64-equivalent** | Native-relative ratio in `NATIVE_BASELINE` when `ci/perf-native-baseline.json` is supplied. Currently **unavailable** because no native ARM64 reference binary/benchmark is checked in; the gate prints `NATIVE_BASELINE unavailable: ...` and never invents a ratio. |
| Legacy absolute guest throughput | **≥50 M guest instructions/s is only a failure floor**, not a target | `kpi/legacy_dispatch_mips` with `absolute_min = 50`. Current baseline is 2047.83 M insn/s (synthetic 1024-NOP dispatch). |
| Compatibility-layer input→present latency | **<2 ms median / <5 ms p99** | `kpi/frame_latency_p50_us` (`absolute_max = 2000`) and `kpi/frame_latency_p99_us` (`absolute_max = 5000`). |
| Frame pacing and GPU-side work | regression-gated against the checked-in baseline | `kpi/frame_latency_*`, `kpi/frame_interval_*`, `kpi/pso_*`, `kpi/encoder_*`, `kpi/shader_*`, `kpi/gfx_*`. |

The legacy absolute MIPS figure is deliberately demoted: it is a floor that
fails the gate, not a success target. Correctness and native-relative CPU cost
remain the real targets.

### Optional native reference format

When a native ARM64 reference is available, put it in
`ci/perf-native-baseline.json`; the gate then prints `NATIVE_RATIO` for every
timing benchmark that has a native value and fails with
`TARGET_EXCEEDED native/<benchmark>` when the ratio exceeds `ratio_limit`:

```json
{
  "schema": 1,
  "available": true,
  "source": "native ARM64 harness, same workload, same host",
  "ratio_warn": 1.10,
  "ratio_limit": 1.20,
  "metrics": {
    "gate/kpi/cpu_dispatch_nop_1024": 500.0
  }
}
```

`ratio_warn` is the 10 % soft target; `ratio_limit` is the 20 % hard target.
Without this file the gate prints `NATIVE_BASELINE unavailable` and does not
invent a ratio.

## Running the gate

```sh
# Blocking gate: defined Criterion subset + KPI comparison to ci/perf-baseline.json
ci/check_perf.sh

# Regenerate the baseline from a clean, quiet machine
ci/check_perf.sh --update

# Adversarial self-tests for the gate itself (pass/regression/edge/CI/missing)
ci/check_perf.sh --self-test

# Machine-readable per-entry report and a configurable budget override
ci/check_perf.sh --report-json target/perf-report.json \
  --thresholds ci/perf-thresholds.json

# In Kiwi-CI
kiwi run --job perf
```

`--report-json PATH` writes a schema-1 document with every gate id, its
status (`PASS`, `REGRESSION`, `TARGET_EXCEEDED`, `BASELINE_PENDING`,
`UNAVAILABLE`, `MISSING_BENCHMARK`, `BASELINE_MISMATCH`), detail text, and the
final exit code. `--thresholds PATH` merges a JSON document over the built-in
table and over already-loaded baseline entries, so a stricter or looser budget
can be applied without regenerating the baseline:

```json
{
  "timing": {"gate/kpi/frame_present_64x64": {"rel": 0.30, "abs": 250.0}},
  "kpi": {"gpu_frame_time_p99_us": {"rel": 0.15, "abs": 250.0}}
}
```

### Real GPU/present timestamps (audit P1 #5)

`casa1::perf` now measures the whole input → submit → present → GPU
completion chain with real timestamps instead of CPU bookkeeping:

| Source | What is captured |
|---|---|
| `MTLCommandBuffer.GPUStartTime` / `GPUEndTime` | Real GPU execution interval for the presentation command buffer (seconds on the CoreAnimation media clock). |
| `CAMetalDrawable.presentedTime` | Real display presentation timestamp, correlated with the input event on the same media clock. |
| CPU submission window | `submit_start`/`submit_end` around encoder creation and `commit`. |
| `CLOCK_PROCESS_CPUTIME_ID` | Real host process CPU time around the measured frame. |
| Guest instruction counter | Real guest instructions retired divided by measured wall time. |

`casa1::perf::measure_gpu_present_into` encodes a real Metal compute
submission per frame, attaches a completion handler (`GpuTimingProbe`) and a
drawable presented handler (`DrawableTimingProbe`), then correlates all four
clocks. The same probes are exposed to the D3D12 swapchain through
`D3d12Runtime::mark_input_event` / `enable_present_timing` and
`D3d12PresentTiming`.

Emitted KPIs (all real-sample only):

| KPI | Unit | Direction | Notes |
|---|---|---|---|
| `gpu_frame_time_p50/p95/p99/p999_us` | µs | lower | Present-to-present intervals when a drawable timestamp exists, otherwise GPU completion intervals. |
| `gpu_frame_time_1pct_low_fps`, `gpu_frame_time_0p1pct_low_fps` | fps | higher | Mean of the slowest 1 % / 0.1 % of real frame intervals. |
| `gpu_time_p50_us`, `gpu_time_p99_us` | µs | lower | `GPUEndTime - GPUStartTime`. |
| `cpu_submit_p50_us`, `cpu_submit_p99_us` | µs | lower | CPU encode + commit window. |
| `input_to_present_p50_us`, `input_to_present_p99_us` | µs | lower | Input event → `presentedTime`; `absolute_max` 2000/5000 µs. |
| `input_to_gpu_completion_p50/p99_us` | µs | lower | Input event → `GPUEndTime`. |
| `host_cpu_time_p50_us` | µs | lower | Process CPU time around the frame. |
| `shader_compile_stall_rate_measured` | stalls/request | lower | Measured in the same window as the shader-cache gate. |
| `guest_instructions_per_sec` | instructions/s | higher | Real guest throughput sample. |
| `gpu_idle_gap_us` | µs | lower | `next GPUStartTime - previous GPUEndTime`. |

When a timestamp source is absent, the metric is emitted as
`{"available": false, "reason": "<exact reason>"}` and never replaced by a
wall-clock estimate. Exact fallbacks:

| Condition | Reason |
|---|---|
| No Metal device | `no Metal device is available; GPU and drawable timestamps cannot be captured` |
| Completed buffer without timestamps | `Metal command buffer completed without GPUStartTime/GPUEndTime timestamps` |
| Unsupported host | `the Metal device does not expose command-buffer GPU timestamps` |
| Headless layer | `CAMetalLayer.nextDrawable returned no drawable (headless presentation); drawable presentedTime is unavailable` |
| Drawable not displayed | `CAMetalLayer drawable reported presentedTime=0; no display presentation occurred` |
| No correlated input | `no input-event timestamp was correlated with the measured frames` |

New timestamp KPIs are recorded as `available: false` in
`ci/perf-baseline.json` until the first real capture. A run that observes real
samples for such an entry prints `BASELINE_PENDING` and passes; after
`ci/check_perf.sh --update` the entry is promoted and regressions fail with
`REGRESSION`/`TARGET_EXCEEDED`. Unavailable metrics always pass with an
`UNAVAILABLE` line.

The script is `ci/check_perf.py`; `ci/check_perf.sh` is a thin wrapper. The
default Criterion filter is `gate/kpi`. The script runs
`cargo bench --bench perf_benchmarks -- --quick gate/kpi` three times
(`--runs 3`), parses `target/criterion/**/new/estimates.json`, and keeps the
fastest median per benchmark to suppress one-off scheduler noise. A synthetic
estimates directory can be supplied with `--estimates-dir` for testing.

## Gate arithmetic

- Each entry has a `direction` (`lower` or `higher`), a relative threshold
  (`rel`) and an absolute floor (`abs`) in its unit.
- `allowed = max(abs, rel * |baseline|)`.
- A point estimate outside `baseline ± allowed` in the bad direction is only a
  regression if the new confidence interval is **entirely** outside the
  baseline interval in that direction. Overlapping intervals produce
  `CI_OVERLAP` and pass; this is the statistical-noise rule.
- A value exactly at `allowed` produces `THRESHOLD_EDGE` and passes; only a
  strictly larger change fails.
- `absolute_max` / `absolute_min` are documented end-user targets and fail
  independently of the baseline.
- Exit codes: `0` pass, `2` regression, `3` missing benchmark, `4`
  baseline/config mismatch, `5` benchmark run failed.
- Explicitly unavailable KPIs pass with an `UNAVAILABLE` line. They never fail
  the gate and never contribute a fabricated number.

## JIT/scheduler KPIs

Measured by `bench_gate_kpis` in `benches/perf_benchmarks.rs`, which emits a
`CASA1_PERF_KPI` JSON document. The values below are the current
`ci/perf-baseline.json` values on Apple Silicon; they are baseline-relative
gates, not universal constants.

| KPI | Gate id | Direction | Threshold | Baseline | Source |
|---|---|---|---|---|---|
| Dispatcher exits per 1000 guest IR instructions | `kpi/dispatcher_exits_per_1000_instructions` | lower | rel 15 %, abs 0.5 | 3.2961 | `WorkerSliceBenchmark` call/return chain (4096 blocks, budget 512) |
| Native chaining rate | `kpi/native_chaining_rate` | higher | rel 2 %, abs 0.01 | 0.995605 | same worker slice |
| Indirect-branch IC hit rate | `kpi/indirect_ic_hit_rate` | higher | rel 2 %, abs 0.01 | 0.999268 | monomorphic indirect call chain (4096 blocks) |
| Generic helper rate | `kpi/generic_helper_rate` | lower | rel 0 %, abs 0.0 | 0.0153846 | `jit_lowering_telemetry` over the gate corpus (64 NOP + 1 catch-all `Hlt`) |
| High-address software syncs | `kpi/high_address_software_syncs_per_1000_instructions` | lower | rel 0 %, abs 0.01 | 0 | `guest_memory_telemetry` for 4096 worker-slice loads at `0x2_0000_0000` |
| High-address guest page faults | `kpi/high_address_guest_page_faults_per_access` | lower | rel 0 %, abs 0.001 | 0 | same workload, materialised pages / executed access |
| Thunk generic dispatch rate | `kpi/thunk_generic_dispatch_rate` | lower | rel 0 %, abs 0.0 | 0 | `thunk_resolve_telemetry`, 256 registered guest thunk addresses |
| Persistent AOT hit rate | `kpi/persistent_aot_hit_rate` | higher | rel 2 %, abs 0.01 | 0.888889 | `JitRuntime::aot_metrics` over 8 fresh instances |
| Legacy absolute throughput floor | `kpi/legacy_dispatch_mips` | higher | rel 50 %, abs 10, **absolute_min 50** | 2047.83 | `execute_ir` 1024-NOP dispatch, 1000 iterations |

The gate also parses the pre-existing diagnostic lines and turns them into
executable entries:

| KPI | Gate id | Direction | Threshold | Baseline | Source line |
|---|---|---|---|---|---|
| Tier-2 compile hit rate | `kpi/tier2_compile_hit_rate` | higher | rel 2 %, abs 0.01 | 1 | `TIER2_HOT_LOOP hit_rate` |
| IAT slots patched | `kpi/iat_patched` | higher | rel 0 %, abs 0.0 | 1.0 | `IAT_METRICS patched` |
| IAT direct dispatch bypasses | `kpi/iat_dispatch_bypasses` | higher | rel 50 %, abs 1.0 | 0.0 | `IAT_METRICS bypasses` |
| IAT repatched slots | `kpi/iat_repatched` | lower | rel 0 %, abs 0.0 | 0.0 | `IAT_METRICS repatched` |
| IAT invalidated slots | `kpi/iat_invalidated` | lower | rel 0 %, abs 0.0 | 0.0 | `IAT_METRICS invalidated` |
| Inline-API registered targets | `kpi/inline_api_registered_targets` | higher | rel 0 %, abs 0.0 | 1.0 | `INLINE_API_STATS registered_targets` |
| Inline-API calls | `kpi/inline_api_call_total` | higher | rel 0 %, abs 0.0 | 0.0 | `INLINE_API_STATS inline_metric_total` |

## CPU/PE/thunk timing subset

| Benchmark | Gate id | Direction | Threshold | Baseline | Workload |
|---|---|---|---|---|---|
| Interpreter dispatch | `gate/kpi/cpu_dispatch_nop_1024` | lower | rel 50 %, abs 400 ns | 563.50 ns | 1024 NOPs through `execute_ir` |
| PE parse | `gate/kpi/pe_parse_minimal` | lower | rel 50 %, abs 500 ns | 264.52 ns | minimal single-section PE |
| Thunk resolution | `gate/kpi/thunk_resolve_256` | lower | rel 50 %, abs 2000 ns | 2033.36 ns | 256 repeat guest→host lookups |
| Shader cache hit | `gate/kpi/shader_cache_hit` | lower | rel 50 %, abs 2000 ns | 1394.66 ns | `compile_with_cache` on a warm entry |
| Upload allocation | `gate/kpi/gfx_upload_allocate_64k` | lower | rel 50 %, abs 20 ns | 9.20 ns | `GpuUploadStreamer::allocate` 64 KiB |
| Command batching | `gate/kpi/gfx_command_batch_128` | lower | rel 50 %, abs 8000 ns | 11399.23 ns | 384 draws through a 128-draw batcher |
| Present bookkeeping | `gate/kpi/frame_present_64x64` | lower | rel 20 %, abs 200 ns | 270.73 ns | one `GraphicsBackend::present` at 64×64 |

## Latency and GPU-side KPIs

All frame KPIs use a real `GraphicsBackend` swapchain at 320×240 and 5000
consecutive presents (128 warm-up presents). `frame_latency_*` is the
wall-clock duration of the compatibility-layer `present` call;
`frame_interval_*` is `PresentResult::frame_time_ns` between consecutive
presents. Percentiles are exact order statistics; `1% low` / `0.1% low` are
the FPS implied by the mean of the slowest 1 % / 0.1 % of presents. These are
CPU-side compatibility-layer measurements, not GPU-execution timestamps (see
the unavailable list).

| KPI | Gate id | Direction | Threshold | Baseline |
|---|---|---|---|---|
| Present latency p50 | `kpi/frame_latency_p50_us` | lower | rel 10 %, abs 100 µs, **absolute_max 2000 µs** | 3.584 µs |
| Present latency p95 | `kpi/frame_latency_p95_us` | lower | rel 10 %, abs 200 µs | 3.750 µs |
| Present latency p99 | `kpi/frame_latency_p99_us` | lower | rel 10 %, abs 200 µs, **absolute_max 5000 µs** | 9.541 µs |
| Present latency p99.9 | `kpi/frame_latency_p999_us` | lower | rel 100 %, abs 500 µs | 60.333 µs |
| Present latency 1 % low | `kpi/frame_latency_1pct_low_fps` | higher | rel 90 %, abs 50000 FPS | 29265.4 FPS |
| Present latency 0.1 % low | `kpi/frame_latency_0p1pct_low_fps` | higher | rel 90 %, abs 20000 FPS | 7127.1 FPS |
| Present interval p50 | `kpi/frame_interval_p50_us` | lower | rel 15 %, abs 100 µs | 3.625 µs |
| Present interval p95 | `kpi/frame_interval_p95_us` | lower | rel 15 %, abs 200 µs | 3.750 µs |
| Present interval p99 | `kpi/frame_interval_p99_us` | lower | rel 15 %, abs 200 µs | 9.542 µs |
| Present interval p99.9 | `kpi/frame_interval_p999_us` | lower | rel 100 %, abs 500 µs | 60.417 µs |
| PSO compile (cold, first key) | `kpi/pso_compile_us` | lower | rel 1000 %, abs 100000 µs | 631.416 µs |
| PSO compile (same key, cache hit) | `kpi/pso_cache_hit_us` | lower | rel 25 %, abs 10 µs | 0.334 µs |
| Pipeline-state switches per 1000 draws | `kpi/encoder_switches_per_1000_draws` | lower | rel 0 %, abs 0.0 | 1000 |
| Cold shader-cache compile stalls per request | `kpi/shader_compile_stall_rate_cold` | lower | rel 10 %, abs 0.05 | 1.0 |
| Warm shader-cache compile stalls per request | `kpi/shader_compile_stall_rate_warm` | lower | rel 0 %, abs 0.0 | 0.0 |
| Required barriers per 1000 considered | `kpi/gfx_barriers_required_per_1000_considered` | lower | rel 0 %, abs 0.0 | 1000 |
| Staged upload copies / (zero-copy + staged) | `kpi/gfx_staged_upload_copy_rate` | lower | rel 0 %, abs 0.0 | 0 |

Cold PSO compile is baseline-relative only (threshold 1000 % / 100000 µs)
because macOS caches compiled Metal pipelines across process runs and the
first compile in a fresh CI cache can be an order of magnitude slower than a
warm-machine baseline. It is exposed as a KPI but is deliberately a wide guard,
not a deterministic absolute target. The warm cache-hit path is stable and
tightly gated.

## Genuinely unavailable metrics

These are emitted as `{"available": false, "reason": ...}` in the KPI document,
recorded as unavailable in `ci/perf-baseline.json`, and printed by the gate as
`UNAVAILABLE`. They never fail the gate.

| Metric | Exact reason |
|---|---|
| GPU idle gaps (`kpi/gpu_idle_gap_us`) | Measured once real `GPUStartTime`/`GPUEndTime` history exists (see above); the checked-in baseline is still the pre-capture unavailable entry until `--update`. |
| Residency churn (`kpi/residency_churn_per_1000_frames`) | `MTLResidencySet` exposes membership and allocated size but no add/remove event counter, and the backend does not record commit churn. |
| GPU heap faults (`kpi/gpu_heap_faults_per_1000_frames`) | Metal does not expose `MTLHeap` page-fault counts. The backend tracks staging fallbacks, not GPU page faults. |
| Native-relative CPU ratio (`NATIVE_BASELINE`) | No native ARM64-equivalent reference binary/benchmark is checked in. Supply `ci/perf-native-baseline.json` to enable ratios; until then the gate prints `NATIVE_BASELINE unavailable`. |

## Baseline hygiene

`ci/perf-baseline.json` is machine-specific and must be regenerated with
`ci/check_perf.sh --update` on a quiet machine when a deliberate performance
change lands. Do not hand-edit baseline values. The baseline stores, for every
entry, its kind, direction, unit, threshold, baseline median/value and (for
Criterion entries) the confidence interval. The gate fails with
`BASELINE_MISMATCH` on any benchmark present in the run but absent from the
baseline, so a newly added benchmark cannot silently bypass gating.

## Gate self-tests

`ci/check_perf.sh --self-test` runs `ci/test_perf_gate.py`, which feeds
synthetic Criterion/KPI documents into `ci/check_perf.py` and pins the exact
exit code and diagnostic for:

| Case | Expected |
|---|---|
| Improvement / no change | exit 0, `PASS` |
| Regression beyond threshold with separated CIs | exit 2, `REGRESSION` |
| Estimate exactly at the allowed delta | exit 0, `THRESHOLD_EDGE` |
| Median regression with overlapping CIs | exit 0, `CI_OVERLAP` |
| Baseline benchmark absent from the run | exit 3, `MISSING_BENCHMARK` |
| KPI regression | exit 2, `REGRESSION` |
| Explicitly unavailable KPI | exit 0, `UNAVAILABLE` |
| Median above a documented `absolute_max` | exit 2, `TARGET_EXCEEDED` |
| Real samples for an unavailable baseline entry | exit 0, `BASELINE_PENDING` |
| Budget override loosens a failing threshold | exit 0, `PASS` |
| Machine-readable report requested | `result=pass` with per-entry `PASS` |
