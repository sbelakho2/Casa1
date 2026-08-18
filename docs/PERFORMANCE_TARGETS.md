# Performance Targets

This document defines acceptable performance targets for Casa1 subsystems.
These targets are used as gates before optimising further — each baseline
must be met before additional optimisation work is undertaken.

## Measurement Methodology

- All measurements taken on **Apple M-series (M1/M2/M3) or equivalent**
- macOS 14+ (Sonoma) or later
- Release build (`cargo bench` / `cargo build --release`)
- Warm CPU caches (run each benchmark for ≥3 warm-up iterations)
- Median of ≥10 measured samples
- Units: μs (microseconds), ns (nanoseconds), MiB/s

---

## 1. CPU Emulation

| Metric | Target | Notes |
|--------|--------|-------|
| Decode throughput (simple ALU) | ≤50 ns/insn | NOP, MOV, ADD |
| Decode throughput (SIMD) | ≤100 ns/insn | MOVUPS, ADDPS |
| Lower-to-IR throughput | ≤200 ns/insn | ALU mix |
| Interpreter execution | ≤500 ns/insn | Full decode+lower+execute |
| JIT compile Tier 0 | ≤2 μs/insn | Fastest compilation path |
| JIT compile Tier 1 | ≤10 μs/insn | Optimising compilation |
| JIT compile Tier 2 | ≤50 μs/insn | Full optimisation |
| JIT execute throughput | ≤20 ns/insn | Compiled code execution |

## 2. PE Loading

| Metric | Target | Notes |
|--------|--------|-------|
| Parse minimal PE | ≤10 μs | Single-section x64 PE |
| Parse 20-section PE | ≤50 μs | Section table stress |
| Parse 100-section PE | ≤250 μs | Large section count |
| Parse + map image | ≤30 μs | Minimal PE full load |
| Large PE (200+ imports) | ≤200 μs | High import count |
| 64-section + 1024-import PE | ≤1 ms | Stress test |

## 3. Shader Translation

| Metric | Target | Notes |
|--------|--------|-------|
| Simple VS translation | ≤500 μs | Minimal vertex shader |
| Simple PS translation | ≤500 μs | Minimal pixel shader |
| Compute shader translation | ≤500 μs | Minimal compute shader |

## 4. Audio

| Metric | Target | Notes |
|--------|--------|-------|
| DirectSound mix @ 44.1 kHz (1024 frames) | ≤200 μs | Stereo, 2 channels |
| DirectSound mix @ 48 kHz (1024 frames) | ≤200 μs | Stereo, 2 channels |
| DirectSound mix @ 96 kHz (1024 frames) | ≤400 μs | Stereo, 2 channels |

## 5. Graphics

| Metric | Target | Notes |
|--------|--------|-------|
| Command batching (max_batch=128) | ≤5 μs/batch | Draw call batching |
| Shader compiler submit (4 concurrent) | ≤2 μs/submit | Job submission latency |
| Upload streaming (64 KiB alloc) | ≤1 μs/alloc | GPU upload ring buffer |

## 6. Network

| Metric | Target | Notes |
|--------|--------|-------|
| Socket create | ≤10 μs | Winsock socket() mock |
| Socket send (1 KiB) | ≤5 μs | Inter-process loopback |
| Socket recv (1 KiB) | ≤5 μs | Inter-process loopback |
| WebSocket send (1 KiB) | ≤10 μs | Mock WebSocket send |
| WebSocket recv (1 KiB) | ≤10 μs | Mock WebSocket recv |

## 7. Fast-Thunk Dispatch

| Metric | Target | Notes |
|--------|--------|-------|
| Inline cache lookup (hit) | ≤100 ns | Hot path |
| Inline cache lookup (miss) | ≤200 ns | Cold path |
| Tier promotion (100 blocks) | ≤50 μs | Hot-count based |

## 8. Startup-to-First-Frame

| Metric | Target | Notes |
|--------|--------|-------|
| Full decode+lower+execute pipeline | ≤200 μs | Mixed 30-instruction block |
| Adaptive JIT (T0→T1→T2) | ≤3 ms | Tier progression |
| PE load and prepare | ≤50 μs | Minimal PE |
| Perf subsystems init | ≤50 μs | All caching structures |

## 9. End-User Steam Experience

Measured on the release build on Apple Silicon with the signed runner, from
the moment the user launches Steam in the GE. Cold-start (first run after
boot) and warm-start (subsequent launches) are recorded separately.

| Metric | Target | Notes |
|--------|--------|-------|
| Steam bootstrap → updater start | ≤10 s | Bootstrapper dispatch to updater entry |
| Steam bootstrap → webhelper | ≤20 s | First steamwebhelper process |
| Steam bootstrap → first CEF paint | ≤30 s | First CEF paint (software or accelerated) |
| Steam bootstrap → first Metal frame | ≤30 s | First Metal-presented frame |
| Steady-state guest instructions/sec | ≥50 M insn/s | Post-login idle Steam UI |
| JIT hit ratio | ≥95 % | Compiled-block execution share |
| Host CPU at idle Steam UI | ≤15 % | One core, post-login idle |
| Memory at login screen | ≤2 GB | Casa1 + Steam resident set |
| Frame latency | ≤100 ms | Input → presented frame (UI interactions) |
