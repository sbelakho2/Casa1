# Casa1 Comprehensive Gap Analysis — Roadmap to 100% Compatibility

> Reality-check note (May 2026): this document mixes implementation notes with forward planning. Several early counts, coverage percentages, and PE-loader gap claims had drifted away from the actual repository. The summary below has been corrected to reflect current code and tests; the later effort estimates should still be treated as planning, not measured coverage.

## 1. Current State Summary

### 1.1 Repository Reality Check

| Measure | Current repository state |
|---------|--------------------------|
| Authored Rust source | 60 files under `src/`, ~175,722 lines |
| Authored Rust tests | 37 files under `tests/`, ~27,284 lines |
| Core execution path | `cli -> runner -> pe_runtime -> cpu/win32/user32/gfx/...` |
| Validation surface | Sectioned integration tests, ignored/manual Steam suites, fuzz targets, CI, and Criterion benches |

### 1.2 What the Code Already Implements

- PE parsing and mapping are materially beyond a stub parser. `src/pe.rs` parses imports, delay imports, exports, relocations, TLS directories, manifests, version resources, activation-context plans, and DLL/TLS lifecycle ordering.
- The PE runtime already executes some guest callbacks that the earlier draft described as absent. In particular, `src/pe_runtime.rs` calls `execute_main_image_tls_process_attach_callbacks` during startup for the main image.
- Graphics support is real, not merely aspirational. `src/d3d11.rs`, `src/d3d12.rs`, `src/gfx.rs`, and `src/metal_backend.rs` back substantial D3D11/D3D12 behavior, and `tests/section6.rs`, `tests/section26.rs`, and `tests/section28.rs` exercise descriptor heaps, raytracing-related paths, barriers, shader parsing, and backend creation.
- Steam coverage is broader than a single installer replay. `tests/section23.rs` and `tests/section24.rs` include Steam.exe tracing, import enumeration, and smoke/coverage suites, although many remain ignored/manual and depend on the checked-in Steam GE.
- The CPU engine supports a large instruction surface, but it still contains many explicit `RcUnimplInsn` paths, especially in VEX/EVEX, selector groups, and some x87 forms. The correct reading is "broad but incomplete", not a clean measured percentage.
- Media, installer, diagnostics, security, and app-bundle subsystems are present in code, but some paths still degrade to stubs or unsupported results, for example non-macOS H.264 decode in `src/media.rs`, partial COM/BCrypt coverage in `src/real_win32.rs`, and numerous unsupported COM-style vtable methods in `src/pe_runtime.rs`.

### 1.3 Evidence-Grounded Status by Area

| Area | Repository reality |
|------|--------------------|
| PE / loader | Implemented parser/mapper with delay imports, relocations, TLS directory parsing, manifest parsing, activation-context planning, and lifecycle planning; SEH/unwind completeness is still a gap |
| CPU / JIT | Custom ARM64 JIT plus interpreter exist; many instruction families are implemented, but numerous unsupported VEX/EVEX/x87/selectors remain |
| Win32 / user32 | Large thunk surface and subsystem models exist, but unsupported imports and stubbed methods remain common |
| D3D11 / D3D12 / DXGI | Real device/runtime layers exist and are tested; many COM-style interface methods still default to `unsupported_method(...)` placeholders |
| D3D9 | There is a `Direct3D9Shim` in `src/d3d11.rs`, so this is not zero code; it is still far from full D3D9 coverage |
| Media / audio | Real subsystems exist; codec and platform coverage are uneven, with explicit unsupported cases |
| Steam | Installer, depot, protocol, integration, live-run GEs, and ignored/manual Steam.exe coverage tests exist |
| Test surface | 37 Rust test files, fuzz targets, benches, CI, and ignored/manual Steam suites; materially larger than the original `section1..section28` summary |

### 1.4 Known Working or Directly Exercised Scenarios

- **Windows Tetris** standalone Win32/DXGI/D3D11/XAudio2 sample under `games/windows_tetris`
- **Sample guest** run/install/play flows through the GE and runner
- **Steam** install/update/protocol and Steam.exe import/smoke/diagnostic paths, with caveats for ignored/manual suites
- **D3D11/D3D12** backend creation, shader parsing, and frame/descriptor/resource flows exercised by tests

### 1.5 Authored File Groups Scanned

The repo-wide review behind this document covered the authored file surface, not generated GE/runtime artifacts:

- `src/` and `src/bin/` runtime, compatibility, graphics, Steam, installer, browser, media, and support modules
- `tests/`, `tests/support/`, and `tests/fixtures/` integration, conformance, smoke, and oracle-based validation suites
- `fuzz/` targets and seed corpora
- `ci/`, `.github/workflows/`, and `benches/` build-validation and performance tooling
- `games/windows_tetris/` sample application, build script, and docs
- root manifest, lockfile, checklist, diagnostics artifacts, and this roadmap

Checked-in GE folders and runtime outputs under `ges/`, `games/windows_tetris/ges/`, `tmp/`, and `target/` were treated as fixtures or artifacts rather than authored implementation.

### 1.6 Strategic Direction for Apple Silicon

- Casa1 should optimize for fewer guest-to-host transitions, not just broader API count. The cost of leaving hot guest code for generic runtime dispatch is one of the main remaining overhead multipliers.
- CPU work should exploit Apple M strengths directly: NEON-backed vector lowering where valid, ARMv8 AES/SHA/PMULL instructions for guest crypto primitives, and honest CPUID/XCR0 reporting that never advertises features without real lowering.
- GPU work should prioritize unified-memory and zero-copy presentation paths before expanding long-tail feature lists. IOSurface/CVPixelBuffer/WKWebView/CEF/video/present sharing is more important for seamlessness than adding more modeled-but-not-executed graphics surface area.
- Metal optimization work must move from placeholder policy objects to live hot-path behavior: real pipeline/binary archives, true async compilation, completion-driven command-buffer reuse, and tile-aware render-pass scheduling.
- Browser, Steam, installers, and certificate/trust behavior should be treated as launch-critical compatibility surfaces rather than secondary integration tasks. For many real titles, the launcher path fails before game rendering matters.
- Unsupported imports, unsupported COM/vtable methods, shader-model requests, and launcher/install failures should drive backlog ranking continuously; this repo already exposes the right failure points, but the plan needs to treat them as telemetry inputs rather than one-off debugging notes.

---

## 2. Gap Analysis by Category

Note: the percentages in this section are legacy planning heuristics, not measured coverage. When they disagree with the code-grounded summary in Section 1, prefer Section 1.

### 2.1 Win32 API Surface (kernel32.dll, ntdll.dll)

**Current coverage: ~55–62%**

| Subcategory | Current | Gap Size | Effort | Priority |
|-------------|---------|----------|--------|----------|
| Process/thread management | 70% | CreateRemoteThreadEx, VirtualAllocEx, ReadProcessMemory, WriteProcessMemory, NtCreateProcess | 8 pw | P1 |
| Memory management | 80% | VirtualAlloc2, VirtualAllocExNuma, CreateFileMappingFromApp, full CoW semantics | 4 pw | P1 |
| File I/O | 85% | NtCreateFile, NtReadFile, NtWriteFile, NtDeviceIoControlFile, ReOpenFile | 6 pw | P0 |
| Synchronization | 75% | Waitable timers, InitOnceExecuteOnce, SRWLock exclusive try | 3 pw | P1 |
| DLL loading | 70% | Delay-load imports, manifest-based SxS resolution, LdrLoadDll | 6 pw | P0 |
| Exception handling | 50% | VEH (partially), full SEH chain unwinding, .pdata processing, RtlRestoreContext | 10 pw | P0 |
| Registry | 90% | RegNotifyChangeKeyValue, RegLoadKey/RegSaveKey, registry virtualization | 2 pw | P2 |
| Environment | 85% | GetEnvironmentStringsA, SetEnvironmentStrings | 1 pw | P2 |

### 2.2 Graphics APIs

#### D3D9/D3D9Ex — Current: ~10%
- **Gap: ~90%** — A shim-level fixed-function path exists in `src/d3d11.rs`, but full IDirect3DDevice9, textures, surfaces, shaders, and state emulation are still missing
- **Effort: 30 pw | Priority: P0** (blocks Halo, Half-Life 2, Fallout 3 era games)

#### D3D10/D3D10.1 — Current: 0%
- **Gap: 100%** — No coverage at all
- **Effort: 15 pw | Priority: P2** (D3D10-era games can often use D3D11 fallback)

#### D3D11 — Current: ~70%
- **Missing: Geometry shaders, hull/domain shaders (tessellation), fuller feature-level coverage, and broader interface-method completion; deferred-context support already exists but fidelity is incomplete**
- **Effort: 12 pw | Priority: P1**

#### D3D12 — Current: ~65%
- **Missing: Real execution for marquee advanced features, broader interface completion, newer device/resource variants, real shader/pipeline archive handling, zero-copy presentation/composition, tile-aware pass merging, and stronger guest-visible fidelity for raytracing and meta-command paths**
- **Effort: 18 pw | Priority: P1**

#### DXGI — Current: ~75%
- **Missing: OutputDuplication, FactoryMedia, multi-adapter**
- **Effort: 4 pw | Priority: P2**

#### OpenGL — Current: ~15%
- **Missing: Guest-ready export surface and true execution; internal context/resource tracking exists, but exported OpenGL compatibility is still shallow**
- **Effort: 40 pw | Priority: P2** (consider delegating to MoltenGL/Zink)

#### Vulkan — Current: ~40%
- **Missing: Real queue submission and guest-visible execution fidelity; object/state tracking exists, but replay into Metal remains incomplete**
- **Effort: 20 pw | Priority: P2** (MoltenVK handles most of this)

#### GDI/GDI+ — Current: ~30%
- **Missing: Text fidelity, richer transforms/compositing, image-codec breadth, and API breadth; software rendering already exists in code**
- **Effort: 15 pw | Priority: P1**

#### DirectDraw — Current: 0%
- **Effort: 10 pw | Priority: P3** (very legacy)

### 2.3 CPU Emulation — Current: ~85–88%

**Missing (~12–15%):**
- AES-NI, SHA, and PCLMULQDQ with real ARMv8 lowering on Apple Silicon
- Full AVX-512 EVEX decode
- String instructions (CMPS, SCAS with REP)
- System instructions (IN, OUT, CLI, STI, HLT, SYSCALL)
- Debug/control register access
- FXSAVE/XRSTOR, XSAVE/XRSTOR
- Tiered JIT hot-path work: block versioning, direct block chaining, flags liveness, and specialized fast-thunk ABI paths
- Self-modifying code detection + JIT cache invalidation
- Hardware breakpoints (DR0-DR3)
- **Effort: 26 pw | Priority: P0**

### 2.4 Window Management (user32.dll) — Current: ~65%

**Missing:**
- CreateWindowExA (ANSI variant)
- DWM composition, visual styles / UxTheme
- SetWindowsHookExW/CallNextHookEx (global hooks)
- GetKeyState, GetAsyncKeyState, GetKeyboardState
- MapVirtualKeyW, VkKeyScanW
- Multi-monitor full support
- IME support
- **Effort: 15 pw | Priority: P0**

### 2.5 Audio — Current: ~60%

| API | Coverage | Effort |
|-----|----------|--------|
| XAudio2 | 85% | 3 pw |
| DirectSound | 40% | 8 pw |
| WASAPI | 50% | 5 pw |
| WinMM | 5% | 4 pw |
| Media Foundation | Partial shim plus macOS H.264 bridge | 10 pw |
| **Total** | | **20 pw | P1** |

### 2.6 Input — Current: ~70%

**Missing:** Multi-touch gestures, pen pressure/tilt, fuller raw-input coverage, Steam Input manifest/binding/glyph support, and richer motion/controller semantics
**Effort: 6 pw | Priority: P2**

### 2.7 Networking — Current: ~65%

**Missing:** Real certificate-chain and pin validation, broader Winsock coverage, RPC/DCOM, WSAPoll, WSAEventSelect, raw sockets, Bluetooth, and launcher/browser-compatible trust behavior for Steam and embedded web flows
**Effort: 28 pw | Priority: P0**

### 2.8 Shell/COM/OLE — Current: ~55%

**Missing:** COM marshaling, DCOM, ActiveX, IE COM, IPersist, drag-and-drop, OLE embedding
**Effort: 30 pw | Priority: P1**

### 2.9 Security/Crypto — Current: ~50%

**Missing:** WinVerifyTrust, Authenticode, CNG full BCrypt* API, DPAPI
**Effort: 12 pw | Priority: P1**

### 2.10 Installer Support — Current: ~60%

**Missing:** Full NSIS/InnoSetup script execution, MSI custom actions, InstallShield custom behavior, and stronger prerequisite/dependency execution fidelity
**Effort: 15 pw | Priority: P1**

### 2.11 Threading/Synchronization — Current: ~75%

**Missing:** Higher-fidelity Windows threadpool and timer semantics, RegisterWait-style behavior, UMS/job-object depth, and broader process/thread realism
**Effort: 8 pw | Priority: P1**

### 2.12 Browser / Embedded Web — Current: partial

**Missing:** Unified real browser path across WebView2, CEF bridge, and Steam UI flows; zero-copy IOSurface/CVPixelBuffer composition; fuller DOM/network/cookie/storage/event fidelity; and robust login/update/service-worker flows
**Effort: 14 pw | Priority: P0**

### 2.13 Steam Platform Integration — Current: partial

**Missing:** Full SteamService behavior, manifest/library discovery fidelity, zero-touch bootstrap, browser-backed Steam UI parity, stricter trust/pinning, and more complete IPC/update flows
**Effort: 14 pw | Priority: P0**

---

## 3. Architecture Gaps

### 3.1 PE Loader Completeness

| Feature | Status | Gap |
|---------|--------|-----|
| DOS/NT header parsing | ✅ | — |
| Section mapping | ✅ | — |
| Import resolution | ✅ | — |
| Base relocation | ✅ | — |
| Export table parsing | ✅ | — |
| Resource loading | ⚠️ Partial | Missing some resource types |
| **Delay-load imports** | ✅ | Parsed and resolved in `src/pe.rs`; broader full-runtime coverage still needs expansion |
| **TLS callbacks** | ⚠️ Partial | TLS directory parsing exists and main-image process-attach callbacks execute; broader DLL/thread lifecycle coverage still needs validation |
| **Lifecycle planning** | ✅ | `src/pe.rs::plan_lifecycle` models DLL/TLS ordering and is tested |
| **Manifest/SxS** | ⚠️ Partial | Embedded/external manifest parsing and activation-context planning exist; broader SxS/runtime binding remains incomplete |
| **Exception directory** | ❌ | .pdata processing missing |

**Effort: 12 pw | Priority: P0**

### 3.2 Memory Model

| Feature | Status |
|---------|--------|
| Virtual memory layout | ⚠️ Partial (not full 64TB x64 layout) |
| Copy-on-write | ❌ Missing |
| Memory-mapped file coherence | ⚠️ Partial |
| ASLR emulation | ⚠️ Partial |
| DEP/NX bit | ⚠️ Partial |
| Guard pages | ❌ Missing |

**Effort: 10 pw | Priority: P1**

### 3.3 System Call Emulation

All ntdll.dll syscalls missing (NtCreateFile, NtCreateSection, NtCreateProcess, etc.)
**Effort: 15 pw | Priority: P2**

### 3.4 Apple Silicon-Native Execution Track

| Feature | Status | Gap |
|---------|--------|-----|
| Tiered execution engine | ⚠️ Partial | Interpreter + ARM64 JIT exist, but hot-path block versioning, direct block chaining, flags liveness, and specialized fast thunks are still missing |
| CPUID/XCR0 honesty + host lowering | ⚠️ Partial | Feature virtualization exists, but AES/SHA/PCLMULQDQ/XSAVE-family support must stay aligned to real lowering instead of optimistic exposure |
| Zero-copy unified-memory composition | ❌ Missing | IOSurface-backed textures and shared browser/video/present paths are still stubbed or CPU-copy-heavy |
| Real Metal pipeline cache | ⚠️ Partial | Metal library loading exists, but binary archives, persistent PSO caches, and true async compilation are incomplete |
| Tile-aware GPU scheduling | ⚠️ Partial | Render-pass merging, heaps, aliasing, and command-pool ideas exist, but are not yet wired into live guest submission hot paths |
| Telemetry-driven compatibility triage | ⚠️ Partial | Tests, traces, and diagnostics exist, but unsupported imports/vtables/shader models are not yet feeding a continuous prioritization loop |

**Effort: 24 pw | Priority: P0**

---

## 4. Roadmap to 100%

The remaining work now needs two concurrent tracks:

- **Compatibility closure**: missing APIs, loader/runtime correctness, interface coverage, and behavior fidelity.
- **Apple-native execution efficiency**: reducing guest/host crossings, exploiting Apple M CPU/GPU strengths directly, and removing CPU-copy-heavy launcher/browser/video paths.

The second track is not optional polish. It is required to make already-partially-supported titles feel seamless and low-overhead on Apple Silicon.

### Cross-Phase Track A: Apple Silicon Efficiency and Seamlessness — 28 person-weeks

| # | Item | Effort |
|---|------|--------|
| A.1 | CPUID/XCR0 honesty plus ARMv8 AES/SHA/PMULL lowering for guest crypto features | 4 pw |
| A.2 | Hot-loop tiering: block versioning, direct block chaining, and specialized fast-thunk ABI paths | 6 pw |
| A.3 | Zero-copy unified-memory composition for browser, video, overlays, and present paths via IOSurface/CVPixelBuffer | 5 pw |
| A.4 | Real Metal shader/pipeline cache: metallib loading, `MTLBinaryArchive`, and disk-backed PSO cache | 4 pw |
| A.5 | True async shader compilation and completion-driven command-buffer reuse | 3 pw |
| A.6 | Tile-aware render-pass scheduling, heap aliasing, and memoryless-attachment usage on Apple GPUs | 3 pw |
| A.7 | Unsupported import/vtable/shader-model telemetry loop that ranks title blockers automatically | 1 pw |
| A.8 | Steam/browser/trust launch-path hardening for seamless startup on already-supported titles | 2 pw |

### Phase 1: Foundation (Current → 70%) — 38 person-weeks

| # | Item | Effort |
|---|------|--------|
| 1.1 | Complete SEH/VEH exception handling (.pdata processing, full unwind) | 8 pw |
| 1.2 | Expand DLL synthetic export tables (+20 DLLs) and close the highest-frequency unsupported imports | 5 pw |
| 1.3 | Broaden delay-load handling inside the full PE runtime and larger DLL sets | 2 pw |
| 1.4 | Extend TLS callback execution beyond main-image process attach and validate thread/DLL cases | 1 pw |
| 1.5 | D3D9 basic rendering (DrawPrimitive, SetStreamSource, FVF) | 8 pw |
| 1.6 | Full user32 input APIs (GetKeyState, MapVirtualKey, etc.) | 3 pw |
| 1.7 | WinMM audio (waveOutOpen, timeGetTime) | 2 pw |
| 1.8 | Broaden forwarded-export coverage across larger DLL sets and runtime paths | 2 pw |
| 1.9 | DllMain execution for all loaded DLLs | 1 pw |
| 1.10 | Close the most common COM/vtable holes for D3D11/DXGI/XAudio2 launcher paths | 6 pw |

### Phase 2: Broad Compatibility (70% → 85%) — 51 person-weeks

| # | Item | Effort |
|---|------|--------|
| 2.1 | D3D9 full implementation (textures, shaders, state management) | 15 pw |
| 2.2 | D3D11 missing features (GS, HS, DS, deferred contexts, feature levels) | 8 pw |
| 2.3 | GDI+/DWrite/UI fidelity pass (GraphicsPath, Image, Matrix, shaping, glyph fidelity) | 8 pw |
| 2.4 | Full COM marshaling and proxy/stub | 6 pw |
| 2.5 | CPU: remaining string/system instruction coverage plus FXSAVE/XSAVE validation after Track A | 5 pw |
| 2.6 | Installer full execution (NSIS, InnoSetup, MSI) | 8 pw |
| 2.7 | Security: WinVerifyTrust, Authenticode, DPAPI, and launcher/browser trust behavior | 5 pw |
| 2.8 | UxTheme / visual styles | 2 pw |
| 2.9 | Unified browser/Steam launcher path with real cookies, storage, login, and update flows | 6 pw |

### Phase 3: Deep Compatibility (85% → 95%) — 58 person-weeks

| # | Item | Effort |
|---|------|--------|
| 3.1 | D3D12 full device interface chain (Device1–Device12) plus real execution for advanced feature paths | 12 pw |
| 3.2 | OpenGL 4.1 → Metal translation (or MoltenVK/Zink delegation) | 15 pw |
| 3.3 | ntdll.dll syscall-level emulation | 10 pw |
| 3.4 | Full memory model (CoW, guard pages, ASLR, 64TB layout) | 6 pw |
| 3.5 | Media Foundation pipeline plus zero-copy video decode/present integration | 8 pw |
| 3.6 | RPC / DCOM | 8 pw |
| 3.7 | CPU: Full AVX-512 EVEX decode and execution | 5 pw |
| 3.8 | Self-modifying code detection + JIT cache invalidation | 3 pw |
| 3.9 | Tile-aware guest submission scheduling across D3D11/D3D12/Metal hot paths | 4 pw |

### Phase 4: Near-Perfect (95% → 99%) — 44 person-weeks

| # | Item | Effort |
|---|------|--------|
| 4.1 | ActiveX / IE COM full implementation | 10 pw |
| 4.2 | DirectDraw complete implementation | 8 pw |
| 4.3 | D3D10 layer (or D3D11 fallback mapping) | 6 pw |
| 4.4 | Full DXGI output duplication / multi-adapter | 4 pw |
| 4.5 | Printing / XPS / GDI printing | 4 pw |
| 4.6 | JIT Tier2 optimization beyond Track A (register allocation, instruction scheduling, profile-guided specialization) | 8 pw |
| 4.7 | Hardware debug register emulation | 2 pw |
| 4.8 | Rare API coverage (WMI, WTS, ETW, Job objects) | 6 pw |

### Phase 5: The Last Mile (99% → 99.9%) — 30+ person-weeks

| # | Item | Effort | Notes |
|---|------|--------|-------|
| 5.1 | Anti-cheat bypass / compatibility layer | 10 pw | EAC, BattlEye, Vanguard detected but cannot run kernel drivers |
| 5.2 | DRM compatibility (Denuvo, Arxan, VMProtect) | 8 pw | Requires extremely accurate timing and CPU behavior |
| 5.3 | Edge-case API behavior matching real Windows | 5 pw | Error codes, undocumented behavior |
| 5.4 | Multi-process coordination (full CreateProcess chain) | 4 pw | Process inheritance, handle duplication |
| 5.5 | Rare CPU instruction edge cases | 3 pw | Undefined behavior matching, alignment faults |
| 5.6 | Accessibility APIs (UIAutomation, MSAA) | 3 pw | New module |
| 5.7 | Windows services full emulation | 5 pw | SCM has basic stubs |

---

## 5. Key Insights

### 5.1 Top 10 Highest-Impact Items

| Rank | Item | Impact | Effort | ROI |
|------|------|--------|--------|-----|
| 1 | **PE runtime unsupported import/vtable closure** | Removes the most common hard-stop failures in already-partially-supported titles | 10 pw | ★★★★★ |
| 2 | **SEH/exception handling** | Required by all C++ apps with try/catch and real crash recovery | 8 pw | ★★★★★ |
| 3 | **Zero-copy browser/video/present path** | Directly reduces overhead and launcher/UI stutter on Apple Silicon | 5 pw | ★★★★★ |
| 4 | **JIT tiering + fast-thunk paths** | Cuts guest/host transition overhead in hot loops and API-heavy games | 6 pw | ★★★★★ |
| 5 | **D3D9 full implementation** | Unblocks a large legacy library (Halo, HL2, Max Payne 2 era) | 30 pw | ★★★★☆ |
| 6 | **Real Metal shader/pipeline cache** | Eliminates runtime compilation hitches and improves repeat-launch smoothness | 4 pw | ★★★★★ |
| 7 | **Unified browser/Steam launcher path** | Required for modern launchers, login flows, storefront UI, and updates | 6 pw | ★★★★★ |
| 8 | **COM marshaling** | Required by Office, Steam UI, complex apps | 6 pw | ★★★★☆ |
| 9 | **Installer execution** | Required for app installation flow and dependency bootstrapping | 8 pw | ★★★★☆ |
| 10 | **D3D11 GS/HS/DS shaders** | Required by modern AAA games with tessellation | 8 pw | ★★★★☆ |

### 5.2 Realistic vs. Architecture-Changing

**Realistic with current architecture:**
- SEH, DLL exports, user32 input, WinMM, AES/SHA/PCLMUL lowering, and honest CPUID/XCR0 gating
- JIT tiering, direct block chaining, fast-thunk ABI paths, and unsupported-import closure
- Zero-copy unified-memory composition, real Metal pipeline caches, D3D11 gaps, D3D12 incremental improvements
- Browser/Steam launcher unification, installer execution, and security/trust expansion
- These represent ~80% of the remaining work

**Requires fundamental architecture changes:**
- **D3D9 fixed-function pipeline**: Needs a complete compatibility-oriented rendering pipeline that still does not exist end to end in the Metal backend
- **OpenGL native translation**: Better to delegate to MoltenGL or Zink
- **Anti-cheat / DRM**: Kernel driver emulation would require a hypervisor
- **Full AVX-512 execution**: 512-bit vector operations on 128-bit NEON hardware

### 5.3 Comparison with Wine/CrossOver/Proton

| Aspect | Casa1 | Wine/Proton |
|--------|-------|-------------|
| **Architecture** | PE loader + JIT (x86→ARM64) | PE loader + native x86 execution |
| **Graphics** | Direct-to-Metal (D3D11/12→MSL) | DXVK (D3D→Vulkan) + VKD3D + MoltenVK |
| **CPU** | Interpreter + custom ARM64 JIT | Native execution (same ISA) |
| **Win32 API** | Large but still partial thunk surface; unsupported imports remain | ~40,000+ functions |
| **COM/OLE** | Basic apartments, IDispatch | Full marshaling, ActiveX, IE |
| **Testing** | 37 Rust test files plus ignored/manual Steam suites, fuzzing, benches, and CI | ~10,000+ conformance tests |
| **macOS native** | Direct Metal rendering | XQuartz/X11 or MoltenVK |

### 5.4 What "Good Enough" 90% Compatibility Looks Like

A 90% compatibility target means:
- **All top-100 Windows applications** run correctly
- **All top-200 games** from 2010–2024 launch and are playable
- **Steam** fully functional, including launcher/login/update/browser-backed flows
- **Installers** work for NSIS, InnoSetup, MSI, and custom installers
- **D3D9/10/11/12** all supported with Metal rendering
- **Audio** works for XAudio2, DirectSound, WASAPI
- **Networking** works for Winsock, HTTP, TLS, and certificate/pinning-sensitive launchers
- **Already-supported titles** avoid obvious shader-compilation stalls and CPU-copy-heavy browser/video/present paths

**To reach 90%, the minimum required work is:**
1. PE runtime import/vtable closure — 10 pw
2. SEH completion (Phase 1.1) — 8 pw
3. D3D9 full implementation (Phase 2.1) — 15 pw
4. D3D11 tessellation/geometry shader completion (Phase 2.2) — 8 pw
5. JIT tiering + fast-thunk path (Track A.2) — 6 pw
6. Zero-copy browser/video/present path (Track A.3) — 5 pw
7. Real Metal shader/pipeline cache (Track A.4 + A.5) — 7 pw
8. Unified browser/Steam launcher path (Phase 2.9) — 6 pw
9. COM marshaling (Phase 2.4) — 6 pw
10. Installer execution (Phase 2.6) — 8 pw
11. Security/trust expansion (Phase 2.7) — 5 pw

**Estimated total effort for 90% with Apple-native smoothness goals: ~130 person-weeks (~2.5 years for a 2-person team, allowing parallel Track A work)**

### 5.5 Code-Grounded Backlog

The full authored-file scan points to a more concrete top-level backlog than the legacy percentage table:

1. **Close PE-runtime unsupported imports and COM/vtable holes first**: `src/pe_runtime.rs` still contains many unsupported imports and large `unsupported_method(...)` regions for D3D11, D3D12, DXGI, XAudio2, DirectInput, ShellLink/IPersistFile, WebView2, and OpenVR.
2. **Finish loader/runtime correctness**: exception-directory and unwind support, broader DLL lifecycle fidelity, and end-to-end SEH remain more important than adding new headline APIs.
3. **Make CPU feature honesty match real Apple M lowering**: `src/cpu.rs` and `src/jit.rs` should prioritize AES/SHA/PCLMULQDQ, FXSAVE/XSAVE-family support, and honest CPUID/XCR0 exposure before broader feature claims.
4. **Reduce guest/host boundary cost**: add direct block chaining, hot-path block versioning, flag-liveness-aware JIT behavior, and specialized fast-thunk ABIs for common runtime calls.
5. **Make unified-memory zero-copy composition a first-class path**: `src/metal_backend.rs`, `src/metal_renderer.rs`, `src/webview2.rs`, `src/cef_bridge.rs`, and media paths should converge on IOSurface/CVPixelBuffer-backed composition instead of CPU upload fallbacks.
6. **Replace modeled Metal optimizations with real hot-path infrastructure**: pipeline/binary archives, true async compilation, completion-driven command-buffer reuse, and tile-aware pass scheduling should move from helper abstractions into live guest submission paths.
7. **Turn graphics planning into guest-visible execution**: the D3D11, D3D12, Vulkan, OpenGL, shader, and Metal layers already track substantial state, but several high-value paths still stop at planning, validation, or metadata instead of true execution.
8. **Promote browser embedding and Steam UI to first-class compatibility goals**: `src/webview2.rs`, `src/cef_bridge.rs`, and `src/steam_integration.rs` show that Steam UI and browser-backed launchers are one of the largest integration risks.
9. **Harden trust, transport, and installer realism together**: `src/network.rs`, `src/winhttp.rs`, `src/wininet.rs`, and `src/installer.rs` need to move from good model coverage to real trust, pinning, script/custom-action, and service-install behavior.
10. **Strengthen CI/fuzz/perf gates and telemetry**: the repo has real benches, fuzzers, and sanitizers, but CI still lacks feature-matrix builds, fuzz execution, performance thresholds, and automatic ranking from unsupported-runtime telemetry.

### 5.6 Missing-Features Matrix

| Feature family | What already exists | Main remaining gap | Priority |
|----------------|---------------------|----------|----------|
| CPU / JIT | Broad interpreter, custom ARM64 JIT, block caching, tiering, SMC invalidation hooks | Unsupported VEX/EVEX/x87/selectors, missing ARM-backed crypto lowering, and too many generic runtime exits | P0 |
| PE runtime | Real PE execution, import dispatch, TLS process-attach callbacks, trace/log/report plumbing | Unsupported imports, unsupported vtables, and missing unwind/SEH completeness | P0 |
| D3D11 / D3D12 / DXGI | Real device/runtime state, descriptor/resource tracking, shader/cache integration | Wider interface completion, true execution fidelity for advanced features, and Apple GPU-aware hot-path scheduling | P0 |
| Vulkan / OpenGL | Real loader and state scaffolding | Guest-ready execution and non-shallow exported compatibility surfaces | P1 |
| Browser / Steam UI | WKWebView-backed CEF bridge and WebView2-shaped state model | One real browser path with working cookies, storage, DOM/network behavior, Steam UI parity, and zero-copy composition | P0 |
| Steam platform | Depot/install/update/protocol/service scaffolding and ignored/manual Steam.exe suites | Full SteamService, IPC, manifest/library discovery, zero-touch bootstrap, and browser-backed UX | P0 |
| Networking / TLS | Real WinHTTP/WinINet/reqwest-backed stacks and native TLS plumbing | Strict trust, pinning, launcher-compatible certificate behavior, and broader Winsock fidelity | P0 |
| Installers | Strong replay/extraction/model coverage across MSI/NSIS/Inno/InstallShield | Full script/custom-action execution and dependency/service realism | P1 |
| COM / Win32 services | Broad local COM, VARIANT/SAFEARRAY, BCrypt, SCM, and threadpool models | Marshaling, out-of-proc behavior, fuller CNG/service semantics | P1 |
| Media / video | MF-style shim, macOS H.264 path, decoder abstractions | Broader codec/container support, stronger real pipeline fidelity, and zero-copy present integration | P1 |
| Text / 2D UI | Real D2D/DWrite/GDI+ software rendering and layout models | Glyph rasterization, shaping, hit-testing, and richer UI fidelity | P1 |
| Metal execution infrastructure | Real Metal device/queue/pipeline wrappers plus advanced-feature scaffolding | IOSurface bridging, real ray/path execution hooks, actual pipeline archives, real async compile, and completion-driven reuse | P0 |
| Tooling / validation | CI, sanitizers, fuzz targets, benches, standalone Tetris sample | Feature-matrix CI, fuzz in CI, perf thresholds, and unsupported-runtime telemetry ranking | P2 |

---

## 6. Total Effort Summary

Note: Track A is a cross-phase execution-efficiency track. The totals below are gross planning effort and are not perfectly additive with phase-only estimates because some Track A work overlaps with Phases 1–3.

| Phase | Target | Effort | Cumulative |
|-------|--------|--------|------------|
| Current | ~55% | — | — |
| Track A | Apple-native efficiency and seamlessness | 28 pw | 28 pw |
| Phase 1 | 70% | 38 pw | 66 pw |
| Phase 2 | 85% | 51 pw | 117 pw |
| Phase 3 | 95% | 58 pw | 175 pw |
| Phase 4 | 99% | 44 pw | 219 pw |
| Phase 5 | 99.9% | 30+ pw | 249+ pw |

**Total estimated gross effort for near-100% with Apple-native efficiency goals: ~249 person-weeks (~5 years for a 1-person team, ~2.5 years for a 2-person team with overlapping Track A work)**

---

*This roadmap now includes a repo-wide authored-file scan across `src/`, `src/bin/`, `tests/`, `tests/support/`, `tests/fixtures/`, `fuzz/`, `ci/`, `benches/`, `games/windows_tetris/`, and root manifests/docs/artifacts. Percentages remain planning heuristics; the backlog and matrix sections are the most code-grounded parts of the document.*
