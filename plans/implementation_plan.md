# Casa1 Remediation Plan — Full Implementation

Based on [`AUDIT_REPORT.md`](../AUDIT_REPORT.md) analysis, this plan covers all 32 findings (F-01 through F-32) and all conformance test gaps across 5 phases. Each item includes specific code changes, files to modify, and test criteria.

---

## Phase 0: Foundational Fixes (Immediate)
**Goal:** Fix existing stubs/placeholders and add missing infrastructure before major new features.

### P0.1 — Complete ole32.dll COM Stubs → Working COM Subsystem
**Files:** [`src/real_win32.rs`](../src/real_win32.rs), [`src/pe_runtime.rs`](../src/pe_runtime.rs), [`src/win32.rs`](../src/win32.rs)
**Finding:** F-04 (CRITICAL)

Current state: `CoCreateInstance` only handles `SHELL_LINK_CLSID`. All other CLSIDs return error.

Tasks:
1. Extend [`ComApartmentState`](../src/real_win32.rs:19) with CLSID→IClassFactory registration table
2. Implement `DllGetClassObject` resolution from registered DLLs
3. Add `IClassFactory::CreateInstance` dispatch for well-known CLSIDs:
   - `DirectSound8` (`3901CC3F-84B5-4FA4-BA35-AA8172B8A6B2`)
   - `XAudio2` (`609ED052-35B5-4F10-9BE6-39650F9781D4`)
   - `CLSID_FileOpenDialog` / `CLSID_FileSaveDialog`
   - `CLSID_ShellLink` (already partially handled)
4. Add COM apartment-aware threading (`CoInitializeEx` with STA/MTA), message pump dispatch for STA
5. Add `CoGetClassObject`, `CoRegisterClassObject`, `CoRevokeClassObject`
6. Add `IUnknown` vtable trampolines for QueryInterface/AddRef/Release in guest memory
7. Add `IDispatch` support with `GetIDsOfNames` and `Invoke` for basic OLE automation
8. Add `VARIANT`/`BSTR`/`SAFEARRAY` handling in [`pe_runtime.rs`](../src/pe_runtime.rs) `HostThunk::VariantClear` (line 13023) and extend with `SysAllocString`, `SysFreeString`, `VariantInit`, `VariantCopy`

**Test:** [`tests/section28_com.rs`](../tests/) (new file) — COM object creation round-trip, refcount verification, QueryInterface for IUnknown→IDispatch, STA apartment behavior test, `DirectSound8` creation via COM.

### P0.2 — Complete CreateProcessW/A for Child Process Launch
**Files:** [`src/pe_runtime.rs`](../src/pe_runtime.rs), [`src/runner.rs`](../src/runner.rs), [`src/cli.rs`](../src/cli.rs)
**Finding:** F-09 (HIGH)

Current state: `CreateProcessW`/`CreateProcessA` thunks at lines 14243-14442 exist but only handle launching within the same GE context, not true child processes.

Tasks:
1. Implement actual sub-process spawning: the Casa1 runner executes a new Casa1 process with a new GE or shared context
2. Pass inherited handles (stdin/stdout/stderr) via environment/pipes
3. Implement `WaitForSingleObject` on process handles
4. Implement `GetExitCodeProcess` and `TerminateProcess`
5. Add `PROCESS_INFORMATION` structure filling with real process/thread IDs
6. Add `STARTUPINFOW` parsing (show window, stdin/stdout handles)

**Test:** [`tests/section29_process.rs`](../tests/) (new) — launcher EXE creates child process, both produce output, parent waits for child, exit codes match.

### P0.3 — Expand DLL Synthetic Export Tables
**Files:** [`src/pe_runtime.rs`](../src/pe_runtime.rs) (export_tables function at line 41185)
**Finding:** From the "DLLs with Synthetic Export Tables" section + ~200 missing DLLs

Current state: ~20 DLLs with exports. Missing critical DLLs: `comctl32.dll`, `comdlg32.dll`, `oleaut32.dll`, `shlwapi.dll`, `crypt32.dll`, `wintrust.dll`, `setupapi.dll`, `dwrite.dll`, `propsys.dll`, `urlmon.dll`, `mscoree.dll`, `msvcrt.dll`, `winmm.dll`, `imm32.dll`, `usp10.dll`, etc.

Tasks:
1. Add export tables for all DLLs listed as gaps in the audit report
2. Each export table needs at minimum the most commonly called 10-20 functions as working thunks (not stubs)
3. For `comctl32.dll`: `InitCommonControls`, `InitCommonControlsEx`, `CreateWindowExW` (delegated), `ImageList_Create`, `ImageList_Add`, `ImageList_Destroy`, `ListView_*` wrappers
4. For `oleaut32.dll`: `SysAllocString`, `SysFreeString`, `SysReAllocString`, `VariantInit`, `VariantClear`, `VariantCopy`, `VariantChangeType`, `SafeArrayCreate`, `SafeArrayDestroy`, `SafeArrayAccessData`, `SafeArrayUnaccessData`, `LoadTypeLib`, `RegisterTypeLib`
5. For `crypt32.dll`: `CertOpenStore`, `CertCloseStore`, `CertFindCertificateInStore`, `CertGetNameStringW`, `CertFreeCertificateContext`, `CryptAcquireContextW`, `CryptCreateHash`, `CryptHashData`, `CryptDeriveKey`, `CryptEncrypt`, `CryptDecrypt`, `CertCreateCertificateContext`
6. For `wintrust.dll`: `WinVerifyTrust` (delegate to native-tls), `CryptCATAdminCalcHashFromFileHandle`, `CryptCATAdminEnumCatalogFromHash`
7. For `shlwapi.dll`: `PathCombineW`, `PathCanonicalizeW`, `PathFindExtensionW`, `PathRemoveExtensionW`, `PathAppendW`, `StrChrW`, `StrCmpW`, `StrCpyW`, `StrCatW`, `SHDeleteKeyW`
8. For `msvcrt.dll`: Full C runtime (most can delegate to `ucrtbase.dll` exports)
9. For `winmm.dll`: `waveOutOpen`, `waveOutClose`, `waveOutWrite`, `waveOutPrepareHeader`, `waveOutUnprepareHeader`, `timeGetTime`, `PlaySoundW`, `mciSendCommandW`
10. For `imm32.dll`: `ImmGetContext`, `ImmSetCompositionWindow`, `ImmReleaseContext`, `ImmGetDefaultIMEWnd`
11. For `dwrite.dll`: `DWriteCreateFactory` (stub that returns basic factory)

**Test:** Extend [`tests/section1.rs`](../tests/section1.rs) or create new conformance tests — each DLL's exports are loadable, key functions return non-error.

### P0.4 — Fix Forwarded Exports Chaining
**Files:** [`src/pe_runtime.rs`](../src/pe_runtime.rs)
**Finding:** Forwarded exports (MEDIUM) — e.g., `kernel32.Sleep` → `kernelbase.Sleep`

Tasks:
1. When resolving an import that points to a forwarded export (`ExportTarget::Forwarder`), follow the chain recursively
2. Ensure `GetProcAddress` resolves forwarded exports by following the chain
3. Detect circular forwarding and fail gracefully

**Test:** Existing [`tests/section2.rs`](../tests/section2.rs) — add test verifying forwarded `kernel32.Sleep` resolves to `kernelbase.Sleep`'s handler.

### P0.5 — Add DLL Entry Point Execution (DllMain)
**Files:** [`src/pe_runtime.rs`](../src/pe_runtime.rs)
**Finding:** DLL entry point execution (MEDIUM) — loaded DLLs need `DLL_PROCESS_ATTACH` with proper HMODULE

Tasks:
1. When a synthetic DLL is first loaded via `LoadLibrary`, call its DllMain entry point with `DLL_PROCESS_ATTACH`
2. For real PE DLLs in the filesystem, execute their actual entry point
3. Track loaded HMODULE values for proper reference counting

**Test:** Extend existing `LoadLibrary` test in Section 1 or 2 to verify `DLL_PROCESS_ATTACH` is called.

---

## Phase 1: macOS App Integration (CRITICAL)
**Goal:** Make installed Windows apps visible and launchable from macOS

### P1.1 — PE Icon Extractor
**Files:** [`src/pe.rs`](../src/pe.rs), [`src/installer.rs`](../src/installer.rs)
**Finding:** F-02 (CRITICAL)

Current state: `find_resource_blob` at line 1388 can extract resources by type ID. Need to add:
- `RT_GROUP_ICON` (type ID 14) and `RT_ICON` (type ID 3) parsing
- `RT_GROUP_ICON` directory entry → individual icon directory entries
- Extract the largest icon (prefer 256×256 32bpp or 48×48 32bpp)

Tasks:
1. Add constants `RT_GROUP_ICON = 14`, `RT_ICON = 3`
2. Add `IconDirHeader`, `IconDirEntry`, `IconImage` structs
3. Add `find_resource_group_icon()` to traverse PE resource directory for `RT_GROUP_ICON`
4. Add `extract_icon_from_pe(path) -> AppResult<Option<IconImage>>` that:
   - Parses `RT_GROUP_ICON` to get list of icon entries (width, height, color count, reserved, planes, bpp, size, offset)
   - Extracts individual icon data via `RT_ICON` entries
   - Picks the highest-quality icon (largest size, most colors)
   - Returns raw BMP/DIB pixel data + dimensions
5. Add `extract_all_icons_from_pe(path) -> AppResult<Vec<IconImage>>` for multi-resolution extraction

**Test:** New tests in [`tests/section30_app_bundle.rs`](../tests/) — `extract_icon_from_pe` on a known PE with icons returns valid icon data with expected dimensions.

### P1.2 — ICO → PNG/ICNS Converter
**Files:** New file [`src/icon.rs`](../src/icon.rs), or extend [`src/installer.rs`](../src/installer.rs)
**Finding:** F-02 (CRITICAL)

Tasks:
1. Parse ICO directory and individual icon entries from raw bytes
2. Convert BMP/DIB icon data to PNG using `png` crate (add to `Cargo.toml`)
3. Generate macOS `.icns` file format:
   - `ic07` (128×128 PNG), `ic08` (256×256 PNG), `ic09` (512×512 PNG), `ic10` (512×512@2x / 1024×1024 PNG)
   - Construct proper ICNS container with header and icon entries
4. Alternatively, generate a simple `.icns` using the `icns` crate or manual binary construction

**Test:** Unit test: known ICO input → valid ICNS output that `iconutil -c icns` accepts (verify by running `iconutil` in test). Test with 16×16, 32×32, 48×48, 256×256 sizes.

### P1.3 — App Bundle Generator
**Files:** New file [`src/app_bundle.rs`](../src/app_bundle.rs), extend [`src/cli.rs`](../src/cli.rs)
**Finding:** F-01 (CRITICAL)

Tasks:
1. Create `AppBundleGenerator` struct with methods:
   - `create_app_bundle(app_name, executable, icon_data, bundle_id) -> PathBuf`
2. Generate directory structure:
   ```
   Foo.app/
     Contents/
       Info.plist
       MacOS/
         casa1-wrapper   (simple shell script or Rust binary)
       Resources/
         icon.icns
       Frameworks/
   ```
3. Generate `Info.plist` with:
   - `CFBundleIdentifier`: `com.casa1.<normalized_app_name>`
   - `CFBundleName`: app name
   - `CFBundleDisplayName`: app name
   - `CFBundleIconFile`: `icon`
   - `CFBundleExecutable`: `casa1-wrapper`
   - `LSMinimumSystemVersion`: `14.0`
   - `NSHighResolutionCapable`: `true`
   - `CFBundleURLTypes` for `steam://` URL handling if applicable
4. Generate `casa1-wrapper` shell script that calls the `casa1` binary with the correct GE and EXE arguments
5. Install the app bundle to `~/Applications/Casa1/` (or user-specified `--apps-dir`)

**Test:** Integration test: call `create_app_bundle("Tetris", ...)` → verify `Tetris.app/Contents/Info.plist` exists with correct fields → verify `casa1-wrapper` script is executable → verify `icon.icns` is valid.

### P1.4 — Launch Services Registration
**Files:** Extend [`src/app_bundle.rs`](../src/app_bundle.rs), or new file
**Finding:** F-03 (CRITICAL)

Tasks:
1. After app bundle creation, call `LSRegisterURL` via CoreServices framework to register the `.app` bundle with Launch Services
2. Use `objc` bindings or `libc` FFI to call `LSOpenCFURLRef`/`LSRegisterURL`
3. Alternatively, run `/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f <app_bundle_path>`

**Test:** After registration, verify `mdfind "kMDItemFSName == 'Tetris.app'"` returns the app path. Verify `open Tetris.app` launches the wrapper.

### P1.5 — CLI `install` Command
**Files:** [`src/cli.rs`](../src/cli.rs), [`src/installer.rs`](../src/installer.rs)
**Finding:** F-01 (CRITICAL)

Tasks:
1. Add `apps:install` CLI subcommand:
   ```
   casa1 apps:install --ge <ge> --exe <path> --name "App Name" [--apps-dir <path>]
   ```
2. This command runs the installer inside the GE, then:
   a. Extracts icon from the installed executable using PE icon extractor (P1.1)
   b. Converts to ICNS (P1.2)
   c. Generates app bundle (P1.3)
   d. Registers with Launch Services (P1.4)
3. Add `apps:list` subcommand to list installed app bundles
4. Add `apps:uninstall` subcommand to remove app bundle and deregister

**Test:** E2E test: install a sample app → verify `.app` appears → verify `open` launches it → verify `apps:list` shows it → uninstall → verify removed.

### P1.6 — Dock Integration During App Execution
**Files:** New file or extend [`src/ge.rs`](../src/ge.rs) or [`src/cef_bridge.rs`](../src/cef_bridge.rs)
**Finding:** F-28 (LOW), F-29 (LOW), F-30 (LOW)

Tasks:
1. When a Windows app runs inside Casa1, set the `NSDockTile` to show the app's icon and name
2. Use `NSProcessInfo` to add `beginActivity` with `NSActivityUserInitiatedAllowingIdleSystemSleep` to prevent App Nap during gameplay
3. Add `NSApplication` activation policy change to show the app in Dock as its own identity
4. Add Spotlight metadata import after app installation

**Test:** Manual verification + unit test for `NSProcessInfo` activity assertion.

---

## Phase 2: Graphics Completeness (HIGH)
**Goal:** Support D3D12, Vulkan, and OpenGL for modern games

### P2.1 — D3D12 Root Signature → Metal Argument Buffers (Complete)
**Files:** [`src/d3d12.rs`](../src/d3d12.rs), [`src/metal_backend.rs`](../src/metal_backend.rs)
**Finding:** F-07 (HIGH) — Root signature mapping partial

Tasks:
1. Complete mapping for all descriptor range types (CBV, SRV, UAV, Sampler)
2. Handle unbounded descriptor arrays (infinite-sized ranges)
3. Handle static samplers in root signatures
4. Handle root constants → inline data in argument buffers
5. Handle root descriptors (CBV, SRV, UAV) directly in root signature
6. Add descriptor table offset management for tier-1 and tier-2
7. Handle visibility flags (SHADER_VISIBILITY_*) correctly

**Test:** [`tests/section6.rs`](../tests/section6.rs) — add test: D3D12 root signature with 4 descriptor tables, unbounded array, 3 static samplers maps to correct Metal argument buffer layout.

### P2.2 — D3D12 Resource Barriers (Complete)
**Files:** [`src/d3d12.rs`](../src/d3d12.rs), [`src/gfx.rs`](../src/gfx.rs)
**Finding:** F-07 (HIGH) — Resource barriers partial

Tasks:
1. Complete transition barrier support for all resource states
2. Implement aliasing barriers for placed resources
3. Implement UAV barriers (already partially in `record_uav_barrier`)
4. Handle split barriers (`D3D12_RESOURCE_BARRIER_TYPE` split begin/end)
5. Add subresource tracking for per-subresource barrier states

**Test:** Extend Section 6 test: render target → pixel shader resource transition produces correct pixel output.

### P2.3 — D3D12 Mesh Shaders
**Files:** [`src/d3d12.rs`](../src/d3d12.rs), [`src/metal_backend.rs`](../src/metal_backend.rs) ([`MeshPipeline`](../src/metal_backend.rs:1563) exists)
**Finding:** F-24 (MEDIUM)

Tasks:
1. Map D3D12 mesh shader (SM 6.5+) to Metal mesh shaders (Metal 3 `MTL::MeshRenderPipelineDescriptor`)
2. Map amplification shaders to Metal object shaders
3. Handle mesh shader payload (vertex/primitive output) conversion
4. Add `DispatchMesh` to command list recording
5. Add threadgroup size mapping

**Test:** Extend Section 6: mesh shader draws correct geometry, vertex count matches.

### P2.4 — DXR 1.0/1.1 Raytracing → Metal Raytracing API
**Files:** [`src/d3d12.rs`](../src/d3d12.rs), [`src/metal_backend.rs`](../src/metal_backend.rs) (acceleration structure and raytracing pipeline structs exist at lines 1254-1456)
**Finding:** F-24 (MEDIUM)

Tasks:
1. Map `D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_INPUTS` to Metal acceleration structure builds
2. Implement bottom-level AS (BLAS) and top-level AS (TLAS) creation
3. Implement `DispatchRays` with shader table parsing
4. Map raygeneration, closesthit, miss, intersection shaders to Metal intersector functions
5. Handle `D3D12_RAYTRACING_PIPELINE_FLAGS`
6. Add raytracing output (RWTexture) support

**Test:** Basic raytraced shadow renders correctly with PSNR > 40dB compared to reference.

### P2.5 — MoltenVK Integration for Vulkan Support
**Files:** [`src/vkgl.rs`](../src/vkgl.rs), [`Cargo.toml`](../Cargo.toml)
**Finding:** F-06 (HIGH)

Current state: [`src/vkgl.rs`](../src/vkgl.rs) has struct/function stubs, SPIR-V parser, and Vulkan state machine skeleton.

Tasks:
1. Bundle MoltenVK dynamically (add `molten-vk` crate or link `libMoltenVK.dylib`)
2. Implement `vkCreateInstance` and `vkCreateDevice` → `MTLDevice`
3. Implement `vkCreateSwapchainKHR` → `CAMetalLayer` + Metal drawables
4. Implement `vkCreateBuffer`/`vkCreateImage` → Metal buffers/textures
5. Implement `vkCmdDraw`/`vkCmdDrawIndexed` → Metal render command encoding
6. Implement `vkCreateShaderModule` → compile SPIR-V → MSL via existing shader compiler infrastructure
7. Implement `vkCreateGraphicsPipelines` → `MTLRenderPipelineState`
8. Implement `vkCreateComputePipelines` → `MTLComputePipelineState`
9. Add `VK_KHR_swapchain`, `VK_KHR_surface`, `VK_MVK_macos_surface` extensions

**Test:** [`tests/section31_vulkan.rs`](../tests/) (new): `vkcube` equivalent renders at 60fps via MoltenVK inside Casa1.

### P2.6 — OpenGL via ANGLE
**Files:** [`src/vkgl.rs`](../src/vkgl.rs) (GLState struct exists at line 2836)
**Finding:** F-10 (HIGH)

Current state: `GLState` exists with basic state tracking but no actual GL rendering.

Tasks:
1. Integrate ANGLE (OpenGL ES → Metal) library or build a minimal GL→Metal translator
2. Implement WGL context creation (fake `wglCreateContext` → Metal device)
3. Map core GL functions (glClear, glDrawArrays, glDrawElements, glBufferData, glTexImage2D) to Metal equivalents
4. Implement GLSL → MSL compilation for basic shaders
5. Support GL states: blend, depth test, stencil, culling, scissor, viewport

**Test:** [`tests/section32_opengl.rs`](../tests/) (new): simple OpenGL triangle renders correctly.

### P2.7 — GDI+ Completion
**Files:** [`src/user32.rs`](../src/user32.rs)
**Finding:** F-11 (HIGH)

Current state: Basic GDI operations present but `Gdip*` functions not implemented.

Tasks:
1. Add `GdipCreateFromHDC`, `GdipDeleteGraphics`
2. Add `GdipDrawLine`, `GdipDrawRectangle`, `GdipDrawEllipse`, `GdipDrawString`
3. Add `GdipCreateSolidFill`, `GdipCreateSolidBrush`, `GdipDeleteBrush`
4. Add `GdipFillRectangle`, `GdipFillEllipse`, `GdipFillRegion`
5. Add `GdipCreatePen1`, `GdipDeletePen`
6. Add `GdipSetSmoothingMode`, `GdipSetTextRenderingHint`
7. Add `GdipCreateBitmapFromHBITMAP`, `GdipCreateHBITMAPFromBitmap`
8. Add `GdipDrawImage`, `GdipDrawImageRect`
9. Add `GdipCreatePath`, `GdipAddPathLine`, `GdipClosePathFigure`, `GdipDeletePath`
10. Add `GdipSetClipPath`, `GdipSetClipRect`
11. Add `GdipBeginContainer`, `GdipEndContainer`
12. Add `GdipSaveGraphics`, `GdipRestoreGraphics`
13. Add `GdipCreateMatrix`, `GdipDeleteMatrix`, `GdipSetWorldTransform`
14. Implement via software rendering to a bitmap buffer (no Metal required for GDI)

**Test:** [`tests/section33_gdi.rs`](../tests/) (new): GDI+ test app renders lines, rectangles, ellipses, text, paths, transforms correctly.

---

## Phase 3: Long Tail Win32 APIs (HIGH/MEDIUM)
**Goal:** Cover the most commonly used missing Win32 APIs

### P3.1 — Add ~200 Missing DLL Synthetic Export Tables
**Files:** [`src/pe_runtime.rs`](../src/pe_runtime.rs) (export_tables function)
**Finding:** From "~200+ Windows DLLs have NO synthetic export table"

Tasks:
Add entries for:
- `comctl32.dll` (30+ exports: InitCommonControls, ImageList_*, ListView_*, TreeView_*, TabCtrl_*, etc.)
- `comdlg32.dll` (10+ exports: GetOpenFileNameW, GetSaveFileNameW, ChooseColorW, ChooseFontW, PageSetupDlg, PrintDlg)
- `shlwapi.dll` (20+ exports: Path* functions, Str* functions, SHDeleteKeyW, SHAutoComplete)
- `crypt32.dll` (20+ exports: Cert* functions, Crypt* functions, PFXImportCertStore)
- `wintrust.dll` (5 exports: WinVerifyTrust, CryptCATAdmin*)
- `setupapi.dll` (10+ exports: SetupDi* functions for device enumeration)
- `urlmon.dll` (10+ exports: URLDownloadToFileW, UrlMk*)
- `dwrite.dll` (1 export: DWriteCreateFactory — stub)
- `propsys.dll` (5 exports: PSPropertyKeyFromString, PSGetPropertyDescriptionFromString)
- `mscoree.dll` (1 export: CorBindToRuntimeEx — stub returning error)
- `winmm.dll` (15+ exports: waveOut*, midiOut*, time*, PlaySound, mci*)
- `imm32.dll` (8 exports: ImmGetContext, ImmSetCompositionWindow, etc.)
- `msacm32.dll` (5 exports: acm* audio compression manager stubs)
- `dplay.dll`/`dplayx.dll` (5 exports each: DirectPlayCreate stubs)
- `ddraw.dll` (10 exports: DirectDrawCreate, IDirectDraw* stubs returning D3D9 shim)
- `mf.dll`/`mfplat.dll`/`mfreadwrite.dll` (15+ exports: MFStartup, MFCreateMediaType, MFCreateSourceReader, etc.)
- `dxva2.dll` (5 exports: DXVA2* stubs)
- `evr.dll` (5 exports: EVR* stubs)
- `wmcodecdsp.dll` (3 exports stub)
- `wmasf.dll` (3 exports stub)

### P3.2 — WebSocket Support in WinHTTP/WinInet
**Files:** [`src/winhttp.rs`](../src/winhttp.rs), [`src/wininet.rs`](../src/wininet.rs)
**Finding:** F-17 (MEDIUM)

Tasks:
1. Implement `WinHttpWebSocketCompleteUpgrade`, `WinHttpWebSocketSend`, `WinHttpWebSocketReceive`, `WinHttpWebSocketClose`, `WinHttpWebSocketShutdown`
2. Map to native `tungstenite` crate or `reqwest` WebSocket support
3. Add corresponding WinInet WebSocket functions

**Test:** New WebSocket echo test: connect to wss://echo.websocket.org, send message, receive echo.

### P3.3 — NTFS Alternate Data Streams Support
**Files:** [`src/real_fs.rs`](../src/real_fs.rs), [`src/ge.rs`](../src/ge.rs)
**Finding:** F-18 (MEDIUM)

Tasks:
1. Extend virtual FS to support `file:ADS_name` syntax
2. Add `CreateFileW` support for ADS paths (e.g., `file.txt:hidden_stream:$DATA`)
3. Store ADS data alongside main file data in virtual FS
4. Implement `BackupRead`/`BackupWrite` for ADS-aware backup

**Test:** Write/read ADS from virtual file, verify data is separate from main stream.

### P3.4 — Registry Change Notifications
**Files:** [`src/real_win32.rs`](../src/real_win32.rs), [`src/ge.rs`](../src/ge.rs)
**Finding:** F-20 (MEDIUM)

Tasks:
1. Implement `RegNotifyChangeKeyValue` with polling at configurable interval
2. Track key/value changes since last notification check
3. Support `REG_NOTIFY_CHANGE_NAME`, `REG_NOTIFY_CHANGE_ATTRIBUTES`, `REG_NOTIFY_CHANGE_LAST_SET`, `REG_NOTIFY_CHANGE_SECURITY` flags
4. Support asynchronous notification (overlapped) and synchronous (wait)

**Test:** Set registry value, wait for notification, verify callback fires.

### P3.5 — XAPO Audio Effects Processing
**Files:** [`src/audio.rs`](../src/audio.rs), [`src/real_audio.rs`](../src/real_audio.rs)
**Finding:** F-21 (MEDIUM)

Tasks:
1. Implement `IXAPO` interface with `Process`, `Initialize`, `GetRegistrationProperties`
2. Implement basic XAPO effect chain processing in software mixer
3. Add reverb effect (convolution reverb with configurable decay)
4. Add equalizer effect (basic 10-band EQ)
5. Wire XAPO chain into XAudio2 voice graph

**Test:** Reverb effect applied to source voice produces audibly different output (verify with FFT comparison).

### P3.6 — Named Pipes for Cross-Process IPC
**Files:** [`src/win32.rs`](../src/win32.rs), [`src/pe_runtime.rs`](../src/pe_runtime.rs)
**Finding:** F-22 (MEDIUM)

Tasks:
1. Implement `CreateNamedPipeW` with PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE/MESSAGE modes
2. Implement `ConnectNamedPipe` (blocking and overlapped)
3. Implement `DisconnectNamedPipe`
4. Implement `CallNamedPipe` (create, connect, write, read, close)
5. Implement `WaitNamedPipe`
6. Use Unix domain sockets on macOS for backing storage
7. Support `PIPE_WAIT` and `PIPE_NOWAIT` modes

**Test:** Two Casa1 processes communicate via named pipe, data integrity verified.

### P3.7 — InstallShield Installer Support
**Files:** [`src/installer.rs`](../src/installer.rs)
**Finding:** F-23 (MEDIUM)

Tasks:
1. Detect InstallShield cabinet files (`.cab`) and `setup.boot`/`setup.inx`
2. Parse InstallShield script format (if possible) or fall back to silent install with detected flags
3. Extract files from InstallShield cabinets
4. Handle InstallShield's `ISSetup.dll` custom actions (execute them as external processes)

**Test:** An InstallShield-based app installs successfully in Casa1 GE.

---

## Phase 4: Media, Steam & Advanced Features (MEDIUM/LOW)
**Goal:** Video playback, Steam completeness, remaining features

### P4.1 — Video Decoder Integration (FFmpeg)
**Files:** [`src/media.rs`](../src/media.rs), new file [`src/video_decoder.rs`](../src/video_decoder.rs)
**Finding:** F-12 (HIGH)

Tasks:
1. Add `ffmpeg-next` crate dependency or use system FFmpeg via FFI
2. Implement H.264/H.265/VP9 decoding
3. Implement software decode → Metal texture upload pipeline
4. Implement video frame timing with presentation timestamps
5. Integrate with Media Foundation `SourceReader` stub

**Test:** 1080p H.264 video plays at 30fps without frame drops, PSNR > 35dB vs reference.

### P4.2 — Media Foundation Pipeline (Basic MFT Graph)
**Files:** [`src/media.rs`](../src/media.rs)
**Finding:** F-13 (MEDIUM)

Tasks:
1. Implement `MFCreateMediaSession`, `MFCreateSourceResolver`, `MFCreateTopology`
2. Implement basic topology building: source → video decoder → video renderer
3. Implement `IMFMediaSession::Start`, `Pause`, `Stop`, `Shutdown`
4. Implement `IMFMediaEventGenerator` for session events

**Test:** MF-based video player renders frames correctly via Casa1.

### P4.3 — SteamVR Functionality
**Files:** [`src/steamvr.rs`](../src/steamvr.rs)
**Finding:** F-14 (MEDIUM)

Tasks:
1. Implement `VR_Init` and `VR_Shutdown` properly
2. Implement `IVRSystem::GetRecommendedRenderTargetSize`, `GetEyeOutputViewport`
3. Implement `IVRCompositor::Submit` → render to Metal texture for HMD display
4. Implement `IVRChaperone` (basic play area definition)
5. Implement tracked device pose retrieval (headset, controllers)
6. Use dummy/static poses when no real headset connected (developer mode)
7. Add `IVRRenderModels` stubs

**Test:** VR app initializes, gets poses, and submits frames without crashing. Actual HMD rendering requires hardware.

### P4.4 — Steam Overlay
**Files:** New file [`src/steam_overlay.rs`](../src/steam_overlay.rs), extend [`src/steam_integration.rs`](../src/steam_integration.rs)
**Finding:** F-15 (MEDIUM)

Tasks:
1. Implement `ISteamOverlay` interface (hook into Casa1 rendering pipeline)
2. Implement Shift+Tab hotkey detection
3. Render overlay as separate Metal render pass composited over game output
4. Overlay content: friends list, web browser (via WKWebView/CefBridge), achievements, notifications
5. Implement `SetOverlayState`, `IsOverlayEnabled`

**Test:** Overlay renders on top of game without significant performance drop (<5% frame time impact).

### P4.5 — Steam Cloud Save Sync
**Files:** Extend [`src/steam.rs`](../src/steam.rs), [`src/steam_integration.rs`](../src/steam_integration.rs)
**Finding:** F-32 (LOW)

Tasks:
1. Implement `ISteamRemoteStorage` interface:
   - `FileWrite`, `FileRead`, `FileDelete`, `FileExists`, `FileSize`, `GetFileTimestamp`
   - `GetQuota`, `SetSyncPlatforms`
   - `UGCDownload`, `UGCDownloadToFile`, `UGCRead`
2. Store cloud saves in local GE filesystem (stub for actual Steam Cloud sync)
3. Implement file change detection and automatic sync (local-only initially)

**Test:** Write save game via `ISteamRemoteStorage::FileWrite`, read back via `FileRead`, verify byte-identical. Persists across sessions.

### P4.6 — AVX-512/BMI2/FMA SIMD Instructions
**Files:** [`src/cpu.rs`](../src/cpu.rs), [`src/jit.rs`](../src/jit.rs)
**Finding:** F-16 (MEDIUM)

Tasks:
1. Add decoder entries for AVX-512F (foundation) instructions:
   - Vector operations: `VADDPS`, `VSUBSPS`, `VMULPS`, `VDIVPS`, `VFMADD132PS`, `VFMSUB132PS`
   - Mask operations: `KANDW`, `KORW`, `KNOTW`, `KSHIFTLW`, `KSHIFTRW`
   - Scatter/gather: `VGATHERDPS`, `VSCATTERDPS`
   - Compress/expand: `VCOMPRESSPS`, `VEXPANDPS`
2. Add BMI1/BMI2: `ANDN`, `BEXTR`, `BLSI`, `BLSMSK`, `BLSR`, `BZHI`, `MULX`, `PDEP`, `PEXT`, `RORX`, `SARX`, `SHLX`, `SHRX`
3. Add FMA3/FMA4: `VFMADD132PS/PD/SS/SD`, `VFNMADD132PS/PD/SS/SD`, etc.
4. For unimplemented instructions, add fallback to software emulation using Cranelift's scalar ops + manual SIMD emulation

**Test:** SIMD-heavy compute workload produces identical results to native x86_64 reference output.

### P4.7 — Multi-touch and Pen Input
**Files:** [`src/real_hid.rs`](../src/real_hid.rs)
**Finding:** F-19 (MEDIUM)

Tasks:
1. Add `WM_TOUCH` message generation from macOS trackpad gestures
2. Use `NSTouch` or `CGEvent` to capture touch points
3. Map to Windows touch structures: `TOUCHINPUT`, `TOUCH_HIT_TESTING_INPUT`
4. Register touch window via `RegisterTouchWindow`
5. Add pen/tablet support via NSTabletPoint events
6. Map to `WM_POINTERDOWN`, `WM_POINTERUPDATE`, `WM_POINTERUP` messages
7. Add `Wintab` API stubs (`WTInfoW`, `WTOpenA`, `WTClose`, `WTPacket`)

**Test:** Touch events delivered to app with correct coordinates. Pen pressure/angle values accessible.

### P4.8 — MSAA Resolve Edge Cases
**Files:** [`src/d3d11.rs`](../src/d3d11.rs), [`src/gfx.rs`](../src/gfx.rs)
**Finding:** F-25 (LOW)

Tasks:
1. Implement custom MSAA resolve kernels for non-standard resolve operations
2. Handle 4x and 8x MSAA sample patterns correctly
3. Add `ResolveSubresource` with format conversion support
4. Handle MSAA render targets bound as shader resources (sample-frequency shading)

**Test:** MSAA resolve produces correct anti-aliased output, match reference.

### P4.9 — MIDI Synthesis
**Files:** New file [`src/midi.rs`](../src/midi.rs), extend [`src/audio.rs`](../src/audio.rs)
**Finding:** F-26 (LOW)

Tasks:
1. Implement General MIDI synthesis using a simple wavetable synthesizer (or bundle a tiny SoundFont synthesizer)
2. Implement `midiOutOpen`, `midiOutShortMsg`, `midiOutLongMsg`, `midiOutClose`
3. Handle MIDI events: Note On/Off, Program Change, Control Change, Pitch Bend
4. Mix MIDI output into Casa1 audio mixer

**Test:** Play MIDI file via Casa1, verify audio output contains expected notes (frequency analysis).

### P4.10 — Force Feedback / Haptic Rumble
**Files:** [`src/real_hid.rs`](../src/real_hid.rs), [`src/steam_input.rs`](../src/steam_input.rs)
**Finding:** F-27 (LOW)

Tasks:
1. Implement `IDirectInputEffect` interface for force feedback
2. Map XInput vibration to macOS haptic feedback via `IOHIDDevice` or `CoreHaptics`
3. Map Steam Input haptics to controller vibration
4. Handle left/right motor speed separately for XInput

**Test:** Triggering rumble via XInput produces controller vibration. Manual verification needed for force feedback wheel.

---

## Phase 5: Conformance Tests (All Severities)
**Goal:** Add tests for all new features and existing untested subsystems

### P5.1 — App Bundle Conformance Tests (CRITICAL)
**File:** [`tests/section30_app_bundle.rs`](../tests/) (new)

Tests:
1. PE icon extraction from known Windows executables (notepad.exe, etc.)
2. ICO → ICNS conversion producing valid iconutil-accepted output
3. App bundle directory structure generation
4. Info.plist correctness (all required keys)
5. Launch Services registration verification
6. `casa1 apps:install` E2E workflow
7. `casa1 apps:list` and `casa1 apps:uninstall`

### P5.2 — D3D12 Rendering Conformance Tests (HIGH)
**File:** Extend [`tests/section6.rs`](../tests/section6.rs)

Tests:
1. Root signature with 4 descriptor tables maps to correct argument buffer layout
2. Resource barrier transitions for all state combinations
3. Mesh shader draws correct geometry
4. Basic raytraced shadow rendering
5. Heap/committed/placed resource management
6. Render pass suspension/resumption

### P5.3 — COM Conformance Tests (HIGH)
**File:** [`tests/section28_com.rs`](../tests/) (new)

Tests:
1. `CoInitializeEx`/`CoUninitialize` round-trip
2. `CoCreateInstance` for DirectSound8 and XAudio2
3. COM object refcounting via `AddRef`/`Release`
4. `QueryInterface` for `IUnknown`, `IDispatch`
5. STA apartment behavior (message pump required)
6. `VARIANT` creation, modification, clearing
7. `BSTR` allocation, modification, freeing
8. `SAFEARRAY` creation, access, destruction
9. `IDispatch::GetIDsOfNames` and `IDispatch::Invoke` for simple method calls

### P5.4 — Multi-Process Conformance Tests (MEDIUM)
**File:** [`tests/section29_process.rs`](../tests/) (new)

Tests:
1. CreateProcess → child process launches independently
2. Parent waits for child via `WaitForSingleObject`
3. `GetExitCodeProcess` returns correct exit code
4. Inherited handles (stdin pipe) work correctly
5. Named pipe communication between parent and child
6. Process handle duplication via `DuplicateHandle`

### P5.5 — Vulkan/OpenGL Conformance Tests (HIGH)
**File:** [`tests/section31_vulkan.rs`](../tests/), [`tests/section32_opengl.rs`](../tests/) (new)

Tests:
1. Vulkan instance/device creation
2. Vulkan swapchain creation and presentation
3. Vulkan triangle rendering (compare pixel output)
4. Vulkan compute shader execution
5. OpenGL context creation (WGL)
6. OpenGL triangle rendering
7. GLSL shader compilation

### P5.6 — Video Decode Conformance Tests (MEDIUM)
**File:** [`tests/section34_video.rs`](../tests/) (new)

Tests:
1. H.264 decoder initialization
2. H.264 1080p decode at 30fps
3. Video frame → Metal texture upload
4. Timestamp presentation correctness
5. Media Foundation topology build and playback

### P5.7 — Extended Network/Crypto Tests
**File:** Extend [`tests/section10.rs`](../tests/section10.rs), [`tests/section11.rs`](../tests/section11.rs)

Tests:
1. WebSocket echo test
2. Raw socket (ICMP ping — if privileges allow)
3. NTFS ADS read/write
4. Registry change notification

### P5.8 — Steam Feature Tests
**File:** Extend [`tests/section25.rs`](../tests/section25.rs), [`tests/section26.rs`](../tests/section26.rs)

Tests:
1. Steam Cloud save write/read round-trip (data model)
2. Steam overlay state management
3. SteamVR initialization/poses/submit (without headset)
4. Steam Input haptic feedback

---

## Summary of All 32 Findings Coverage

| Finding | Severity | Phase | Status |
|---------|----------|-------|--------|
| F-01 No macOS .app bundle generation | CRITICAL | P1.3, P1.5 | New |
| F-02 No PE icon extraction → ICNS | CRITICAL | P1.1, P1.2 | New |
| F-03 No Launch Services registration | CRITICAL | P1.4 | New |
| F-04 No COM/OLE automation | CRITICAL | P0.1 | Extend |
| F-05 No kernel-mode driver emulation | CRITICAL | P0.1 (shim) | New |
| F-06 No Vulkan/MoltenVK | HIGH | P2.5 | New |
| F-07 D3D12 incomplete | HIGH | P2.1-P2.4 | Extend |
| F-08 No .NET CLR hosting | HIGH | P3.1 (mscoree stub) | New |
| F-09 No CreateProcess | HIGH | P0.2 | Extend |
| F-10 No OpenGL | HIGH | P2.6 | New |
| F-11 GDI+ incomplete | HIGH | P2.7 | New |
| F-12 No video decode | HIGH | P4.1 | New |
| F-13 No DirectShow/MF | MEDIUM | P4.2 | New |
| F-14 SteamVR not functional | MEDIUM | P4.3 | Extend |
| F-15 No Steam Overlay | MEDIUM | P4.4 | New |
| F-16 AVX-512/BMI2/FMA incomplete | MEDIUM | P4.6 | Extend |
| F-17 No WebSocket | MEDIUM | P3.2 | New |
| F-18 No NTFS ADS | MEDIUM | P3.3 | New |
| F-19 No multi-touch/pen | MEDIUM | P4.7 | New |
| F-20 Registry notifications | MEDIUM | P3.4 | New |
| F-21 XAPO effect chains | MEDIUM | P3.5 | New |
| F-22 No named pipes | MEDIUM | P3.6 | New |
| F-23 InstallShield support | MEDIUM | P3.7 | New |
| F-24 Mesh shaders/DXR | MEDIUM | P2.3, P2.4 | New |
| F-25 MSAA edge cases | LOW | P4.8 | Extend |
| F-26 No MIDI | LOW | P4.9 | New |
| F-27 No force feedback | LOW | P4.10 | New |
| F-28 No macOS menu bar | LOW | P1.6 | New |
| F-29 No App Nap prevention | LOW | P1.6 | New |
| F-30 No Spotlight indexing | LOW | P1.6 | New |
| F-31 No Docker isolation | LOW | Deferred | — |
| F-32 Steam Cloud save sync | LOW | P4.5 | New |

---

## Conformance Test Gaps Coverage

| Gap | Severity | Phase |
|-----|----------|-------|
| No app bundle conformance test | CRITICAL | P5.1 |
| No icon extraction conformance test | CRITICAL | P5.1 |
| No D3D12 rendering conformance test | HIGH | P5.2 |
| No Vulkan/MoltenVK conformance test | HIGH | P5.5 |
| No COM conformance test | HIGH | P5.3 |
| No multi-process conformance test | MEDIUM | P5.4 |
| No video decode conformance test | MEDIUM | P5.6 |
| Steam voice/chat tests are model-only | MEDIUM | P5.8 |

---

## New Files to Create

| File | Phase | Purpose |
|------|-------|---------|
| `src/icon.rs` | P1.1-P1.2 | PE icon extraction and ICO/ICNS conversion |
| `src/app_bundle.rs` | P1.3-P1.4 | macOS `.app` bundle generator |
| `src/steam_overlay.rs` | P4.4 | Steam in-game overlay |
| `src/video_decoder.rs` | P4.1 | Video codec integration |
| `src/midi.rs` | P4.9 | MIDI synthesis |
| `tests/section28_com.rs` | P5.3 | COM conformance tests |
| `tests/section29_process.rs` | P5.4 | Multi-process conformance tests |
| `tests/section30_app_bundle.rs` | P5.1 | App bundle conformance tests |
| `tests/section31_vulkan.rs` | P5.5 | Vulkan conformance tests |
| `tests/section32_opengl.rs` | P5.5 | OpenGL conformance tests |
| `tests/section33_gdi.rs` | P2.7 | GDI+ conformance tests |
| `tests/section34_video.rs` | P5.6 | Video decode conformance tests |

## Files to Significantly Extend

| File | Changes |
|------|---------|
| `src/pe.rs` | Add icon resource parsing (`RT_GROUP_ICON`, `RT_ICON`) |
| `src/pe_runtime.rs` | Complete COM stubs, expand export tables, add forwarded export chaining, add DllMain |
| `src/real_win32.rs` | Complete COM apartment, add CLSID registry, add IDispatch |
| `src/win32.rs` | Add named pipes, extend CreateProcess |
| `src/d3d12.rs` | Complete root signature, resource barriers, mesh shaders, raytracing |
| `src/metal_backend.rs` | Wire up mesh shaders, raytracing pipelines |
| `src/vkgl.rs` | Implement working Vulkan→Metal translation |
| `src/user32.rs` | Complete GDI+ functions |
| `src/audio.rs` / `src/real_audio.rs` | XAPO effect chains |
| `src/media.rs` | Media Foundation pipeline |
| `src/steamvr.rs` | Functional VR runtime integration |
| `src/steam_integration.rs` | Steam Cloud, Workshop, Overlay integration |
| `src/cpu.rs` / `src/jit.rs` | AVX-512/BMI2/FMA instruction coverage |
| `src/real_hid.rs` | Multi-touch, pen, force feedback |
| `src/real_fs.rs` | NTFS ADS |
| `src/installer.rs` | InstallShield support |
| `src/winhttp.rs` / `src/wininet.rs` | WebSocket support |

## New Dependencies (Cargo.toml)

- `png` — PNG encoding for icon conversion (P1.2)
- `image` — Image format handling for icon processing (P1.2)
- `tungstenite` — WebSocket client (P3.2)
- `ffmpeg-next` — Video decoding (P4.1)
- `midly` — MIDI file parsing (P4.9)
- `hound` — WAV file writing for audio tests (P3.5)
