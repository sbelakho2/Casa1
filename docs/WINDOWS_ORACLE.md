# Windows Differential Oracle

## 1. Why

Casa1 reimplements Windows semantics (path parsing, case folding, share
conflicts, loader behavior, …). Any single wrong assumption can be baked into
both the runtime **and** the code that computes its expectations — the old
`casa1-oracle` binary computed expectations with Casa1-side implementations
(`oracle_parse_windows_path`, `oracle_fold_key`, `share_conflict`,
`oracle_load_order`, …), so a wrong Windows assumption could hide in both
sides and never be noticed.

The differential oracle breaks that loop:

* a **reference executable** (`windows_reference/casa1-windows-reference.exe`)
  runs on **real Windows 10/11** and executes test vectors with **real Win32
  and CRT calls** — it never reimplements semantics, it *is* Windows;
* the **host harness** (`src/bin/casa1-oracle.rs`) generates the same vectors
  and computes the **Casa1 runtime's own behavior** per vector (the
  emulated-Casa1 candidate);
* the harness **compares** the runtime candidate against the captured
  reference results and fails on any diff.  There is NO Casa1-side semantic
  model: the reference executable is the only truth, and categories the
  runtime cannot compute yet are reported honestly as `runtime_unavailable`.

## 2. Architecture

```
windows_reference/            standalone Cargo crate (workspace-excluded,
  src/main.rs                 has its own [workspace] table)
  src/schema.rs               wire schema (mirror of src/windows_oracle.rs)
  src/exec.rs                 platform dispatch
  src/win32.rs   [windows]    REAL Win32/CRT executors — the reference IS Windows
  src/stub.rs    [!windows]   stubs returning unsupported_platform

src/windows_oracle.rs         wire schema, deterministic corpus generator,
                              comparison engine (protocol, NOT semantics)
src/oracle_suites.rs          suite data contracts derived from the captured
                              reference results (consumed by sections 2/3)
src/bin/casa1-oracle.rs       harness only: `vectors`, `compare`, `api-report`,
                              and the CASA1_WINDOWS_REFERENCE_* env modes

tests/section42_windows_oracle.rs
tests/fixtures/section42/golden_windows_reference_results.json
.github/workflows/windows-oracle.yml
```

### 2.1. Reference executable = truth

`casa1-windows-reference.exe <vectors.json> <results.json>` reads a
schema-version-1 vector file, executes every vector **in file order** with
real API calls, and writes a canonical results file with a capture header.
Category coverage (all executed with real calls, never reimplemented):

| Category | Real APIs used |
| --- | --- |
| `path_normalize` | `GetFullPathNameW` (+ `SetCurrentDirectoryW` for cwd-dependent inputs) |
| `case_fold` | `CompareStringOrdinal(IGNORE_CASE)`, `GetStringTypeW(CT_CTYPE1)` |
| `file_sharing` | `CreateFileW` with access/share/disposition combos |
| `file_lock` | `LockFileEx`/`UnlockFileEx` incl. `ERROR_LOCK_VIOLATION` |
| `delete_semantics` | `DeleteFileW`, `MoveFileExW`, `GetFileAttributesW`, open-while-delete-pending |
| `api_set` | `LoadLibraryExW(LOAD_LIBRARY_SEARCH_SYSTEM32)` + `GetProcAddress` + `GetModuleHandleExW` + `GetModuleFileNameW` |
| `registry` | `RegCreateKeyExW`/`RegSetValueExW`/`RegQueryValueExW`/`RegDeleteValueW` (HKCU) |
| `synchronization` | `CreateEventW`/`CreateMutexW`/`CreateSemaphoreW`, waits, `ReleaseMutex`, `ReleaseSemaphore`, worker threads for `WAIT_ABANDONED`/`ERROR_NOT_OWNER` |
| `crt_printf` | UCRT `snprintf`/`%n`, `_set_invalid_parameter_handler`, `_set_printf_count_output`, `strtol`, `_errno` |
| `thread_tls` | `TlsAlloc`/`TlsSetValue`/`TlsGetValue`/`TlsFree`, thread isolation, `TLS_MINIMUM_AVAILABLE` |

`arithmetic_flags` is intentionally **not** a Windows category — the CPU
vectors belong to the CPU differential harness and are skipped here.

On non-Windows hosts the crate still builds (the workspace check depends on
it) and every vector reports `unsupported_platform`, which the comparison
flags as a diff — a non-Windows reference is never mistaken for Windows
truth.

### 2.2. No Casa1-side semantic model

The Casa1-side model (`src/oracle_model.rs`) was REMOVED entirely: a test
comparing Casa1 behavior against Casa1-computed expectations is not Windows
conformance.  The suite shapes the section tests consume
(`src/oracle_suites.rs`) are derived exclusively from the captured
reference results; categories the reference does not yet cover make the
corresponding tests skip with a clear message.

`compute_runtime_result` (`src/windows_oracle.rs`) computes the CASA1
RUNTIME's own behavior per vector by driving the runtime's real machinery
(`real_fs::parse_windows_path`, the GameEnvironment share/lock matrix, the
Win32Subsystem sync/TLS layers, the pe_runtime CRT tables) — the candidate
the differential validates.  Any divergence from a real Windows capture is
a runtime defect the CI reports.

## 3. Vector and result schema (schema_version 1)

```json
{
  "schema_version": 1,
  "vectors": [
    { "id": "path_normalize:000", "category": "path_normalize",
      "input": { "path": "C:\\Alpha\\Beta\\.\\Gamma\\..\\File.txt",
                 "cwd": null, "long_paths_enabled": false } }
  ]
}
```

```json
{
  "schema_version": 1,
  "capture": {
    "source": "windows",
    "captured_by": "casa1-windows-reference",
    "captured_on": "windows-10-11",
    "capture_date": "2026-08-19T14:02Z",
    "note": null,
    "os_edition": "Professional",
    "os_build": "10.0.22631",
    "arch": "x64",
    "reference_sha256": "…64 hex chars of the reference exe…",
    "corpus_sha256": "…64 hex chars of the vector corpus…"
  },
  "results": [ { "id": "path_normalize:000", "category": "path_normalize",
                 "output": { "normalized": "C:\\Alpha\\Beta\\File.txt",
                             "kind": "drive_abs", "has_ads": false,
                             "last_error": 0 } } ]
}
```

The provenance fields are computed by the reference executable at capture
time: os edition from the capture machine's registry (`EditionID`), build
from `RtlGetVersion`, architecture from `GetNativeSystemInfo`, plus the
SHA-256 of the reference executable itself and of the input corpus.  The
reference-results consumers require these fields to be present (serde
defaults keep old files parseable, but they are not accepted as real
captures).

Both sides reject files whose `schema_version` differs from the protocol
version. The schema is deliberately extensible: `input`/`output` are
category-specific JSON objects, so new categories need no wire-format change.

### 3.1. Per-category output shapes

| Category | Output fields |
| --- | --- |
| `path_normalize` | `normalized`, `kind` (`drive_abs`/`drive_rel`/`rooted`/`relative`/`unc`/`verbatim`/`device`), `has_ads`, `last_error` |
| `case_fold` | `ordinal_ignore_case_equal`, `left_c1_type_bits`, `right_c1_type_bits` |
| `file_sharing` | `second_open_succeeds`, `second_error` |
| `file_lock` | `lock1`/`lock2`/`unlock1`/`lock3` (`{performed, succeeded, error}`) |
| `delete_semantics` | `success`, `error`, `file_exists_after`, `rename_succeeded`, `second_open_succeeded`, `second_open_error` |
| `api_set` | `loads`, `resolved_module` (full path from `GetModuleFileNameW`), `export_resolvable` |
| `registry` | `error`, `value_bytes` (lowercase hex), `value_type` |
| `synchronization` | `waits` (array of wait return codes), `releases` (`[{succeeded, error}]`), `abandoned` |
| `crt_printf` | `handler_invoked`, `ret`, `errno`, `written`, `value`, `end_consumed`, `buffer` (nulls where N/A) |
| `thread_tls` | per-kind fields (`index_valid`, `set_succeeded`, `get_matches`, `minimum_available`, `free_succeeded`, `new_index_valid`, `succeeded`, `error`, `value_is_null`, `other_thread_value_is_null`, `main_value_preserved`) |

### 3.2. Determinism scope (what the corpus may assume)

The corpus is shared by the model (macOS) and the reference (Windows), and
CI fails on any diff, so vectors only cover behavior that is deterministic
across Windows 10/11 x64 machines:

* `path_normalize` inputs are cwd-independent, or carry an explicit `cwd`
  (the reference creates `C:\Windows\Temp\casa1-oracle-cwd` and
  `SetCurrentDirectoryW`s into it; the runtime executor resolves relative,
  drive-relative and root-relative inputs against the same fixed working
  directory). Verbatim/device inputs avoid `.`/`..` components
  (GetFullPathNameW's handling of dots inside `\\?\` paths is not
  exercised). Non-verbatim paths longer than MAX_PATH are **not** included:
  `GetFullPathNameW` behavior depends on the machine's `LongPathsEnabled`
  policy (the schema keeps `long_paths_enabled` for protocol completeness;
  the reference cannot honor a per-vector flag because the policy is
  process-wide).
* `api_set` host DLLs are device-dependent by design (Microsoft's api-set
  schema does not guarantee a stable host). The runtime executor reports the
  `pe::ApiSetResolver` host (`kernel32`, `ole32`, `ucrtbase`, `user32`, …);
  `loads` and `export_resolvable` are compared strictly, and
  `resolved_module` is normalized to the lowercased basename with one
  tolerance: if Windows reports the **virtual alias** itself (a name starting
  with `api-ms-`/`ext-ms-`) the comparison accepts it, because that is a
  legitimate loader report rather than a host difference. A real host
  mismatch (model says `user32`, Windows says something else) still fails.
* `case_fold` corpus characters are ASCII plus a small set of Latin-1/Greek
  letters with well-known Unicode properties (`Σ/ς/ß/µ/Μ/é/É`). Ordinal
  ignore-case folding is simple per-code-unit uppercasing: `ς`→`Σ`, `µ`→`Μ`,
  but `ß`≠`SS`.
* `crt_printf` relies on documented UCRT behavior: `%n` is disabled by
  default (invalid parameter handler invoked, EINVAL), enabled by
  `_set_printf_count_output(1)`; `strtol` overflow/underflow → `ERANGE` with
  `LONG_MAX`/`LONG_MIN`; invalid base → `EINVAL` with no consumption;
  `snprintf` truncation returns the would-be length; a null format invokes
  the invalid parameter handler. Vectors run in file order because the
  handler/%n state evolves across vectors.
* `thread_tls` avoids reading a freed slot (undefined/implementation-defined
  behavior); it covers alloc, set/get round-trip, per-thread isolation,
  `TLS_MINIMUM_AVAILABLE` (the SDK constant 64), `TlsFree`, reallocation,
  and invalid-index errors.
* `synchronization` waits use `INFINITE`/`0` timeouts only where the outcome
  is state-determined; the abandoned-mutex vector is race-free by
  construction (the worker is already blocked in its wait before the main
  thread releases, so the worker must acquire and terminate first).
* `registry` operates on `HKCU\Software\Casa1\OracleRef` and the reference
  cleans up after the run.

## 4. Harness commands

```
casa1-oracle vectors --out vectors.json [--categories a,b,c]
casa1-oracle compare --results r.json [--vectors v.json] [--categories ...]
               [--required-categories a,b,c] [--report-only]
casa1-oracle api-report --out api-completeness.json
```

`compare` computes the **Casa1 runtime's behavior** per vector (default
corpus when `--vectors` is omitted; filtered to the categories present in
the reference file) and prints a JSON report with per-category summaries and
per-field diffs. It exits `1` on any diff unless `--report-only`, and it
ALWAYS exits `1` when a `--required-categories` category is not validated
by the differential (the runtime reported it `runtime_unavailable`, or the
reference file does not cover it) — `--report-only` never suppresses the
coverage exit.  `--required-categories` defaults to all ten advertised
categories, so a compare against a reference file that covers a subset must
name the subset explicitly.

Environment-driven modes (ad-hoc use on a Windows host):

* `CASA1_WINDOWS_REFERENCE_EXE=<exe>` — the harness runs the reference
  executable on the generated corpus and compares its output;
* `CASA1_WINDOWS_REFERENCE_RESULTS=<file>` — the harness compares against an
  existing reference results file.

(There is no `model-results` command: the harness never computes expected
values itself.)

### 4.1. Golden fixture

`tests/fixtures/section42/golden_windows_reference_results.json` is a
checked-in reference-results file covering the `path_normalize`,
`case_fold`, and `file_sharing` vectors. It carries the capture header
(`source: "windows"`, `captured_by: "casa1-windows-reference"`) and is
currently **model-generated** — the first real Windows capture (CI artifact)
is the authoritative replacement. `tests/section42_windows_oracle.rs` validates that the golden file fails
loudly (placeholder values + the coverage gate) and that mutations are
detected; the tests also prove the fail-loud non-Windows stub behavior and
the required-categories gate.  The reference-results consumers
(`tests/support::reference_results`) REFUSE model-generated placeholders —
the differential tests skip until a real Windows capture is available.

## 5. Adding a category

1. Add the category name to `ALL_CATEGORIES` in `src/windows_oracle.rs`
   (and, if it is not Windows-specific, keep `arithmetic_flags` style
   categories out).
2. Add input/output shapes and a generator arm (`generate_category`) in
   `src/windows_oracle.rs`.
3. Add the Casa1 runtime candidate arm in `src/windows_oracle.rs`
   (`compute_runtime_result`), returning `runtime_unavailable` until the
   runtime behavior is implemented — never a fabricated pass.
4. Add the executor arm in `windows_reference/src/win32.rs` using real
   Win32/CRT calls only (and mirror any new input structs).
5. Add output-shape and determinism notes to this document and to the schema
   section above.
6. Extend the corpus in `generate_vectors` only with cases the model can
   predict exactly; ambiguous/device-dependent cases belong in the protocol
   but not in the CI corpus (see §3.2).

## 6. CI flow

`.github/workflows/windows-oracle.yml`:

1. **generate-corpus** (macos-latest): `casa1-oracle vectors` → uploads the
   vector file. Generation happens on macOS, not Windows: the generator is
   pure deterministic data and this keeps the Casa1 crate (which is not yet
   guaranteed to build on Windows) out of the Windows job — the Windows job
   builds only the tiny standalone reference crate.
2. **reference-capture** (windows-latest): builds
   `windows_reference` and runs
   `casa1-windows-reference.exe vectors.json results.json`; uploads the
   results artifact.
3. **compare** (macos-latest): downloads the artifact, runs
   `casa1-oracle compare --vectors … --results … --required-categories
   path_normalize,case_fold,file_sharing,file_lock,delete_semantics,api_set,registry,synchronization,crt_printf,thread_tls`;
   **the job fails on any diff**, and on any required category the runtime
   does not compute or the capture does not cover — the workflow cannot
   succeed with untested categories.

The checked-in golden fixture is validated by the regular `cargo test
--tests` run (`tests/section42_windows_oracle.rs`).

## 7. Extension plan

The protocol is designed to grow. Planned categories (each needs a real-API
executor in the reference, a model predictor, corpus vectors, and
comparison semantics):

* **CPU** — arithmetic flags, x87/SSE state: belongs to the CPU differential
  harness (not Windows); the protocol can host them via a future
  `cpu_*` category or a sibling harness.
* **VM** — VirtualAlloc/VirtualProtect/VirtualQuery commit/reserve states,
  page guard, `MEM_TOP_DOWN`, allocation granularity, `PAGE_GUARD` one-shot
  behavior.
* **Loader** — import resolution order, DLL search order (`SafeDllSearchMode`
  off/on), `LOAD_LIBRARY_SEARCH_*` flags, delay-load failures, TLS
  callbacks, module base randomization (`GetModuleHandleExW` probing).
* **Exceptions** — `RaiseException`/`UnhandledExceptionFilter` routing,
  vectored handlers, SEH unwind order, `EXCEPTION_CONTINUE_EXECUTION`
  semantics, `SetUnhandledExceptionFilter` return-value behavior.
* **Registry** — value enumeration order, `RegGetValue` normalization,
  32/64-bit views (`KEY_WOW64_*`), volatile keys, notify behavior.
* **Synchronization** — SRW locks, condition variables, `WaitOnAddress`,
  reader/writer lock recursion, `QueueUserAPC` ordering, `Sleep` vs
  `SleepEx` alertability.
* **User32** — window class atom handling, `WM_NCCREATE` return semantics,
  message queue invariants, `GetWindowLongPtr` index validation,
  `CreateWindowEx` failure codes.
* **COM** — apartment initialization (`CoInitializeEx`), class registration,
  `CoCreateInstance` HRESULT mapping, `IUnknown` reference-counting
  protocol, `RegisterClassObject`/`CoRevokeClassObject`.
* **Winsock** — `WSAStartup` versions, blocking vs non-blocking error codes
  (`WSAEWOULDBLOCK`), `select`/`WSAEventSelect` state transitions, socket
  option inheritance.
* **WinHTTP** — `WinHttpOpen` session semantics, header normalization,
  proxy environment handling, `WINHTTP_OPTION_*` validation.
* **GDI** — device context state (`SaveDC`/`RestoreDC`), pen/brush
  selection, `GetObject` returns, `CreateCompatibleDC` behavior.
* **DXGI** — adapter enumeration (`EnumAdapters`/`EnumAdapterByLuid`),
  `CreateSwapChain` parameter validation, feature-level fallback.
* **Audio/MF** — `WASAPI` device enumeration, format negotiation
  (`IsFormatSupported`), Media Foundation source resolution, `MFTEnum`
  ordering.

Each extension follows the same contract: versioned vectors, real-API
reference execution, runtime executor (never a fabricated pass), strict
comparison, CI failure on any diff or coverage gap.
