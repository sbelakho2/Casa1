# Code Audit Findings — src/shader.rs

- **Batch:** Casa1 shader/DXIL pipeline audit (batch 1)
- **File:** `src/shader.rs` (5976 lines, read fully in sequential chunks 1–5976)
- **Date:** 2026-08-15
- **Toolchain:** `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (see Build section)

Severity counts: **CRITICAL 1 · HIGH 5 · MEDIUM 9 · LOW 7 · PERF 1** (23 findings total; per-line references inside).

---

## [CRITICAL] Index-out-of-bounds panic on untrusted DXIL operand (`dim >= 3`)

- File: src/shader.rs:1977, src/shader.rs:1986, src/shader.rs:1995, src/shader.rs:2007
- Description: Four sites do `let dim = args[0].parse::<u32>().unwrap_or(0);` followed by `["x", "y", "z"][dim as usize].min("z")`. `args[0]` is a raw operand taken from parsed DXIL bytecode (untrusted input). Any operand value ≥ 3 (e.g. a shader compiled against a bogus or hand-crafted resource dimension, or any 3D op with `dim=3` in the "component" slot) panics with `index out of bounds` in both debug and release builds (bounds check is never elidable here). The trailing `.min("z")` is a string compare, not the intended `dim.min(2)`, so it provides no protection. This is the only reachable panic in the file from attacker-controlled shader data.
- Fix suggestion: Replace with a checked lookup, e.g. `let coord = match dim { 0 => "x", 1 => "y", _ => "z" };` (or `["x","y","z"].get(dim as usize).copied().unwrap_or("z")`). Apply to all four sites.

## [HIGH] LLVM BinaryOps 11–16 mislabeled — every bitwise/shift op translates to the wrong MSL operator

- File: src/shader.rs:1574-1580
- Description: `dxil_opcode_to_msl` maps opcodes 11–16 as `11 => "&", 12 => "|", 13 => "^", 14 => "<<", 15 => ">>", 16 => ">>"`. Per the LLVM IR `BinaryOps` enum (and the record layout `[opcode, type, op0, op1]` in `FUNC_CODE_INST_BINOP`), the correct mapping is `11=Shl, 12=LShr, 13=AShr, 14=And, 15=Or, 16=Xor`. As written, `and`/`or`/`xor` produce `<<`/`>>`/`>>` and `shl`/`lshr`/`ashr` produce `&`/`|`/`^` — wrong output for every shader using integer bitwise ops (extremely common in HLSL).
- Fix suggestion: `11 => binop("<<"), 12 => binop(">>"), 13 => binop(">>"), 14 => binop("&"), 15 => binop("|"), 16 => binop("^")`.

## [HIGH] Instruction operands are mapped to temporaries by position, not by bitcode value ID

- File: src/shader.rs:3518-3523
- Description: In `generate_msl_from_parsed_dxil`, each operand is rendered as `_t{i}` (its position in the operand list) whenever `(i as u32) < var_counter.saturating_sub(1)`, else as the raw number. LLVM bitcode operands are dense value IDs (relative to the current instruction in bitcode v1), not per-instruction indices: this heuristic references nonexistent/wrong `_tN` temporaries for essentially any multi-operand instruction, and emits raw value IDs (type indices, constants) as MSL expressions in the fallback. The resulting MSL is wrong or fails to compile. No value-ID→temp registry exists anywhere in the file.
- Fix suggestion: Build a `BTreeMap<u32, String>` mapping bitcode value IDs → `_tN` as instructions are emitted (per function), and resolve operands through it, falling back to an emitted `constant` for unknown IDs.

## [HIGH] Signedness/floating-ness hardcoded; div/rem/comparison translation is wrong for signed and unsigned operands

- File: src/shader.rs:3525-3528 (call site), src/shader.rs:1560-1573, src/shader.rs:1584-1601, src/shader.rs:3247
- Description: `is_signed` is hardcoded `false` and `is_float` is a rough opcode-range guess. Consequences: (1) the `udiv/sdiv/fdiv` and `urem/srem` chains at 1560–1573 are three identical branches (clippy `if_same_then_else` confirms) — signed division of a negative int comes out as unsigned; (2) `icmp_ugt/uge/ult/ule` (opcodes 20–23) emit `>`, `>=`, `<`, `<=` which are signed semantics in MSL for `int` operands; (3) the CMP predicate mapping `18 + pred.min(11)` collapses all fcmp predicates ≥ 12 (OGT…TRUE) into `!=`, and maps fcmp_false(10)/fcmp_oeq(11) onto `==`/`!=` wrongly.
- Fix suggestion: Track types per value ID (from the TYPE_BLOCK reader) and pass real `is_signed`/`is_float`; map predicates explicitly: icmp 0–9 → 18–27 (signed/unsigned variants need distinct MSL expressions only where the operand type differs), fcmp 10–25 → proper `==`, `!=`, `>`, `>=`, `<`, `<=` with `is_float=true`.

## [HIGH] Char6 decoding is inverted versus the LLVM bitstream spec — names garble to digits/letters swapped

- File: src/shader.rs:960-971
- Description: LLVM's 6-bit char encoding is `'a'..'z' = 0..25, 'A'..'Z' = 26..51, '0'..'9' = 52..61, '.' = 62, '_' = 63`. `read_char6` maps `0..=9 → '0'..'9'`, `10..=35 → 'a'..'z'`, `36..=61 → 'A'..'Z'` — digits and letters are swapped regions, so every Char6-encoded string (type names, DXIL opaque-type names such as `dx.types.Handle`, record names) decodes to the wrong characters, corrupting any downstream name matching.
- Fix suggestion: Reorder the match arms to `0..=25 => (b'a' + val) as char`, `26..=51 => (b'A' + (val - 26)) as char`, `52..=61 => (b'0' + (val - 52)) as char`, `62 => '.'`, `63 => '_'`.

## [HIGH] Bitstream primitive decoding deviates from the LLVM bitstream format — real DXIL bitcode is misparsed

- File: src/shader.rs:1110-1121 (UNABBREV_RECORD), src/shader.rs:1034-1042 (ENTER_SUBBLOCK), src/shader.rs:1238-1260 (DEFINE_ABBREV), src/shader.rs:1159-1166 (Array)
- Description: Per LLVM's `BitCodeFormat` spec: (a) UNABBREV_RECORD is `[codevbr6, numopsvbr6, op0vbr6, …]` — code and num-ops are VBR6 values in the stream after the abbrev-id field; the code instead reads a 13-bit code and 14-bit num-ops out of the header word (`(header >> 2) & 0x1FFF`, `(header >> 15) & 0x3FFF`), then reads operands from the *next* word, so operand 0 onward is read from the wrong bit position for any record with operands (i.e. all of them). (b) ENTER_SUBBLOCK is `[blockidvbr8, newabbrevlenvbr4, <align32>, blocklen32]`; the code extracts a fixed 16-bit block ID and 2-bit abbrev width from the header word — wrong for DXIL-era (LLVM ≥ 3.0) streams. (c) DEFINE_ABBREV operands start with a literal-marker bit (`1` = literal followed by vbr8 value; `0` = encoding: Fixed=1, VBR=2, Array=3, Char6=4, Blob=5 with vbr5 width); the code parses `(kind << 3) | value` with a shifted kind numbering (`Literal=0`), so even correct abbrevs decode with wrong kinds/widths. (d) `AbbrevOp::Array` reads the length then all elements as VBR6, ignoring the element encoding operand that follows per spec. Net effect: abbreviated and unabbreviated records from real DXIL are misparsed; combined with the swallowed error at line 3623, shaders fall back to empty instruction bodies instead of failing loudly.
- Fix suggestion: Reimplement per spec: read code/numops via `read_vbr_uint(6)` after the abbrev-id field; read blockid/abbrevlen via VBR8/VBR4; parse abbrev operands by first reading a 1-bit literal flag, then encoding(3 bits)+vbr5 width or literal vbr8; decode Array elements using the following element operand encoding.

---

## [MEDIUM] VBR decode truncates values that cross a 32-bit word boundary; width-0 causes shift underflow

- File: src/shader.rs:871-902
- Description: In `read_vbr_uint`, when a VBR field straddles a word boundary the current chunk holds fewer than `width` bits; the continuation bit is then read as `(chunk >> (width - 1)) & 1` from the *truncated* chunk, which is always 0. A VBR6 value needing ≥ 6 chunks (value ≥ 2^30) is therefore decoded truncated instead of continuing into the next word. Additionally, `width == 0` (from a malformed BLOCKINFO abbrev `Vbr(0)`) makes `width - 1` underflow: `chunk >> 0xFFFF_FFFF` panics in debug builds and yields a wrong value (masked shift) in release. `shift` can also exceed 31 (`result |= (chunk & value_mask) << shift`), which is a debug panic/masked-truncation for large values.
- Fix suggestion: Reject `width == 0`; accumulate continuation across chunks by tracking the bit position of the *field* (not the chunk), e.g. only test the continuation bit when the full field bit has been consumed, and clamp `shift` (`if shift >= 32 { break; }`) so `<<` never overflows.

## [MEDIUM] Dot4AddI8Packed ignores sign extension — signed packed dot product is wrong for bytes ≥ 0x80

- File: src/shader.rs:2498-2507
- Description: `dx.op.dot4add.i8.packed` operates on signed i8 lanes; the emitted MSL `(int)((a >> 0) & 0xFF) * …` masks to 0..255 and then casts, so lane values ≥ 0x80 (i.e. negative i8) contribute 128..255 instead of -128..-1, producing incorrect results for any input with the high bit set. The U8 variant (2511) is correct.
- Fix suggestion: Sign-extend each lane, e.g. `(int)(int8_t)((a >> 0) & 0xFF)` per lane (or `(int)((a << 24) >> 24)`).

## [MEDIUM] sincos translation takes the address of operand variables and never assigns `dst`

- File: src/shader.rs:1853-1864
- Description: Emits `sincos(args[0], &dst, &args.get(1).unwrap_or(dst));` — `&args[1]` is an address-of on a plain value expression (MSL compile error or overwrite of an input), and `dst` is never assigned (the function writes through pointers), so the SSA-style temp that later instructions read is undefined. In the common 1-arg case both outputs alias `dst`, losing the cosine.
- Fix suggestion: Emit two temps: `float _s, _c; sincos(args[0], &_s, &_c); dst = _s;` (or `_tN`/`_tN+1`), and record both temps in the value-ID registry.

## [MEDIUM] Wave intrinsic emulations are semantically wrong

- File: src/shader.rs:2434-2445 (WaveMatch), src/shader.rs:2240-2249 & 2374-2433 (WavePrefix/MultiPrefix), src/shader.rs:2230-2232 (WaveActive)
- Description: (a) `WAVEMATCH` emits `simd_vote(a == a)` for the 1-arg form (via `args.get(1).unwrap_or(&args[0])`) — always true; WaveMatch must compare against the *current lane's* value (e.g. `simd_vote(args[0] == simd_broadcast_first(args[0]))` is also wrong; it needs per-lane comparison via `simd_ballot` over a broadcast comparison). (b) `WAVEPREFIX`/`WAVEMULTIPREFIX*` use `args[1]` as the value, but plain `WavePrefixSum(value)` has the value in `args[0]` (the 2-arg form is `(mask, value)` only for the Multi variants) — the mask gets summed instead of the value for the plain intrinsic. (c) `WAVEACTIVE` emits `simd_active(true)` which is not an MSL builtin.
- Fix suggestion: Match DXIL operand order per intrinsic (plain prefix ops take 1 arg), and emit `simd_ballot`/`simd_compare`-based equality masks for WaveMatch; replace `simd_active(true)` with `simd_active_mask()`.

## [MEDIUM] pack_cbuffer over-allocates scalar arrays (16 bytes/element) and can wrap on overflow

- File: src/shader.rs:3903-3910, src/shader.rs:4452-4458
- Description: For `array_len > 1`, non-matrix fields are sized `16 * array_len` regardless of components. HLSL cbuffer packing packs 4 scalars (or a float4) per 16-byte register, so `float data[8]` should be 32 bytes, not 128 — the reported cbuffer size and offsets are wrong for scalar/2-component arrays, and the constant buffer bound at that size will be mismatched. Additionally `align_up` computes `value + alignment - 1` without checked arithmetic; cbuffer sizes near u32::MAX wrap silently.
- Fix suggestion: Compute `element_size` from components and pack `ceil(array_len * components / 4) * 16` for scalar arrays (and use 16-per-element only for float4-sized elements); use `checked_add`/`checked_mul` in `align_up`.

## [MEDIUM] Bitcode/program parse failures are swallowed — shaders silently translate with empty bodies

- File: src/shader.rs:3619-3635 (`.ok()`), src/shader.rs:4034-4058 (compile_with_cache), src/shader.rs:2958 (skip_wrapper)
- Description: `translate_shader` calls `parse_dxil_program_bitcode(bitcode_bytes).ok()`, discarding the error and falling back to an empty `ParsedDxilProgram`; `generate_msl_from_parsed_dxil` then emits a body with zero instructions, and `compile_with_cache` counts such failures as ordinary misses. Any parser defect (see the HIGH bitstream finding) therefore degrades silently into shaders with no instruction bodies instead of surfacing `RcDxilInvalid`. `skip_wrapper()`'s bool return is likewise ignored, so a wrapper with a bad size field produces a misleading "missing LLVM bitcode magic" error.
- Fix suggestion: Propagate the bitcode parse error through `translate_shader` (map to a `ShaderError` with `failing_pass: "bitcode_parse"`); log/store failures in `CacheRunStats`; check and handle `skip_wrapper()`'s return value.

## [MEDIUM] Control-flow and memory translation are stubs producing wrong or uncompilable MSL

- File: src/shader.rs:1676-1683 (phi), src/shader.rs:1668-1675 (switch), src/shader.rs:1703-1706 (alloca), src/shader.rs:1707-1714 (load), src/shader.rs:1723-1730 (GEP)
- Description: phi always assigns the first incoming value (wrong for loops/branches); switch emits only a comment ("handled above", but nothing handles it); alloca emits only a comment while loads/stores/GEPs reference the pointer as `args[0][0]`/`&args[0][args[1]]` with no declarations emitted anywhere — generated MSL references undeclared variables and cannot compile for any shader with allocas or phi nodes (i.e. essentially all real ones). These are unfinished-translation markers (per the task: todo/unimplemented-class logic).
- Fix suggestion: At minimum, emit declarations for alloca'd temps in a preamble and track pointer→element sizes; map phi through the predecessor taken in the emitted goto structure; or reject such shaders explicitly with a clear error rather than emitting uncompilable MSL.

## [MEDIUM] Program-header layout and PROG payload offset assume a custom format, not DXIL's

- File: src/shader.rs:4085-4115 (parse_program_part), src/shader.rs:3673-3688 (find_prog_part_offset)
- Description: `parse_program_part` reads `instruction_count` at offset 0, `ir_size` at 4, threadgroup x/y/z at 8/12/16, `use_count` at 20. The DXIL spec program header is `version(4), size(4), bitcode_offset(4), bitcode_size(4), …` — feeding a real DXIL PROG part would interpret the bitcode size as a threadgroup size and the bitcode size as a resource-use count, likely rejecting valid shaders (or, if accepted, reading garbage uses). `find_prog_part_offset` uses `part_off + 24` which matches this file's own payload layout (24-byte header immediately after the part descriptor offset) but is 12 bytes short for standard DXIL containers that include a 12-byte part header (`part_off + 12 + 24`). If real DXIL is ever fed (the module docs claim "DXIL container and program part parsing"), translation breaks silently.
- Fix suggestion: Either document/pin the custom container format and validate a format tag, or implement the DXIL spec layout (version/size/bitcode_offset/bitcode_size) and compute the bitcode start as `part_off + 12 + 24` with the 12-byte part header accounted for.

## [MEDIUM] Reflection cross-check requires exact set equality — valid shaders may be rejected

- File: src/shader.rs:4187-4240
- Description: `cross_check_reflection` fails if the reflection resource set differs from the PROG-part use table by even one entry. The PROG uses are parsed from the (custom-format) use table while reflection comes from the RFLX part; any benign mismatch (e.g. cbuffer `size_bytes` `unwrap_or(0)` vs the reflection's real size, or samplers recorded as buffers) turns a perfectly renderable shader into a hard load failure.
- Fix suggestion: Compare per-resource with tolerance: require every `use` to be present in reflection (superset check) and only warn on extras; relax the cbuffer size comparison when the use table lacks a size.

---

## [LOW] Dead code: four unused functions, an unused struct field, unused enum field

- File: src/shader.rs:1264 (read_type_table), src/shader.rs:1381 (read_metadata_records), src/shader.rs:1398 (parse_module_block), src/shader.rs:1497 (hlsl_type_components), src/shader.rs:1481/3343 (DxilFunction.num_instructions written, never read), src/shader.rs:245 (CbufferField.is_bool never consulted in pack_cbuffer)
- Description: The four functions are never called (verified by grep across src/); `num_instructions` and `is_bool` are write-only. Relatedly, the TYPE_CODE_* constants used only by dead `read_type_table` are also wrong vs LLVM (HALF=10 not 13, FUNCTION_OLD=9 not 12, ARRAY=11 not 9, VECTOR=12 not 10), which hides the bitstream-format drift noted above.
- Fix suggestion: Delete the dead functions/fields, or wire `read_type_table` into operand typing (which would also fix the HIGH signedness finding).

## [LOW] Tautological test assertion

- File: src/shader.rs:4818
- Description: `assert!(decoded.is_none() || decoded.is_some());` is always true — the test verifies nothing (the comment above even says the checksum is intentionally bogus).
- Fix suggestion: Either construct the entry with a real checksum (`checksum_payload(&payload).unwrap()`) and assert `decoded.is_some()` + field equality, or assert `decoded.is_none()` with the dummy checksum.

## [LOW] `compile_msl_source` / `mtl_library_bytes` are placeholder formats — no Metal compilation happens

- File: src/shader.rs:3691-3696, src/shader.rs:3650-3660
- Description: `compile_msl_source` returns `"MTLCOMPILED|{len}|{src}"` bytes ("In production, this would invoke `metal`…"), and `translate_shader` wraps the MSL source in `"MSL|…|"` bytes that no consumer in this file parses. The pipeline currently cannot produce an actual Metal library; any caller treating `mtl_library_bytes` as compilable data gets source text.
- Fix suggestion: Wire in a real Metal compiler invocation (or the async compiler in `async_pipeline_compiler.rs`) and emit/consume a versioned binary format; otherwise document the contract and return the source with an explicit flag.

## [LOW] Wrapper handling deviates from the LLVM wrapper format

- File: src/shader.rs:551-554, src/shader.rs:975-996
- Description: The code checks wrapper magic `0xDEC0_4342`; LLVM's documented wrapper magic is `0x0B17C0DE` with fields `[Magic, Version, Offset, Size, CPUType]` — the code instead treats byte 4-7 as a big-endian size and skips only 8 bytes, and `skip_wrapper`'s result is ignored (see MEDIUM swallowing finding). DXIL doesn't use the wrapper at all, so this path is dead-but-wrong.
- Fix suggestion: Remove the wrapper branch or implement the documented format (LE magic 0x0B17C0DE, version 0, offset/size/CPUType) and honor the return value.

## [LOW] Intrinsic-ID mapping table should be validated against the DXIL opcode numbering

- File: src/shader.rs:2773-2943
- Description: The table maps IDs 150–160 to thread-ID/barrier intrinsics and 136–143 to atomics, but DXIL's actual opcode assignments place thread IDs/barriers in the 80–96 range and atomics around 130–145; mismatched IDs fall through to `map_dxil_intrinsic_id → None → generic call (opcode 41)`, silently emitting `_tN = _fn_<id>(...)` calls that reference nonexistent functions. The arithmetic range 6–60 matches the DXIL spec; the rest should be verified against `DXILOperations.h` before trusting (a wrong ID is silently a broken shader, not an error).
- Fix suggestion: Cross-check the table against DXC's `DXILOperations` numbering; for unmapped IDs emit a translation error instead of a generic call.

## [LOW] `fuzz_summary` error path includes the raw message — unbounded output

- File: src/shader.rs:4067-4079
- Description: `format!("err:{}:{}", error.code.as_u32(), error.message)` embeds `error.message`, which for parse errors contains untrusted length/format details and can be long (and non-deterministic across versions) in a fuzz-summary string.
- Fix suggestion: Truncate the message (e.g. first 128 chars) or emit only the code.

## [LOW] Unsigned arithmetic widths rely on 64-bit usize

- File: src/shader.rs:3835 (`descriptor_count * 6`), src/shader.rs:4095 (`use_count * 8`), src/shader.rs:4135 (`resource_count * 7`), src/shader.rs:4410-4413 (`start + size`)
- Description: Counts are u32 cast to usize; on 32-bit targets `u32::MAX * 8` wraps, so `checked_range` can pass and the subsequent `bytes[offset + k]` reads go out of bounds (panic). macOS is 64-bit so this is currently latent, but the module is exported publicly.
- Fix suggestion: Use `checked_mul`/`checked_add` (or saturating) when computing byte extents from untrusted counts.

---

## [PERF] ShaderCache insert is O(n²) and get/insert clone large payloads

- File: src/shader.rs:454-462 (eviction loop), src/shader.rs:438-443 (get), src/shader.rs:4011-4016 (build_cache_entry)
- Description: `insert` recomputes `total_size_bytes()` (a full O(n) sum over all entries) on every eviction iteration, so inserting into a cache that must evict k entries is O(n·k). `get` returns a `ShaderCacheEntry` by value, cloning the full payload (MSL library bytes, reflection JSON, pipeline archive — typically hundreds of KB to MB) even when the caller only needs a hit/miss check. `build_cache_entry` clones `mtl_library_bytes` once more. During a Steam-title load with hundreds of shaders this adds up to noticeable per-frame-during-load stalls.
- Fix suggestion: Track `total_bytes` as a field (add on insert, subtract on evict) so the while-loop is O(k); change `get` to return `Option<&ShaderCacheEntry>` (or take a `&mut` visitor); avoid the extra clone in `build_cache_entry` by moving `output.mtl_library_bytes`.

---

## Clippy

`cargo clippy --all-targets --no-deps` (CARGO_BUILD_JOBS=4) — warnings referencing src/shader.rs (none are errors; all style):

- `clippy::len_without_is_empty` — src/shader.rs:427 (public `len` on `ShaderCache`, no `is_empty`)
- `clippy::manual_clamp` — src/shader.rs:521 (`max_threads.max(1).min(4)` → `clamp(1, 4)`)
- `clippy::while_let_loop` — src/shader.rs:1202, 1267, 1384, 1401, 2987, 3085, 3356
- `clippy::unnecessary_map_or` — src/shader.rs:1290
- `clippy::if_same_then_else` — src/shader.rs:1562, 1564, 1566, 1572 (×2) — the identical udiv/sdiv/fdiv and urem/srem branches (see HIGH finding)
- `clippy::len_one` ("length comparison to one") — 41 occurrences at src/shader.rs:1539, 1606, 1614, 1622, 1631, 1633, 1641, 1651, 1670, 1695, 1709, 1854, 1975, 1984, 1993, 2005, 2208, 2215, 2222, 2274, 2281, 2288, 2298, 2312, 2319, 2326, 2333, 2340, 2347, 2354, 2361, 2368, 2435, 2449, 2456, 2463, 2470, 2480, 2490, 2605 (`args.len() >= 1` → `!args.is_empty()`)
- `clippy::useless_format` — src/shader.rs:3338 (`format!("_fn_0")`)
- `clippy::manual_range_patterns` ("OR pattern can be rewritten using a range") — src/shader.rs:1560, 3536
- `clippy::manual_div_ceil` / `clippy::manual_checked_div` — src/shader.rs:4453, 4456 (align_up can be `div_ceil` with checked ops)

## Build

`cargo clippy --all-targets --no-deps` **did not complete**: the crate failed to compile with 19 errors in `casa1` (lib) and 27 in `casa1` (lib test), **all in files outside scope** — src/jit.rs (7), src/d2d.rs (2), src/winhttp.rs (1), src/seh.rs (1), src/security.rs (1), src/video_decoder.rs (1), src/crash_recovery.rs (1), src/d3d11.rs (2) (deny-by-default lints: missing `unsafe` on raw-pointer-deref public fns, always-true comparisons, `set_len` after reserve, `PI`/`TAU` approximations, equal-expression logic bugs). 1415 warnings emitted overall; **no errors reference src/shader.rs**. shader.rs warnings are listed above. Because the build aborted, warnings from targets after the failure point may be incomplete; re-run clippy after fixing the out-of-scope errors to confirm.
