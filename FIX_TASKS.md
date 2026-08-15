# AUDIT_FINDINGS.md

- **Batch**: Casa1 steam/VR/GE subsystem audit
- **Files**:
  - `src/ge.rs` (2756 lines)
  - `src/steamvr.rs` (1813 lines)
  - `src/steam_input.rs` (1437 lines)
- **Date**: 2026-08-15
- **Method**: Every line of all three files read in sequence; whole-crate `cargo clippy --all-targets --no-deps` run (see `## Clippy` / `## Build` sections); cross-file consumers of exposed APIs checked for context.

---

## [HIGH] Sandbox escape: host symlinks inside mapped drives bypass `ensure_within_allowed_roots`

- File: src/ge.rs:1620, src/ge.rs:1676, src/ge.rs:1715
- Description: `resolve_existing_path` walks components with `find_existing_child_case_insensitive` + `PathBuf::push` and never calls `fs::canonicalize`. The final `ensure_within_allowed_roots` check (and the one after a reparse redirect at line 1671) is purely lexical (`path.starts_with(root)`). A symlink anywhere inside a mapped drive (e.g. `drive_c/.../link -> /etc` or any outside dir) is followed transparently by every subsequent `fs::write`/`fs::read_dir`/`fs::metadata` operation, so reads/writes escape the GE sandbox. The shell layer even advertises symlinks as present (`SFGAO_LINK`, real_win32.rs:11865), so such links are a supported reality in the tree.
- Fix suggestion: canonicalize the final resolved path (`fs::canonicalize(&current_host)`) before the allowed-roots check in both `resolve_existing_path` (line 1676) and the reparse-redirect branch (line 1671), and require the canonicalized path to start with a canonicalized allowed root. Also reject `path.is_symlink()` components unless they resolve back inside an allowed root.

## [HIGH] FILETIME epoch wrong: GE ticks are 100 ns since 1970, guest-visible FILETIME requires 1601

- File: src/ge.rs:2218
- Description: `current_windows_ticks` computes `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos() / 100`, i.e. 100 ns units since 1970-01-01. Windows FILETIME is 100 ns since 1601-01-01. These ticks are stored in `fs_state.entries` and written directly into guest memory as FILETIME values (pe_runtime.rs:37250 `write_guest_pointer(..., creation_time_ticks, ...)`), so every GE-created file reports creation/access/write times ~11644473600 seconds (≈369 years) early to the guest. `get_file_metadata`/`set_file_times` round-trip the same wrong epoch, so the error is consistent within GE but wrong vs. real Windows.
- Fix suggestion: add the FILETIME-epoch offset when converting host time: `(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() / 100) + 116444736000000000`.

## [HIGH] `wait_get_poses` sets `tracking_result = 0` instead of `ETrackingResult_Running_OK` (200)

- File: src/steamvr.rs:1431, src/steamvr.rs:1434, src/steamvr.rs:1438
- Description: The module's own constant is `E_TRACKING_RESULT_RUNNING_OK = 200` (line 35) and `stationary_hmd()` uses it (line 310), but `wait_get_poses` overwrites `tracking_result` with `0` — a value that does not exist in the real `ETrackingResult` enum (1 = Uninitialized, 200 = Running_OK). Spec-compliant guests compare `pose.trackingResult == ETrackingResult_Running_OK` before trusting a pose, so every pose returned by the compositor looks untracked/uninitialized to them (e.g. Unity/UE VR runtimes drop to fallback or fail).
- Fix suggestion: use `E_TRACKING_RESULT_RUNNING_OK` (200) at lines 1431, 1434 and 1438 instead of the literal `0`.

## [HIGH] `ControllerState::to_bytes` does not match `VRControllerState_t` layout (axes shifted, types written into axis slots)

- File: src/steamvr.rs:163, src/steamvr.rs:175
- Description: Real `VRControllerState_t` is `{ u32 unPacketNum; u64 ulButtonPressed; u64 ulButtonTouched; VRControllerAxis_t rAxis[5]; }` with `VRControllerAxis_t { f32 x; f32 y; }` (60 bytes total; there is no axis-type array). `to_bytes` emits the 20-byte header, then `r_axis` as **5 floats**, then `ul_axis_type` as 5 u32s. The guest interprets bytes 20..60 as 10 floats: axis0=(lx,ly) is correct, but axis1.x = trigger, axis1.y = type[0] (0), axis2 = (0,0), axis3 = (type[2]=2 as denormal float, 0), axis4 = (0,0). The trigger value lands in axis1 (trackpad slot) and the guest-visible axis-type information is garbage, so games cannot locate the trigger axis at all.
- Fix suggestion: emit 10 floats per the real layout — for each of the 5 axes write `(x, y)`; either drop `ul_axis_type` from the serialized form or encode it elsewhere (the real struct has no type array).

## [HIGH] `get_digital_action_data` / `get_analog_action_data` write guest buffers with wrong field order

- File: src/steamvr.rs:995, src/steamvr.rs:1043
- Description: Real `InputDigitalActionData_t` is `{ bool bState; bool bActive; VRInputOrigin_t activeOrigin(u64); u32 updateTime; }` (20 bytes) — `bState` first. The code writes `active` at offset 0 and `pressed` at offset 4, i.e. **bState/bActive swapped**: guests see "active" as the pressed state and vice versa. Real `InputAnalogActionData_t` is `{ f32 x,y,z; f32 deltaX..deltaZ; bool bActive; VRInputOrigin_t activeOrigin; u32 updateTime; }` (40 bytes) — the code writes `active` at offset 0 (where `x` belongs), shifting every analog field: guest reads x = active(0/1), y = 0, z = joystick-x, deltaX = joystick-y, etc. Analog action data is effectively garbage for the guest.
- Fix suggestion: write digital as `pressed` at 0..4, `active` at 4..8, origin at 8..16, time at 16..20; write analog as x,y,z at 0..12, deltas at 12..24, active at 24..28, origin at 28..36, time at 36..40.

## [MEDIUM] `get_prop_string` violates the OpenVR size contract: truncated copy without null terminator, returns bytes written instead of required size

- File: src/steamvr.rs:1099
- Description: When `buffer_len`/`buffer` is smaller than the encoded string, the code copies `max_chars` UTF-16 units (no null terminator, since the terminator is cut off) and returns `max_chars*2`. Real OpenVR returns the **required** size including the terminator so the caller retries; here the guest believes it has the full string, reads past the end of the written data (missing terminator) and never retries. Also the return value doubles as "property found" (0 = not found), so a truncated write is indistinguishable from a missing property.
- Fix suggestion: always return `encoded.len() * 2` as the required size; copy `min(encoded.len(), buffer_len/2)` units including the terminator when it fits.

## [MEDIUM] `VREvent` (and the data union) is smaller than the real `VREvent_t`

- File: src/steamvr.rs:503
- Description: The struct claims to "match `vr::VREvent_t` layout" but models the event payload as `data: [u8; 40]` (total 52 bytes). The real `VREvent_Data_t` union is larger (≥ 32 bytes for `VREvent_Reserved_t`; the union in current SDKs is 64 bytes, making `VREvent_t` ~80 bytes with padding). Any dispatch code that copies this struct (or an array of them) into guest memory will misplace subsequent data and leave the guest's union fields (e.g. `data.controller.button`) at offsets that don't match what the emulator wrote — the button mask is written at `data[..8]` which is only the low 32 bits the guest will read as `VREvent_Controller_t.button`, so multi-button masks are lost.
- Fix suggestion: model the union at the real size (64 bytes, `#[repr(C)]` with alignment 8) and verify the serialized size against the guest ABI (sizeof(VREvent_t) in the targeted SDK version); ideally write `data` as a typed `VREvent_Controller_t { u32 button }` union member.

## [MEDIUM] `CompositorFrameTiming` / `CompositorCumulativeStats` do not match the real OpenVR structs

- File: src/steamvr.rs:389, src/steamvr.rs:454
- Description: Both structs claim to match OpenVR layouts, but the real `Compositor_FrameTiming` is a sequence of `m_n...`/`m_fl...` timing counters/doubles and the real `Compositor_CumulativeStats` is a small set of frame counters — neither has the fields used here (`num_frames_cpu/gpu/early/idle`, `total_milliseconds`, `[f32; 8]` per-frame arrays, `_padding: [u8; 20]`). Guests reading these buffers as OpenVR structs will misparse every field.
- Fix suggestion: mirror the exact `Compositor_FrameTiming` and `Compositor_CumulativeStats` definitions from the targeted openvr.h (field names, types, order, `m_nSize` first) and `repr(C)` them.

## [MEDIUM] `controller_fn_tables` stack-cleanup values don't match the declared x86 stdcall signatures

- File: src/steamvr.rs:1773
- Description: The table documents `(thunk, stack_cleanup_bytes)` for x86 stdcall, but the values don't match the real `IVRController_002`/`IVRInput_003` signatures: `Release` (no args) is listed as 4, `TriggerHapticPulse(device, axis, u16 duration)` should clean up 12 (4+4+2→12) but is listed as 16, `GetControllerState(device, ptr)` should be 8 but is listed as 12, and slot 8 of the IVRInput table duplicates `GetActionSetHandle` with cleanup 12 (real slot 8 is `GetDigitalActionData`). The function is currently unused (dead code), but if the dispatch layer adopts these values for x86 guests, every call through the table corrupts the stack.
- Fix suggestion: derive cleanup sizes from the real signatures (`GetControllerState`/`GetControllerStateForNextFrame` = 8, `TriggerHapticPulse` = 12, `Release` = 4 — verify against openvr.h; the real IVRInput_003 slot 8 is `GetDigitalActionData`), or remove the unused table.

## [MEDIUM] Read-only drive mappings are not enforced on any write path

- File: src/ge.rs:816, src/ge.rs:836, src/ge.rs:856, src/ge.rs:1043
- Description: `DriveMapping.read_only` is only consulted to exclude drives from `snapshot_files` and to filter `active_drive_mappings`. `create_directory`, `write_file`, `write_file_overwrite` and `open_file` (with write/delete access) never check it, so a guest can modify a drive the config declares read-only (the shipped default `Z:` mapping is read-only; user-added read-only mappings are also silently writable). Same for `requires_permission`, which is never checked anywhere.
- Fix suggestion: in `resolve_drive_mapping` callers, reject write/delete requests against `mapping.read_only` (and gate `requires_permission` mappings on an explicit grant) — e.g. return `RcFsAccessDenied` from `open_file`/`write_file`/`create_directory` when the mapping is read-only and the operation requests write or delete.

## [MEDIUM] Registry watchers on `HKCR` never fire

- File: src/ge.rs:1344, src/ge.rs:1844
- Description: `registry_watch` for `HKCR` registers a watcher with hive `"HKCR"` (line 1807 path returns `(normalized_hive, normalized_key)` for `allow_hkcr_write=false`), but every HKCR write is redirected to hive `HKCU` key `Software\Classes\...` (line 1800-1806) and `notify_registry_watchers(&actual_hive, &actual_key)` (line 1159) compares `watcher.hive != hive` (line 1852) — `"HKCR" != "HKCU"` — so the watcher is never woken. Reads of HKCR are also merged from two hives, so a single-hive watcher cannot represent them anyway.
- Fix suggestion: special-case HKCR in `registry_watch` (subscribe to both merged sources — HKCU\Software\Classes and the HKLM branch) or have `notify_registry_watchers` expand HKCR writes into notifications for any HKCR watcher whose key is a suffix of `Software\Classes\...`.

## [MEDIUM] WOW6432 redirection condition inverted: `RegistryView::Native` should redirect for 32-bit guests

- File: src/ge.rs:1810
- Description: On real Windows, a 32-bit process accessing `HKLM\Software` **without** a WOW64 view flag is redirected to `Software\WOW6432Node`. Here redirection only happens when `view == RegistryView::Wow6432`; `Native` (the no-flag default, and the view used by `apply_overrides_for_program`) produces no redirection for an x86 GE. The same inverted logic leaks into `hkcr_merged_keys` (line 1835), so x86 guests read the 64-bit HKLM branch of `Software\Classes`. Any x86 game relying on `HKLM\Software\...` (virtually all 32-bit installers) will miss values real Windows would redirect.
- Fix suggestion: redirect when `arch == X86 && view != RegistryView::Native64` (i.e. Native and Wow6432 both redirect); keep the `Software\Classes` exclusion.

## [MEDIUM] `fs_state.entries` grows unboundedly and stale entries survive deletion; snapshot time bases are inconsistent

- File: src/ge.rs:1765, src/ge.rs:743, src/ge.rs:1532
- Description: (a) Every guest-visible create/rename leaves a `FsMetadataRecord` in `fs_state.entries`; nothing ever removes entries for deleted/renamed files, so the persisted config grows without bound and deleted-then-recreated paths keep stale attrs/times. (b) In `snapshot_files`, tracked files get `record.ticks / 10_000` (ms since **1970**) while untracked files get `util::elapsed_offset_ms(epoch, ...)` (ms since an arbitrary caller-supplied `epoch`); when `epoch` isn't 1970 (the stated purpose of the parameter), mixed trees produce spurious `modify` deltas purely from the different time bases.
- Fix suggestion: (a) prune `fs_state.entries` whose host path no longer exists (or on delete); (b) normalize both branches to the same reference — convert record ticks to ms-since-`epoch`, or always use UNIX_EPOCH as the snapshot base.

## [PERF] Every guest file operation rewrites the entire config + reparse DB (two JSON files)

- File: src/ge.rs:556, src/ge.rs:1532
- Description: `create_directory`, `write_file`, `write_file_overwrite`, `set_file_attributes`, `set_file_times`, `create_reparse_point` and `upsert_fs_entry` all end in `save_config()` → `write_config()`, which serializes the whole `GeConfig` (including the unbounded `fs_state.entries`) via `stable_json` and writes `ge.json` **and** the reparse DB file. Games that create files per-frame (logs, caches, save games) turn a small O(1) syscall into an O(n) serialize + 2 file writes per operation — O(n²) over a session as `fs_state` grows, plus write amplification on the host disk.
- Fix suggestion: batch/dirty-flag config persistence (save at frame boundaries or on a timer), or store `fs_state` as an append-only/sidecar log; at minimum skip the reparse-DB write when it hasn't changed.

## [MEDIUM] `is_action_active` returns true for every registered action regardless of action-set membership

- File: src/steam_input.rs:923
- Description: When any action set is active for a controller, `is_action_active` returns `digital_actions.contains_key(name) || analog_actions.contains_key(name)` — i.e. whether the action was ever registered anywhere, not whether it belongs to the currently active set. There is no action-set membership tracking (handles are registered globally and `activate_action_set` only records a handle). Games that switch action sets (menus vs. gameplay) see all actions of all sets "active" simultaneously.
- Fix suggestion: record the owning action-set handle at registration time and compare against the controller's current set/layers; without that, keep the current permissive behavior but document it as such.

## [MEDIUM] Disconnected controllers keep their last input forever (stuck inputs); `last_raw_state` never pruned

- File: src/steam_input.rs:526, src/steam_input.rs:456
- Description: `run_frame` only inserts/updates entries; nothing removes them, and `get_connected_controllers` always reports all 4 slots as connected. If a controller stops being polled (disconnect, battery, removal), `get_digital_action_data`/`get_analog_action_data` keep returning the last snapshot — a held button stays pressed indefinitely. The map is also keyed by arbitrary guest-supplied `ControllerHandle`s, so a misbehaving caller can grow it without bound.
- Fix suggestion: track staleness per handle (timestamp per entry) and drop entries not refreshed for N frames; cap the map to the 4 known slot handles.

## [MEDIUM] `send_rumble_via_iokit` sends the output report to the first HID device with any VID/PID, not the intended controller

- File: src/steam_input.rs:1325
- Description: The iteration accepts *any* IOService that has `VendorID`/`ProductID` properties ("We accept *any* HID device..."), so the rumble report is delivered to the first enumerated device (often a keyboard or trackpad), regardless of the XInput slot or the actual controller. The dedicated `find_hid_device(vendor_id, product_id)` helper that would match correctly is dead code and returns a fake `1 as *mut c_void` sentinel pointer ("FIXME: Return a real IOHIDDeviceRef", line 269). Multi-controller setups always rumble the same (wrong) device.
- Fix suggestion: wire the slot's VID/PID (from the raw gamepad source) into the IOKit scan, or delete `find_hid_device` and pass the matched `IORegistryEntryID` from the polling path; at minimum require `IOHIDDevice` class plus a VID/PID filter for the specific controller.

## [PERF/MEDIUM] Every haptic pulse blocks the calling thread on a synchronous `osascript` spawn

- File: src/steam_input.rs:1084
- Description: `notify_software_haptic` runs `std::process::Command::new("osascript").output()` synchronously for every rumble with `duration_ms >= 100 && intensity > 32`, and the macOS fallback path (`send_hid_rumble` → no device found → `notify_software_haptic`) triggers it for **every** rumble call. Games firing repeated pulses (weapons, racing) stall the calling thread (typically the game/emulator thread) ~50–150 ms per pulse, and each call forks a process.
- Fix suggestion: rate-limit notifications (min interval, e.g. 250 ms) and spawn asynchronously (`spawn`), or replace osascript with a once-per-slot state change only.

## [MEDIUM] `trigger_repeated_haptic_pulse`/HID report format won't rumble real Xbox controllers

- File: src/steam_input.rs:687, src/steam_input.rs:1140
- Description: The output report `[0x00, left, right]` is not a valid Xbox 360/One/PS4 rumble report (Xbox 360 uses report ID 0x00 with a specific 8-byte payload; Xbox One uses a different VID/PID-specific report), and the "intensity" derivation (`pulse_count.min(100) * duration_ms.min(5000)`, then `>> 8`) is arbitrary — real Steam Input `TriggerRepeatedHapticPulse` semantics (count/interval/duration) are not reflected. Result: on real hardware rumble is silent; only the software notification path produces any feedback.
- Fix suggestion: either implement per-vendor rumble reports (report ID 0x00, packet 0x00, big/small motor bytes for X360) with the actual motor intensities, or document the software-only fallback and skip the IOKit path entirely.

## [MEDIUM] `is_tracked_device_connected`/`get_tracked_device_class` contradict `poll_next_event` device indices; controllers reported connected even when `hmd_enabled` is false

- File: src/steamvr.rs:1075, src/steamvr.rs:1086
- Description: `is_tracked_device_connected` (and class) return `true` for devices 1/2 as soon as `initialized` is true — even after `shutdown()` sets `hmd_enabled = false` (only `initialized` is checked, and `shutdown` clears it too — OK — but there is no path where controllers are reported disconnected). Combined with `get_controller_state` returning defaults and events never delivered when Steam Input is inactive, games can't distinguish "controller present but idle" from "connected and usable". Minor spec deviation; primary risk is games assuming poses/state are live.
- Fix suggestion: gate device presence on `hmd_enabled` and report `TRACKED_DEVICE_CLASS_INVALID`/disconnected when the HMD is disabled.

## [LOW] `poll_next_event` pops LIFO — event order reversed

- File: src/steamvr.rs:1306
- Description: `pending_events.pop()` dequeues newest-first. `enqueue_button_events` pushes press-then-release per device; multiple buttons changed in one `update_controllers_from_steam_input` push several events that the guest receives in reverse order. Real OpenVR is FIFO.
- Fix suggestion: drain with `remove(0)`/`VecDeque::pop_front`, or reverse the push order.

## [LOW] `get_prop_string` semantics — also note `PROP_FIRMWARE_VERSION`/`PROP_HARDWARE_REVISION` collide with real property IDs

- File: src/steamvr.rs:600, src/steamvr.rs:138, src/steamvr.rs:215
- Description: `PROP_FIRMWARE_VERSION = 1054` duplicates `PROP_FIRMWARE_UPDATE_AVAILABLE` (1054) and `PROP_HARDWARE_REVISION = 1055` duplicates `PROP_FIRMWARE_MANUAL_UPDATE` (1055); real OpenVR has no `Prop_FirmwareVersion`/`Prop_HardwareRevision` — guests asking `Prop_Firmware_UpdateAvailable` via `GetInt32TrackedDeviceProperty` get `1` while `GetBoolTrackedDeviceProperty` returns `false` for the same ID. Additionally `BUTTON_TOUCHPAD = 0x100` is the real `k_eButton_ProximitySensor` value; the real SteamVR touchpad button mask is `0x1000` (`k_eButton_SteamVR_Touchpad`), so games reading touchpad presses never see them (stick clicks map to the wrong bit).
- Fix suggestion: drop the invented constants or move them to unused IDs; map stick clicks to `0x1000`.

## [LOW] Dead code / latent issues in steamvr.rs

- File: src/steamvr.rs:899, src/steamvr.rs:1517, src/steamvr.rs:1397
- Description: (a) `set_action_manifest_path` ignores the path and returns 0 ("Already loaded") without ever parsing the guest manifest — subsequent `get_action_handle` for actions outside the 10 built-ins return 0. (b) `load_render_model_async` stores data that `load_render_model` never uses (it regenerates the mesh each call), and both `load_render_model`/`wait_get_poses`/`to_bytes` allocate Vecs per call — per-frame allocations in the compositor path (`wait_get_poses` clones two 16-pose arrays, lines 1442-1443). (c) controller pose velocity estimation (lines 1397-1427) is dead: `left_controller`/`right_controller` poses are never updated after `new()`, so velocity is always ~0.
- Fix suggestion: cache the generated mesh in `load_render_model`; use the async-loaded buffer; copy poses without allocation; either add a real pose-update path or remove the dead velocity math.

## [LOW] `event_age_seconds` reported as elapsed-since-last-frame instead of ~0

- File: src/steamvr.rs:871, src/steamvr.rs:881
- Description: Fresh events are reported with `event_age_seconds = last_frame_time.elapsed()` (typically 0–16 ms, fine) — but if the game doesn't poll for a while, the *next* batch of events reports the accumulated age, which real OpenVR defines as seconds since the event occurred (≈0). Cosmetic for most games.
- Fix suggestion: use 0.0 (or the age at enqueue time, tracked explicitly).

## [LOW] ge.rs edge cases

- File: src/ge.rs:2110, src/ge.rs:990, src/ge.rs:1254, src/ge.rs:908, src/ge.rs:2508
- Description:
  - 260-char limit off-by-one: `MAX_PATH = 260` includes the terminating null, so a 260-char path must be rejected; `> 260` accepts it.
  - `get_file_metadata` returns `RcFsNotFound` for files that exist on host but aren't in `fs_state` (e.g. pre-existing GE content) — inconsistent with the rest of the FS layer which works off host paths.
  - `registry_delete_value` succeeds silently when the value doesn't exist (Windows returns ERROR_FILE_NOT_FOUND).
  - `enumerate_directory` swallows per-entry errors via `filter_map(Result::ok)`.
  - `ranges_overlap` treats length-0 ranges as never overlapping; on Windows a zero-length lock means "to end of file".
  - `snapshot_files` aborts the whole snapshot with `RcIo` if a file disappears between walk and stat.
- Fix suggestion: use `>= 260`; fall back to host metadata (or synthesize a record) in `get_file_metadata`; return `RcRegistryNotFound` when the value is absent; propagate entry errors; treat `length == 0` as EOF-range; skip vanished entries.

## [LOW] steam_input.rs edge cases

- File: src/steam_input.rs:777, src/steam_input.rs:415, src/steam_input.rs:536, src/steam_input.rs:886, src/steam_input.rs:1163
- Description: (a) `get_glyph_for_action_handle` looks the handle up in `action_sets` (action-**set** handles) though its parameter and name say action handle — glyphs never resolve for real digital/analog handles. (b) `SteamInputController.active_action_set` is never read. (c) `get_connected_controllers` always returns all 4 slots as connected regardless of hardware. (d) `push_action_set_layer` stacks grow without bound if the game never pops. (e) `send_hid_rumble_ext` double-notifies (calls `send_hid_rumble` which may notify, then calls `notify_software_haptic` again). (f) `find_hid_device` (lines 151-279) is dead code that parses `ioreg` output and returns a dangling sentinel pointer `1 as *mut c_void` documented as a "retained IOHIDDeviceRef" — if ever called, its result is a fake pointer.
- Fix suggestion: look up digital/analog maps in (a); remove dead field/function; reflect real connection state in (c); cap layer stacks; dedupe notification in (e).

## [LOW] No reachable panics from untrusted input in scope

- File: src/ge.rs, src/steamvr.rs, src/steam_input.rs
- Description: All slice indexing (`raw[0..1]`, `raw[2..]`, `components[..len-1]`, `components[..=index]`, buffer copies) is guarded by prior ASCII/length checks; `.expect()` appears only on poisoned mutex locks; untrusted config/manifest JSON parsing routes through `AppError` without `unwrap`. `wildcard_match` (ge.rs:2465) is O(n·m) with an allocation per call, but only with config-controlled patterns (bounded). FFI calls (kill/flock/IOKit) are null-checked and released on all paths; `IOHIDDeviceSetReport` is called with a non-null device. No unsafe misuse, no Send/Sync violations, no static mut found. Noted as verification, not a finding.

---

## Clippy

Clippy warnings referencing the three audited files (full output in `clippy_out.txt`):

`src/ge.rs`:
- ge.rs:428 `if_same_then_else` — identical `Ok(false)` branches in `wait_for_change` (also a real readability/spec smell; see findings)
- ge.rs:1024 `collapsible_if`
- ge.rs:1173 `collapsible_if`
- ge.rs:1738 `suspicious_open_options` — `OpenOptions::create(true)` without `truncate` (lock file; content unused, but add `.truncate(false)` to silence)
- ge.rs:2320 `if_same_then_else` — identical `target` branches in `build_reparse_redirect`
- ge.rs:2397, ge.rs:2402, ge.rs:2403 `collapsible_if` (×3 in `enumerate_subkeys`)

`src/steamvr.rs`:
- steamvr.rs:536 `derivable_impls` (VRTrackingState)
- steamvr.rs:562 `derivable_impls` (VRCompositorState)
- steamvr.rs:773 `too_many_arguments` (9/7)
- steamvr.rs:878, 879, 887, 888 `field_reassign_with_default` (VREvent construction)
- steamvr.rs:1087 `if_same_then_else`; steamvr.rs:1089 `needless_bool`
- steamvr.rs:1293, 1295, 1297, 1398, 1414, 1442, 1443, 1488 `clone_on_copy` (×8)
- steamvr.rs:1773 `type_complexity`

`src/steam_input.rs`:
- steam_input.rs:26 (and :25) `duplicated_attributes` — `#[link(...)]` `kind = "framework"` repeated on adjacent attributes
- steam_input.rs:272 `manual_dangling_ptr` — `1 as *mut c_void` sentinel in `find_hid_device` (ties into dead-code finding)
- steam_input.rs:470 `unnecessary_cast` (`i as i32`)
- steam_input.rs:498 `manual_range_contains`
- steam_input.rs:701 `manual_clamp` + `unnecessary_cast`
- steam_input.rs:1171 `collapsible_if`

(All are `warn` level; the crate has 1415 warnings / 1262 duplicates overall.)

## Build

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` **failed to compile**: 19 errors in `casa1` (lib), 27 in `casa1` (lib test) — all located in files outside the audit scope (d2d.rs:974 `erasing_op`, seh.rs:1978 `erasing_op`, dwrite.rs:1398 logic-bug assert, pe_runtime.rs/network.rs/ws2_32-related `not_unsafe_ptr_arg_deref`, `vec`-related `uninit_vec` in pe_runtime.rs, `identity_op`/`approx_constant` errors in several files). Because compilation aborted, clippy could not lint every downstream file, but the three audited files were linted and their warnings are listed above. No errors reference ge.rs/steamvr.rs/steam_input.rs. (`--all-features` not used; system ffmpeg absence is environmental and out of scope.)
