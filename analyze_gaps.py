#!/usr/bin/env python3
"""Analyze which gaps are still open in execution_plan.md G1-G12."""
import subprocess, os

os.chdir('/Users/sabelakhoua/IdeaProjects/Casa1')

def eg(pattern, file):
    r = subprocess.run(['grep', '-n', pattern, file], capture_output=True, text=True)
    return r.stdout.strip()

results = {}

# G1-G4: cpu.rs
print("=== G1-G4: cpu.rs ===")
r = eg('DecodedOpcode::(Fxsave|Fxrstor|Xsave|Xrstor|Hlt|Cli|Sti|PortIn|PortOut|Cmps|Scas|MovFromDr|MovToDr)', 'src/cpu.rs')
lines = [l for l in r.split('\n') if 'opcode: DecodedOpcode' in l]
print(f"  Decode arms: {len(lines)}")

r = eg('IrInstruction::(Fxsave|Fxrstor|Xsave|Xrstor|Hlt|Cli|Sti|PortIn|PortOut|Cmps|Scas|MovFromDr|MovToDr)', 'src/cpu.rs')
lines = [l for l in r.split('\n') if 'ir.push(IrInstruction' in l or 'IrInstruction::' in l]
print(f"  Translate/Execute arms: {len(lines)}")

r = eg('pub dr:', 'src/cpu.rs')
print(f"  dr field: {'YES' if r else 'NO'}")

r = eg('fxsr: true', 'src/cpu.rs')
print(f"  fxsr: {'YES' if r else 'NO'}")

r = eg('Halted', 'src/reason.rs')
print(f"  Halted in reason.rs: {'YES' if r else 'NO'}")

# G5: FastThunk in jit.rs
print("\n=== G5: FastThunk ===")
for pat in ['FastThunkTable', 'struct FastThunk', 'fn register_fast_thunk', 'fn allocate_thunk', 'emit_arm64']:
    r = eg(pat, 'src/jit.rs')
    if r:
        print(f"  {pat}: YES")
    else:
        print(f"  {pat}: MISSING")

# G6: Unwind in jit.rs
print("\n=== G6: JIT Unwind ===")
for pat in ['RuntimeFunction', 'UnwindInfo', 'UNW_FLAG', 'SehSubsystem']:
    r = eg(pat, 'src/jit.rs')
    if r:
        print(f"  {pat}: YES")
    else:
        print(f"  {pat}: MISSING")

# G7: WinVerifyTrust in pe_runtime.rs
print("\n=== G7: WinVerifyTrust ===")
r = eg('WinVerifyTrust =>', 'src/pe_runtime.rs')
print(f"  Dispatch match: {'YES' if r else 'NO'}")
if r: print(f"    -> {r}")

r = eg('verify_pe_authenticode', 'src/pe_runtime.rs')
print(f"  Calls verify_pe_authenticode: {'YES' if r else 'NO'}")
if r: print(f"    -> {r[:200]}")

# G8: Certificate pinning in network.rs
print("\n=== G8: Cert Pinning ===")
for pat in ['verify_certificate_pin', 'tls::', 'danger_accept_invalid_certs', 'add_root_certificate']:
    r = eg(pat, 'src/network.rs')
    if r:
        print(f"  {pat}: YES")
    else:
        print(f"  {pat}: MISSING")

# G9: IOSurface in cef_bridge.rs
print("\n=== G9: CEF IOSurface ===")
for pat in ['IOSurface', 'io_surface', 'create_texture_from_io_surface', 'MTLTexture']:
    r = eg(pat, 'src/cef_bridge.rs')
    if r:
        print(f"  {pat}: YES  ({r[:70]})")
    else:
        print(f"  {pat}: MISSING")

# G10: Video IOSurface in video_decoder.rs
print("\n=== G10: Video IOSurface ===")
for pat in ['CVMetalTextureCache', 'CVMetalTextureCacheCreateTextureFromImage', 'MTLTexture']:
    r = eg(pat, 'src/video_decoder.rs')
    if r:
        print(f"  {pat}: YES  ({r[:80]})")
    else:
        print(f"  {pat}: MISSING")

# G11: RenderPassPlan merge in gfx.rs
print("\n=== G11: RenderPassPlan ===")
r = eg('can_merge_with', 'src/gfx.rs')
print(f"  can_merge_with: {'YES' if r else 'NO'}")
r = eg('merge_store_action', 'src/gfx.rs')
print(f"  merge_store_action: {'YES' if r else 'NO'}")
r = eg('active_pass.*merge\|merge.*active_pass\|fn.*merge.*pass', 'src/d3d12.rs')
print(f"  merge wiring in d3d12.rs: {'YES' if r else 'NO'}")
if r:
    print(f"    -> {r[:100]}")

# G12: Async in metal_backend.rs
print("\n=== G12: Async Pipeline ===")
for pat in ['new_render_pipeline_state_async', 'completionHandler', 'AsyncPipeline', 'fallback.*shader']:
    r = eg(pat, 'src/metal_backend.rs')
    if r:
        print(f"  {pat}: YES  ({r[:80]})")
    else:
        print(f"  {pat}: MISSING")
