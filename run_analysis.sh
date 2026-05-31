#!/bin/bash
cd /Users/sabelakhoua/IdeaProjects/Casa1

echo "=== G5: FastThunk ==="
grep -n 'FastThunkTable\|fn register_fast_thunk\|fn allocate_thunk\|emit_arm64' src/jit.rs || echo "NOT FOUND"

echo ""
echo "=== G6: JIT Unwind ==="
grep -n 'RuntimeFunction\|UnwindInfo\|UNW_FLAG\|SehSubsystem' src/jit.rs || echo "NOT FOUND"

echo ""
echo "=== G7: WinVerifyTrust dispatch ==="
grep -n 'WinVerifyTrust =>' src/pe_runtime.rs | head -5

echo ""
echo "=== G8: Cert pinning ==="
grep -n 'verify_certificate_pin\|certificate_pins\|danger_accept' src/network.rs | head -10

echo ""
echo "=== G9: IOSurface CEF ==="
grep -n 'IOSurface\|create_texture_from_io_surface' src/cef_bridge.rs | head -10

echo ""
echo "=== G10: Video IOSurface ==="
grep -n 'CVMetalTextureCache\|CVMetalTextureCacheCreateTextureFromImage' src/video_decoder.rs | head -10

echo ""
echo "=== G11: RenderPassPlan merge wiring in d3d12 ==="
grep -n 'merge\|can_merge_with' src/d3d12.rs | head -10

echo ""
echo "=== G12: Async Pipeline ==="
grep -n 'new_render_pipeline_state_async\|completionHandler\|async.*compile\|PipelineCompiler' src/metal_backend.rs | head -10
