#!/usr/bin/env python3
"""
Replace brittle test assertions (assert!(result.is_ok()), assert!(result.is_err()))
with informative assertions that show actual values on failure.
"""

import re
import os

# Files to process
test_files = []
for root, dirs, files in os.walk('tests'):
    for f in files:
        if f.endswith('.rs'):
            test_files.append(os.path.join(root, f))

# Also process key src files that have test modules
src_files = [
    'src/user32.rs', 'src/pe_runtime.rs', 'src/network.rs', 'src/pe.rs',
    'src/threads.rs', 'src/app_bundle.rs', 'src/installer.rs', 'src/sandbox.rs',
    'src/winhttp.rs', 'src/wininet.rs', 'src/real_win32.rs', 'src/real_audio.rs',
    'src/real_net.rs', 'src/seh.rs', 'src/security.rs', 'src/crash_recovery.rs',
    'src/metal_backend.rs', 'src/metal_renderer.rs', 'src/jit.rs',
    'src/vkgl.rs', 'src/wsl.rs', 'src/cef_bridge.rs', 'src/media.rs',
    'src/video_decoder.rs', 'src/host_thunks.rs', 'src/wmi.rs', 'src/anticheat.rs',
    'src/shader.rs', 'src/steam_protocol.rs', 'src/perf.rs', 'src/real_fs.rs',
    'src/denuvo.rs', 'src/scm.rs', 'src/diagnostics.rs', 'src/steam_integration.rs',
    'src/trace.rs',
]

all_files = test_files + [f for f in src_files if os.path.exists(f)]

print(f"Processing {len(all_files)} files...")

total_replacements = 0

for filepath in all_files:
    with open(filepath, 'r') as f:
        content = f.read()
    original = content

    # Pattern 1: assert!(result.is_ok()) where result is a simple variable
    # Replace with: assert!(result.is_ok(), "expected Ok, got {result:?}")
    content = re.sub(
        r'assert!\((\w+)\.is_ok\(\)\)',
        r'assert!(\1.is_ok(), "expected Ok, got {\1:?}")',
        content
    )

    # Pattern 2: assert!(result.is_err()) where result is a simple variable
    content = re.sub(
        r'assert!\((\w+)\.is_err\(\)\)',
        r'assert!(\1.is_err(), "expected Err, got {\1:?}")',
        content
    )

    # Pattern 3: assert!(expr.is_ok()) for multiline expressions (common pattern in test files)
    # Replace with assertion showing the value
    # This uses a more complex regex for multiline cases
    content = re.sub(
        r'assert!\(([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\))\.is_ok\(\)\)',
        r'let _result = \1;\n    assert!(_result.is_ok(), "expected Ok, got {_result:?}")',
        content
    )

    # Pattern 4: assert!(expr.is_err()) for complex expressions
    content = re.sub(
        r'assert!\(([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\))\.is_err\(\)\)',
        r'let _result = \1;\n    assert!(_result.is_err(), "expected Err, got {_result:?}")',
        content
    )

    if content != original:
        count = content.count('\n') - original.count('\n')
        # Actually count replacements more carefully
        diff_lines = set(content.splitlines()) - set(original.splitlines())
        rel_count = len([l for l in diff_lines if 'assert!' in l or 'let _result' in l])
        total_replacements += max(1, rel_count)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  Fixed {filepath}")

print(f"\nTotal replacements made: ~{total_replacements}")
