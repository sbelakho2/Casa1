# Host Thunk Guide

This document describes how to add a new host thunk to Casa1. A "host thunk"
is a bridge function that allows guest (Windows x86/x64) code to call into the
host (macOS) implementation. The thunk translates calling conventions, marshals
arguments, and handles errors.

## Overview

Host thunks are defined as variants of the [`HostThunk`] enum in
[`src/pe_runtime.rs`](../src/pe_runtime.rs). Each thunk corresponds to a
Windows API function that Casa1 implements natively on the host side.

## Step-by-Step Guide

### Step 1: Define the Thunk Enum Variant

Add a new variant to the [`HostThunk`] enum in [`src/pe_runtime.rs`](../src/pe_runtime.rs):

```rust
pub enum HostThunk {
    // ... existing variants ...

    /// MyNewApiFunction — implements `MyNewApiFunction` from `myapi.dll`.
    /// Arguments: (param1: u32, param2: *mut u8) → u32
    MyNewApiFunction,
}
```

**Naming convention**: Use the exact Windows API function name in PascalCase.
Add a doc comment describing the function's signature and purpose.

### Step 2: Add a ReasonCode Variant

If the thunk can fail in a detectable way, add a corresponding
[`ReasonCode`](../src/reason.rs) variant:

```rust
// In src/reason.rs
pub enum ReasonCode {
    // ... existing variants ...

    /// MyNewApi-specific failure
    RcMyNewApiFailed = 2900,
}
```

**Guidelines for ReasonCodes**:
- Use the `Rc` prefix for recoverable errors
- Use the next available numeric range (check existing codes first)
- Group related codes together (e.g., network codes are 2700–2799)
- Add a doc comment explaining when this code is returned

### Step 3: Register the Thunk in the Dispatch Table

Add the thunk to the DLL export resolution table. Find the appropriate DLL
section in [`src/pe_runtime.rs`](../src/pe_runtime.rs) and add:

```rust
// In the DLL export resolution (e.g., for myapi.dll)
"MyNewApiFunction" => HostThunk::MyNewApiFunction,
```

Also specify the number of bytes the thunk expects on the stack (for x86
calling convention) in the `stack_cleanup_bytes()` method:

```rust
HostThunk::MyNewApiFunction => 8, // 2 × 4 bytes (param1 + param2)
```

### Step 4: Implement the Thunk Handler

Add a match arm in the main thunk dispatch block (the large `match` on
`HostThunk` variants):

```rust
HostThunk::MyNewApiFunction => {
    // Read arguments from guest registers (x64 calling convention)
    let param1 = state.get(Register::Rcx) as u32;
    let param2_ptr = state.get(Register::Rdx);

    // Validate pointer if applicable
    if param2_ptr != 0 {
        // SAFETY: param2_ptr was validated as non-null. The guest provided
        // this pointer and guarantees it points to a valid buffer of the
        // expected size.
        let value = memory.read_u8(param2_ptr)
            .map_err(|e| AppError::new(
                ReasonCode::RcMyNewApiFailed,
                &format!("failed to read param2: {e}"),
            ))?;

        // ... implement the actual logic ...
        state.set(Register::Rax, 1); // SUCCESS
    } else {
        // Null pointer — return error
        state.set(Register::Rax, 0); // FAILURE
    }
}
```

**Important conventions**:
- Use `state.get(Register::Rcx)`, `Rdx`, `R8`, `R9` for the first four
  arguments (x64 calling convention).
- Use `state.set(Register::Rax, ...)` for the return value.
- Use `memory.read_*()` / `memory.write_*()` for guest memory access.
- Always include `// SAFETY:` comments for any unsafe operations.

### Step 5: Add Unit Tests

Add unit tests in the same file (within a `#[cfg(test)]` module) or in the
appropriate test file under [`tests/`](../tests/):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_new_api_success() {
        let mut runtime = TestRuntime::new();
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        // Set up arguments
        state.set(Register::Rcx, 42); // param1
        let buf_addr = 0x1000;
        memory.map_bytes(buf_addr, &[0xAA]); // param2
        state.set(Register::Rdx, buf_addr);

        // Dispatch the thunk
        runtime.dispatch_thunk(HostThunk::MyNewApiFunction, &mut state, &mut memory)
            .expect("thunk should succeed");

        // Verify return value
        assert_eq!(state.get(Register::Rax), 1); // SUCCESS
    }

    #[test]
    fn test_my_new_api_null_pointer() {
        let mut runtime = TestRuntime::new();
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();

        state.set(Register::Rcx, 42);
        state.set(Register::Rdx, 0); // null pointer

        runtime.dispatch_thunk(HostThunk::MyNewApiFunction, &mut state, &mut memory)
            .expect("thunk should succeed");

        assert_eq!(state.get(Register::Rax), 0); // FAILURE
    }
}
```

### Step 6: Add Integration Tests

For guest-visible behavior, add integration tests that exercise the thunk
through the full PE loading and execution pipeline:

```rust
// In tests/section_myapi.rs
use casa1::*;

#[test]
fn test_guest_calls_my_new_api() {
    // Build a minimal PE that imports MyNewApiFunction from myapi.dll
    // Execute it through the PE runtime
    // Verify the guest receives the expected return value
}
```

## Argument Passing Conventions

### x64 Calling Convention (Windows)

| Argument | Register |
|----------|----------|
| 1st | `RCX` |
| 2nd | `RDX` |
| 3rd | `R8` |
| 4th | `R9` |
| 5th+ | Stack at `RSP + 0x28` (after shadow space) |
| Return | `RAX` |

### x86 Calling Convention (Win32 / stdcall)

| Argument | Location |
|----------|----------|
| All | Stack (`ESP + 4`, `ESP + 8`, ...) |
| Return | `EAX` |
| Stack cleanup | Callee (thunk must pop args) |

### Helper Functions

Use these helpers defined in [`src/pe_runtime.rs`](../src/pe_runtime.rs):

- `guest_call_arg_u32(state, memory, index)` — read the Nth argument (0-based)
  handling both x64 register and x86 stack conventions.
- `guest_call_arg_u64(state, memory, index)` — same for 64-bit arguments.
- `guest_call_arg_ptr(state, memory, index)` — same for pointer-sized arguments.

## Error Handling Patterns

### Pattern 1: Return Error Code in RAX

Most Windows APIs return `TRUE`/`FALSE` or `S_OK`/`E_FAIL`:

```rust
state.set(Register::Rax, 0); // FALSE / E_FAIL
state.set(Register::Rax, 1); // TRUE
state.set(Register::Rax, 0); // S_OK (HRESULT)
```

### Pattern 2: Set Last Error

Some functions require setting the thread's last error:

```rust
// Set ERROR_INVALID_PARAMETER
self.set_last_error(87);
state.set(Register::Rax, 0); // return FALSE
```

### Pattern 3: Return ReasonCode via AppError

For internal errors that should propagate to the host:

```rust
return Err(AppError::new(
    ReasonCode::RcMyNewApiFailed,
    "descriptive error message",
));
```

## Checklist for New Thunks

- [ ] `HostThunk` enum variant added with doc comment
- [ ] `ReasonCode` variant added (if the thunk can fail)
- [ ] DLL export resolution entry added
- [ ] `stack_cleanup_bytes()` updated for x86 calling convention
- [ ] Thunk handler implemented with `// SAFETY:` comments
- [ ] Unit test for success path
- [ ] Unit test for failure / error path
- [ ] Integration test for guest-visible behavior
- [ ] Doc comment on the enum variant describes argument types and return value
