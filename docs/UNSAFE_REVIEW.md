# Unsafe Code Review

This document describes the rules and conventions for writing and reviewing
`unsafe` code in Casa1. Because Casa1 is a systems-level compatibility layer
that directly manipulates memory, CPU state, and hardware APIs, `unsafe` code
is unavoidable — but it must be written and reviewed with extreme care.

## Guiding Principles

1. **Minimize unsafe surface area** — use safe abstractions wherever possible.
2. **Document every invariant** — every `unsafe` block must have a `// SAFETY:`
   comment explaining why the operation is sound.
3. **Review before merge** — all new `unsafe` code requires review by at least
   one team member familiar with the relevant subsystem.

## Rule 1: SAFETY Comments

Every `unsafe` block must be preceded by a `// SAFETY:` comment:

```rust
// SAFETY: `ptr` was obtained from `alloc_zeroed` with layout for 8 bytes
// aligned to 8. The allocation has not been freed. We only write within
// the allocated bounds.
unsafe {
    std::ptr::write_unaligned(ptr as *mut u64, value);
}
```

**What the SAFETY comment must address**:
- Where did the pointer come from?
- Why is it valid (aligned, non-null, within bounds)?
- Why is the lifetime correct (no use-after-free)?
- Why is there no data race (thread safety)?

### Examples of Good SAFETY Comments

```rust
// SAFETY: The guest memory image guarantees that `addr` is within the
// mapped guest address space. The MemoryImage::read_u32 method performs
// bounds checking internally. We hold no mutable references to the memory
// image at this point.
let value = unsafe { memory.read_u32(addr)? };
```

```rust
// SAFETY: MAP_JIT memory is thread-local on Apple Silicon. We have called
// pthread_jit_write_protect_np(false) before this block and will call
// pthread_jit_write_protect_np(true) after. No other thread can access
// this memory region because it is freshly allocated and not yet registered
// with the thunk table.
unsafe {
    std::ptr::copy_nonoverlapping(code.as_ptr(), buf.as_mut_ptr(), code.len());
}
```

### Examples of Bad SAFETY Comments

```rust
// SAFETY: it's fine
unsafe { ... }

// SAFETY: we know this is valid
unsafe { ... }
```

## Rule 2: Pointer Validity

All pointer dereferences must be validated:

| Check | When Required |
|-------|--------------|
| Non-null | Before any dereference |
| Alignment | Before `read`/`write` with alignment requirements |
| Bounds | Before accessing array/buffer elements |
| Lifetime | Ensure the pointee outlives the reference |

```rust
// GOOD: Validate before use
if ptr.is_null() {
    return Err(AppError::new(ReasonCode::RcWin32InvalidHandle, "null pointer"));
}
// SAFETY: ptr was validated as non-null above. The caller guarantees it
// points to a valid buffer of at least `size` bytes.
let slice = unsafe { std::slice::from_raw_parts(ptr, size) };
```

## Rule 3: Lifetime Management

Raw pointers must not outlive the data they reference:

```rust
// BAD: dangling pointer
fn get_str(&self) -> *const u8 {
    let s = format!("hello");
    s.as_ptr() // s is dropped here, pointer is dangling
}

// GOOD: return owned data
fn get_str(&self) -> Vec<u8> {
    format!("hello").into_bytes()
}
```

When storing raw pointers in structs (e.g., for FFI or JIT), document the
ownership invariant:

```rust
/// Raw pointer to the JIT code buffer.
/// Owned by `JitRuntime`. Valid as long as `JitRuntime` is alive.
code_ptr: *mut u8,
```

## Rule 4: Thread Safety

Shared mutable state accessed from multiple threads must use proper
synchronization:

```rust
// GOOD: atomic operations for signal-safe global state
static SIGBUS_JIT_RUNTIME: AtomicPtr<JitRuntime> = AtomicPtr::new(std::ptr::null_mut());

// SAFETY: AtomicPtr provides atomic load/store. The pointer is only set
// before JIT execution begins and cleared after it ends. The JIT execution
// is single-threaded per guest process.
let runtime = SIGBUS_JIT_RUNTIME.load(Ordering::Acquire);
```

**Rules for concurrent unsafe code**:
- Use `AtomicPtr`, `AtomicUsize`, etc. for lock-free shared state
- Use `Mutex` or `RwLock` for complex shared data
- Never call non-async-signal-safe functions from signal handlers
- Document the synchronization strategy in comments

## Rule 5: JIT Code and W^X Compliance

JIT-compiled code must follow Apple's W^X (Write XOR Execute) rules:

1. **Allocate with `MAP_JIT`** — use `mmap` with the `MAP_JIT` flag:
   ```rust
   // SAFETY: MAP_JIT is supported on Apple Silicon (macOS 11+).
   // The kernel enforces W^X: the page is either writable or executable,
   // never both at the same time.
   let ptr = unsafe {
       libc::mmap(
           std::ptr::null_mut(),
           size,
           libc::PROT_READ | libc::PROT_WRITE,
           libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
           -1,
           0,
       )
   };
   ```

2. **Toggle write protection** — use `pthread_jit_write_protect_np`:
   ```rust
   // Before writing JIT code:
   unsafe { libc::pthread_jit_write_protect_np(0) }; // Enable writes

   // ... write machine code ...

   // After writing, before execution:
   unsafe { libc::pthread_jit_write_protect_np(1) }; // Enable execution
   ```

3. **Never have both write and execute permissions simultaneously**

See [`src/jit.rs`](../src/jit.rs) for the full JIT memory management
implementation.

## Rule 6: FFI Calls

All FFI (Foreign Function Interface) calls must document:

1. **The caller's responsibilities** — what must be true before the call
2. **The callee's guarantees** — what the function returns and when it can fail
3. **Memory ownership** — who allocates, who frees

```rust
// SAFETY: `self.device` is a valid Metal device obtained from
// MTLCreateSystemDefaultDevice(). The `new_buffer_with_data` selector
// expects: (data_ptr, length, options). `data.as_ptr()` is valid for
// `data.len()` bytes. `MTLResourceStorageModeShared` is the correct
// storage mode for CPU-accessible buffers on Apple Silicon.
let buffer = unsafe {
    let () = msg_send![self.device, newBufferWithBytes:data.as_ptr()
                                              length:data.len()
                                             options:MTLResourceStorageModeShared];
};
```

## Rule 7: Signal Handlers

Signal handlers (e.g., SIGBUS for JIT page faults) must be **async-signal-safe**:

**Allowed in signal handlers**:
- Atomic operations (`AtomicPtr::load`, `AtomicUsize::store`)
- Writing to pre-allocated buffers
- `sigaction`, `raise`, `_exit`
- Simple arithmetic

**NOT allowed in signal handlers**:
- Memory allocation (`malloc`, `Box::new`)
- Mutex locking (potential deadlock)
- Printing / logging (not async-signal-safe)
- Any function that may call `malloc` internally

```rust
// GOOD: signal handler using only atomics
extern "C" fn sigbus_handler(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: AtomicU64::load is async-signal-safe. We only read the fault
    // address from siginfo and update atomic counters.
    let fault_addr = unsafe { (*info).si_addr as u64 };
    SIGBUS_TOTAL_EVENTS.fetch_add(1, Ordering::Relaxed);
    // ... handle page fault using only atomic operations ...
}
```

## Review Checklist

When reviewing PRs that contain `unsafe` code, verify:

- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] Pointer validity is documented (non-null, aligned, in-bounds)
- [ ] Lifetime invariants are stated
- [ ] Thread safety is analyzed (data races, synchronization)
- [ ] JIT code follows W^X rules (MAP_JIT, write protection toggle)
- [ ] FFI calls document caller responsibilities
- [ ] Signal handlers are async-signal-safe
- [ ] No undefined behaviour under any code path
- [ ] Error paths clean up resources (no leaks)
- [ ] Test coverage for both success and failure paths

## Automated Enforcement

The project includes a Python script ([`add_safety_comments.py`](../add_safety_comments.py))
that can identify `unsafe` blocks missing `// SAFETY:` comments. Run it as
part of the review process:

```bash
python3 add_safety_comments.py --check src/
```

This script will flag any `unsafe` blocks that lack proper SAFETY comments.
