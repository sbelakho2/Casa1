//! Native ARM64 reference lane for the Casa1 performance harness.
//!
//! Runs four deterministic workloads twice in one process:
//!
//! * `native` — plain Rust on the host CPU.
//! * `casa1` — the same workload through Casa1's public guest execution path
//!   (`execute_ir` for straight-line work, `WorkerSliceBenchmark` for
//!   call/return and indirect-call chains).
//!
//! The emitted JSON lets `ci/check_perf.py` compute
//! `casa1_time / native_time` per workload.  A side that cannot run (non-ARM64
//! host, JIT unavailable) is `available: false` with an exact reason and the
//! ratio is refused; nothing is fabricated.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every method forwards to `System`, which upholds GlobalAlloc's
// contract; the atomics only observe successful allocations.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded to the system allocator with the same layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded to the system allocator with the same pointer/layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded to the system allocator with the same arguments.
        let resized = unsafe { System.realloc(pointer, layout, new_size) };
        if !resized.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        resized
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const INTEGER_ITERATIONS: u64 = 100_000;
const MEMORY_BYTES: usize = 64 * 1024;
const CALL_BLOCKS: u64 = 4096;
const CALL_BUDGET: u64 = 512;
const NATIVE_LOAD_BIAS: u64 = 0x1000;
const NATIVE_DEST_BIAS: u64 = 0x2_0000;

struct SideMeasurement {
    wall_ns: u64,
    cpu_ns: u64,
    allocations: u64,
    checksum: u64,
}

fn measure<F>(work: F) -> Result<SideMeasurement, String>
where
    F: FnOnce() -> Result<u64, String>,
{
    let allocations_before = ALLOCATIONS.load(Ordering::Relaxed);
    let cpu_before = casa1::perf::process_cpu_time_ns();
    let started = Instant::now();
    let checksum = work()?;
    let wall_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let cpu_after = casa1::perf::process_cpu_time_ns();
    let allocations = ALLOCATIONS
        .load(Ordering::Relaxed)
        .saturating_sub(allocations_before);
    Ok(SideMeasurement {
        wall_ns,
        cpu_ns: cpu_after.saturating_sub(cpu_before),
        allocations,
        checksum,
    })
}

#[inline(never)]
fn native_integer_step(value: u64) -> u64 {
    value.wrapping_mul(1_664_525).wrapping_add(1_013_904_223)
}

#[inline(never)]
fn native_leaf(value: u64) -> u64 {
    value.wrapping_add(1)
}

fn native_integer_loop(iterations: u64) -> u64 {
    let mut value = 1_u64;
    for _ in 0..iterations {
        value = native_integer_step(black_box(value));
    }
    value
}

fn native_memory_copy(source: &[u8], destination: &mut [u8]) -> u64 {
    destination.copy_from_slice(source);
    checksum_bytes(destination)
}

fn native_function_calls(iterations: u64) -> u64 {
    let mut value = 0_u64;
    for _ in 0..iterations {
        value = native_leaf(black_box(value));
    }
    value
}

fn native_indirect_calls(iterations: u64) -> u64 {
    let target: fn(u64) -> u64 = native_leaf;
    let mut value = 0_u64;
    for _ in 0..iterations {
        value = target(black_box(value));
    }
    value
}

fn checksum_bytes(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for chunk in bytes.chunks_exact(8) {
        let mut word = [0_u8; 8];
        word.copy_from_slice(chunk);
        hash ^= u64::from_le_bytes(word);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn memory_operand(address: u64) -> casa1::cpu::MemoryOperand {
    casa1::cpu::MemoryOperand {
        base: None,
        index: None,
        scale: 1,
        displacement: 0,
        rip_relative: false,
        rip_base: 0,
        segment: None,
        address_size_32: false,
        absolute_address: Some(address),
    }
}

fn guest_integer_loop(iterations: u64) -> Result<u64, String> {
    use casa1::cpu::{
        CompareOperand, CpuState, GuestArch, IrInstruction, MemoryImage, Register, execute_ir,
    };

    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rax, 1);
    let mut memory = MemoryImage::default();
    let block = [
        IrInstruction::ImulReg {
            dst: Register::Rax,
            src: CompareOperand::ImmediateU64(1_664_525),
            width: 8,
        },
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 1_013_904_223,
            width: 8,
        },
    ];
    for _ in 0..iterations {
        execute_ir(&mut state, &mut memory, &block)
            .map_err(|error| format!("guest integer loop failed: {error}"))?;
    }
    Ok(state.get(Register::Rax))
}

fn guest_memory_copy() -> Result<u64, String> {
    use casa1::cpu::{CpuState, GuestArch, IrInstruction, MemoryImage, Register, execute_ir};

    let source_address = NATIVE_LOAD_BIAS;
    let destination_address = NATIVE_DEST_BIAS;
    let source: Vec<u8> = (0..MEMORY_BYTES)
        .map(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
        .collect();
    let mut memory = MemoryImage::default();
    memory.map_bytes(source_address, &source);
    memory.map_bytes(destination_address, &[0_u8; MEMORY_BYTES]);
    let mut state = CpuState::new(GuestArch::X64);
    let mut block = Vec::with_capacity(MEMORY_BYTES / 8 * 2);
    for offset in (0..MEMORY_BYTES).step_by(8) {
        block.push(IrInstruction::LoadMemory {
            dst: Register::Rax,
            address: memory_operand(source_address + offset as u64),
            width: 8,
        });
        block.push(IrInstruction::StoreMemory {
            src: Register::Rax,
            address: memory_operand(destination_address + offset as u64),
            width: 8,
        });
    }
    execute_ir(&mut state, &mut memory, &block)
        .map_err(|error| format!("guest memory copy failed: {error}"))?;
    let copied = memory
        .read_bytes(destination_address, MEMORY_BYTES)
        .map_err(|error| format!("guest memory copy read-back failed: {error}"))?;
    Ok(checksum_bytes(&copied))
}

fn guest_call_chain(indirect: bool) -> Result<u64, String> {
    use casa1::cpu::{GuestArch, IrInstruction, MemoryImage, Register};
    use casa1::jit::WorkerSliceBenchmark;

    if !casa1::jit::jit_execution_available() {
        return Err("JIT execution capability is unavailable on this host".to_string());
    }
    let target = if indirect {
        vec![(
            0x1000_u64,
            vec![IrInstruction::CallRegister {
                src: Register::Rax,
                return_address: 0x1010,
            }],
        )]
    } else {
        vec![(
            0x1000_u64,
            vec![IrInstruction::Call {
                target: 0x2000,
                return_address: 0x1010,
            }],
        )]
    };
    let mut blocks = target;
    blocks.push((0x1010, vec![IrInstruction::Jump { target: 0x1000 }]));
    blocks.push((
        0x2000,
        vec![
            IrInstruction::AddImm {
                dst: Register::Rcx,
                value: 1,
                width: 8,
            },
            IrInstruction::Return { stack_adjust: 0 },
        ],
    ));
    let stack = if indirect { 0x12_000 } else { 0x11_000 };
    let mut memory = MemoryImage::default();
    memory.map_bytes(stack & !0xfff, &[0_u8; 0x1000]);
    let mut harness =
        WorkerSliceBenchmark::new(GuestArch::X64, &memory, &blocks, 0x1000, stack + 0x800);
    harness.reset();
    if indirect {
        harness.set_rax(0x2000);
    }
    let mut executed = 0_u64;
    let mut instructions = 0_u64;
    while executed < CALL_BLOCKS {
        let (ran, retired, _metrics) = harness.run(CALL_BUDGET.min(CALL_BLOCKS - executed));
        if ran == 0 {
            return Err("guest call chain stopped before the requested block count".to_string());
        }
        executed += ran;
        instructions += retired;
    }
    if instructions == 0 {
        return Err("guest call chain retired zero guest instructions".to_string());
    }
    Ok(instructions)
}

fn side_json(measurement: Option<SideMeasurement>, reason: Option<String>) -> serde_json::Value {
    match measurement {
        Some(side) => serde_json::json!({
            "available": true,
            "wall_ns": side.wall_ns,
            "cpu_ns": side.cpu_ns,
            "allocations": side.allocations,
            "checksum": side.checksum,
        }),
        None => serde_json::json!({
            "available": false,
            "reason": reason.unwrap_or_else(|| "workload is unavailable".to_string()),
        }),
    }
}

fn workload_json(
    native: Result<SideMeasurement, String>,
    guest: Result<SideMeasurement, String>,
) -> serde_json::Value {
    let native_measurement = native.as_ref().ok().map(|side| SideMeasurement {
        wall_ns: side.wall_ns,
        cpu_ns: side.cpu_ns,
        allocations: side.allocations,
        checksum: side.checksum,
    });
    let guest_measurement = guest.as_ref().ok().map(|side| SideMeasurement {
        wall_ns: side.wall_ns,
        cpu_ns: side.cpu_ns,
        allocations: side.allocations,
        checksum: side.checksum,
    });
    let ratio = casa1::perf::native_relative_ratio(
        guest.is_ok(),
        guest_measurement.as_ref().map_or(0, |side| side.wall_ns),
        native.is_ok(),
        native_measurement.as_ref().map_or(0, |side| side.wall_ns),
    );
    let (ratio_value, ratio_reason, ratio_cpu_value, ratio_cpu_reason) = match ratio {
        Ok(value) => (
            serde_json::json!(value),
            serde_json::Value::Null,
            match (
                guest_measurement.as_ref().map(|side| side.cpu_ns),
                native_measurement.as_ref().map(|side| side.cpu_ns),
            ) {
                (Some(guest_cpu), Some(native_cpu)) if guest_cpu > 0 && native_cpu > 0 => {
                    serde_json::json!(guest_cpu as f64 / native_cpu as f64)
                }
                _ => serde_json::Value::Null,
            },
            match (
                guest_measurement.as_ref().map(|side| side.cpu_ns),
                native_measurement.as_ref().map(|side| side.cpu_ns),
            ) {
                (Some(guest_cpu), Some(native_cpu)) if guest_cpu > 0 && native_cpu > 0 => {
                    serde_json::Value::Null
                }
                _ => serde_json::json!(
                    "CPU-time ratio is unavailable because a real process CPU time sample is missing"
                ),
            },
        ),
        Err(reason) => (
            serde_json::Value::Null,
            serde_json::json!(reason.reason()),
            serde_json::Value::Null,
            serde_json::json!(reason.reason()),
        ),
    };
    serde_json::json!({
        "native": side_json(native_measurement, native.err()),
        "casa1": side_json(guest_measurement, guest.err()),
        "ratio": ratio_value,
        "ratio_unavailable_reason": ratio_reason,
        "ratio_cpu": ratio_cpu_value,
        "ratio_cpu_unavailable_reason": ratio_cpu_reason,
    })
}

fn main() {
    let arm64 = cfg!(target_arch = "aarch64");
    let native_unavailable = (!arm64).then(|| {
        format!(
            "native reference lane requires an ARM64 host (running {})",
            std::env::consts::ARCH
        )
    });

    let mut source = vec![0_u8; MEMORY_BYTES];
    for (index, byte) in source.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
    }
    let mut destination = vec![0_u8; MEMORY_BYTES];

    let integer_native = if arm64 {
        measure(|| Ok(native_integer_loop(INTEGER_ITERATIONS)))
    } else {
        Err(native_unavailable.clone().unwrap_or_default())
    };
    let integer_guest = measure(|| guest_integer_loop(INTEGER_ITERATIONS));

    let memory_native = if arm64 {
        measure(|| Ok(native_memory_copy(&source, &mut destination)))
    } else {
        Err(native_unavailable.clone().unwrap_or_default())
    };
    let memory_guest = measure(guest_memory_copy);

    let calls_native = if arm64 {
        measure(|| Ok(native_function_calls(CALL_BLOCKS)))
    } else {
        Err(native_unavailable.clone().unwrap_or_default())
    };
    let calls_guest = measure(|| guest_call_chain(false));

    let indirect_native = if arm64 {
        measure(|| Ok(native_indirect_calls(CALL_BLOCKS)))
    } else {
        Err(native_unavailable.clone().unwrap_or_default())
    };
    let indirect_guest = measure(|| guest_call_chain(true));

    let document = serde_json::json!({
        "schema": 1,
        "generated_at": format!("{:?}", std::time::SystemTime::now()),
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "native_arm64": arm64,
        },
        "workloads": {
            "integer_loop": workload_json(integer_native, integer_guest),
            "memory_copy": workload_json(memory_native, memory_guest),
            "function_calls": workload_json(calls_native, calls_guest),
            "indirect_calls": workload_json(indirect_native, indirect_guest),
        },
    });
    let text = serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string());
    // Explicit output wins; otherwise write the harness's default report path
    // so `cargo run --bin perf_native` feeds `ci/check_perf.py` directly.
    let path = std::env::var("CASA1_PERF_NATIVE_OUT")
        .unwrap_or_else(|_| "target/casa1-perf-native.json".to_string());
    let _ = std::fs::write(path, &text);
    println!("CASA1_PERF_NATIVE {text}");
}
