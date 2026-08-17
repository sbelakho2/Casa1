// Smoke test: allocate MAP_JIT memory, write two ARM64 instructions, mark it
// executable and call it.
//
// NOTE: Executing MAP_JIT memory on Apple Silicon requires the
// `com.apple.security.cs.allow-jit` entitlement.  If the call below faults
// with EXC_BAD_ACCESS / KERN_PROTECTION_FAILURE, the binary is missing that
// entitlement (e.g. built without a signed .app bundle or the codesign flag).

// The libc crate declares `pthread_jit_write_protect_np` as returning void,
// but the real API returns a kern_return_t; declare it with the true
// signature so the caller can detect failure.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "pthread_jit_write_protect_np"]
    fn pthread_jit_write_protect_np_kern_return(enabled: libc::c_int) -> libc::c_int;
}

fn main() {
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
            -1,
            0,
        );
        eprintln!("MAP_JIT ptr = {:p}", ptr);
        if ptr == libc::MAP_FAILED {
            eprintln!("mmap FAILED");
            std::process::exit(1);
        }
        std::ptr::write_volatile(ptr as *mut u32, 0xd2800540);
        std::ptr::write_volatile((ptr as *mut u8).add(4) as *mut u32, 0xd65f03c0);

        #[cfg(target_os = "macos")]
        {
            let rc = pthread_jit_write_protect_np_kern_return(1);
            if rc != 0 {
                eprintln!("pthread_jit_write_protect_np(1) failed: {rc}");
                std::process::exit(1);
            }
        }

        eprintln!("calling...");
        let f: unsafe extern "C" fn() -> u64 = std::mem::transmute(ptr);
        let r = f();
        eprintln!("returned: {}", r);
        eprintln!("MAP_JIT EXECUTION WORKS!");
    }
}
