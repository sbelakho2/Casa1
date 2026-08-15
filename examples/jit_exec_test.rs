fn main() {
    unsafe {
        let ptr = libc::mmap(std::ptr::null_mut(), 4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT, -1, 0);
        eprintln!("MAP_JIT ptr = {:p}", ptr);
        if ptr == libc::MAP_FAILED { eprintln!("mmap FAILED"); std::process::exit(1); }
        std::ptr::write_volatile(ptr as *mut u32, 0xd2800540);
        std::ptr::write_volatile((ptr as *mut u8).add(4) as *mut u32, 0xd65f03c0);
        libc::pthread_jit_write_protect_np(1);
        eprintln!("calling...");
        let f: unsafe extern "C" fn() -> u64 = std::mem::transmute(ptr);
        let r = f();
        eprintln!("returned: {}", r);
        eprintln!("MAP_JIT EXECUTION WORKS!");
    }
}
