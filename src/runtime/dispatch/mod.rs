//! Runtime dispatch tree: the split dispatch modules for the guest API
//! surfaces.  The Nt*/Rtl* native-API dispatch arms live in
//! [`ntdll`](self::ntdll); they build on the canonical layers
//! ([`crate::ntdll`], the canonical VM, the live object/handle namespace,
//! the guest scheduler) and are wired into the main `dispatch_import` match
//! in `crate::runtime`.

use crate::runtime::HostThunk;

/// The IUnknown vtable preamble: QueryInterface/AddRef/Release are the
/// shared guest-object lifecycle slots every COM-style object starts with.
pub(crate) fn unknown_preamble() -> Vec<HostThunk> {
    vec![HostThunk::GuestObjectAddRef, HostThunk::GuestObjectRelease]
}

pub(crate) mod codecs;
pub(crate) mod com;
pub(crate) mod comdlg32;
pub(crate) mod crypto;
pub(crate) mod d3d8thk;
pub(crate) mod dinput;
pub(crate) mod dpapi;
pub(crate) mod dshow;
pub(crate) mod esent;
pub(crate) mod final_scraps;
pub(crate) mod hid;
pub(crate) mod httpapi;
pub(crate) mod imagehlp;
pub(crate) mod imm32;
pub(crate) mod ldap;
pub(crate) mod legacy_gfx;
pub(crate) mod long_tail;
pub(crate) mod mf;
pub(crate) mod mpr;
pub(crate) mod msacm;
pub(crate) mod msafd;
pub(crate) mod mscoree;
pub(crate) mod msctf;
pub(crate) mod msi;
pub(crate) mod msvbvm60;
pub(crate) mod ncrypt;
pub(crate) mod ntdll;
pub(crate) mod opengl;
pub(crate) mod pdh;
pub(crate) mod propsys;
pub(crate) mod rpcrt4;
pub(crate) mod system_sweep;
pub(crate) mod trust;
pub(crate) mod userenv;
pub(crate) mod uxtheme;
pub(crate) mod wic;
pub(crate) mod wininet;
pub(crate) mod wlanapi;

/// Shared fixture for the per-module dispatch tests: an x86 guest runtime
/// with the standard base addresses and a stack-argument dispatch helper,
/// mirroring the runtime's own `dispatch_x86_thunk` test harness.
#[cfg(test)]
pub(crate) mod test_support {
    use super::super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    /// The fixture: the runtime plus the guest memory it dispatches into.
    pub(crate) struct Fixture {
        pub(crate) runtime: PeHostRuntime,
        pub(crate) memory: MemoryImage,
        pub(crate) _temp: TempDir,
    }

    /// Guest stack address for the x86 stack-argument dispatch helper.
    pub(crate) const STACK: u64 = 0x50_000;

    /// Run the body on an 8 MB stack thread (the runtime's guest-callback
    /// machinery needs the same big-stack setup the runtime test suite uses).
    pub(crate) fn with_big_stack<T: Send + 'static>(
        body: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    /// Build an x86 fixture runtime in a temporary game environment.
    pub(crate) fn x86_fixture(name: &str) -> Fixture {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X86);
        runtime.next_data_address = data_base_for_arch(GuestArch::X86);
        runtime.next_heap_address = heap_base_for_arch(GuestArch::X86);
        runtime
            .win32
            .reset_address_space(private_pages_base_for_arch(GuestArch::X86));
        runtime.x86_heap_region = 0;
        Fixture {
            runtime,
            memory: MemoryImage::default(),
            _temp: temp_dir,
        }
    }

    /// Dispatch one thunk with x86 stack arguments through the real import
    /// dispatch (the same path a guest import call takes) and return EAX.
    pub(crate) fn dispatch_x86(fixture: &mut Fixture, thunk: HostThunk, args: &[u32]) -> u64 {
        let mut bytes = Vec::with_capacity(args.len() * 4);
        for arg in args {
            bytes.extend_from_slice(&arg.to_le_bytes());
        }
        dispatch_x86_stack(fixture, thunk, &bytes)
    }

    /// Dispatch one thunk with a raw x86 stack byte layout (for the
    /// signatures that pass 64-bit doubles on the stack).
    pub(crate) fn dispatch_x86_stack(
        fixture: &mut Fixture,
        thunk: HostThunk,
        stack_bytes: &[u8],
    ) -> u64 {
        let thunk_address = fixture.runtime.alloc_host_thunk(thunk);
        fixture.memory.map_bytes(STACK - 0x400, &[0_u8; 0x600]);
        write_u32(&mut fixture.memory, STACK, 0xDEAD_BEEF);
        for (index, byte) in stack_bytes.iter().enumerate() {
            fixture.memory.write_u8(STACK + 4 + index as u64, *byte);
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, STACK);
        fixture
            .runtime
            .dispatch_import(thunk_address, &mut state, &mut fixture.memory)
            .expect("dispatch thunk");
        state.get(Register::Rax)
    }
}
