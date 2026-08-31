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

pub(crate) mod com;
pub(crate) mod dshow;
pub(crate) mod legacy_gfx;
pub(crate) mod mf;
pub(crate) mod mscoree;
pub(crate) mod ntdll;
pub(crate) mod opengl;
pub(crate) mod wic;
