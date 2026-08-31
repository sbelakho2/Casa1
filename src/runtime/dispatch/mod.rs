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
