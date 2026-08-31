//! DirectShow module dispatch: the quartz.dll exports, in a dedicated
//! module per the audit's modularity requirement.  The module surface is
//! the classic COM server contract (DllGetClassObject/DllCanUnloadNow/
//! DllRegisterServer/DllUnregisterServer) plus AMGetErrorTextW, the
//! DirectShow error-code formatter.  DllGetClassObject hands out a class
//! factory for the Filter Graph object; with no filters registered the
//! graph object's methods answer the documented VFW_E_NO_* errors.
//!
//! Layer contract: DllGetClassObject returns HRESULTs in EAX; the class
//! factory follows the standard IClassFactory vtable layout.

use super::super::*;
use super::unknown_preamble;

/// S_OK.
const S_OK: u32 = 0;
use crate::runtime::state::GuestObjectKind;

/// IID_IGraphBuilder: {56a868a9-0ad4-11ce-b03a-0020af0ba770}
const IID_GRAPH_BUILDER: [u8; 16] = [
    0xa9, 0xa8, 0x68, 0x56, 0xd4, 0x0a, 0xce, 0x11, 0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70,
];

/// VFW_E_NO_FILTERS — no DirectShow filters are registered.
const VFW_E_NO_FILTERS: u32 = 0x8004_0227;
impl PeHostRuntime {
    /// Route every quartz thunk to its dispatch function.
    pub(crate) fn dispatch_dshow(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::AmGetErrorTextW => self.dispatch_am_get_error_text_w(state, memory),
            HostThunk::DllCanUnloadNow => self.dispatch_dshow_can_unload_now(state, memory),
            HostThunk::DshowClassFactoryCreateInstance => {
                self.dispatch_dshow_class_factory_create_instance(state, memory)
            }
            HostThunk::DshowClassFactoryLockServer => {
                self.dispatch_dshow_class_factory_lock_server(state, memory)
            }
            HostThunk::DshowFilterGraphRenderFile => {
                self.dispatch_dshow_filter_graph_render_file(state, memory)
            }
            HostThunk::DshowFilterGraphRender => {
                self.dispatch_dshow_filter_graph_render(state, memory)
            }
            HostThunk::DllRegisterServer => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::DllUnregisterServer => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted quartz thunk {thunk:?}"),
            )),
        }
    }

    /// `AMGetErrorTextW(hr, pBuffer, MaxLen)` — the DirectShow error text
    /// for the well-known VFW_E_* / AMERR_* codes.
    pub(crate) fn dispatch_am_get_error_text_w(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let hr = guest_call_arg_u32(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let max_len = guest_call_arg_u32(state, memory, 2)?;
        let text = dshow_error_text(hr);
        let mut written = 0_u32;
        for unit in text.encode_utf16() {
            if written >= max_len.saturating_sub(1) {
                break;
            }
            write_guest_u16(memory, buffer + (written as u64 * 2), unit).ok();
            written += 1;
        }
        write_guest_u16(memory, buffer + (written as u64 * 2), 0).ok();
        state.set(Register::Rax, u64::from(written));
        Ok(())
    }

    /// `DllCanUnloadNow()` — the COM server lock count decides: S_FALSE
    /// while anything is locked.
    pub(crate) fn dispatch_dshow_can_unload_now(
        &mut self,
        state: &mut CpuState,
        _memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let locked = self.com_server_lock_count > 0;
        state.set(Register::Rax, if locked { 1 } else { 0 });
        Ok(())
    }

    /// `IClassFactory::CreateInstance(pUnkOuter, riid, ppvObject)` — create
    /// the Filter Graph object.
    pub(crate) fn dispatch_dshow_class_factory_create_instance(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _outer = guest_call_arg(state, memory, 1)?;
        let riid = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        let iid = memory.read_bytes(riid, 16).unwrap_or_default();
        if iid != IID_GRAPH_BUILDER {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            }
            state.set(Register::Rax, 0x8000_4002);
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, dshow_filter_graph_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::DshowFilterGraph, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, 0x8007_000E);
            return Ok(());
        }
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IClassFactory::LockServer(fLock)` — the server lock count.
    pub(crate) fn dispatch_dshow_class_factory_lock_server(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let lock = guest_call_arg_u32(state, memory, 1)?;
        if lock != 0 {
            self.com_server_lock_count = self.com_server_lock_count.saturating_add(1);
        } else {
            self.com_server_lock_count = self.com_server_lock_count.saturating_sub(1);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IGraphBuilder::RenderFile(...)` — no filters are registered.
    pub(crate) fn dispatch_dshow_filter_graph_render_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _file = guest_call_arg(state, memory, 1)?;
        let _title = guest_call_arg(state, memory, 2)?;
        state.set(Register::Rax, u64::from(VFW_E_NO_FILTERS));
        Ok(())
    }

    /// `IGraphBuilder::Render(pUnkSource)` — no filters are registered.
    pub(crate) fn dispatch_dshow_filter_graph_render(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _source = guest_call_arg(state, memory, 1)?;
        state.set(Register::Rax, u64::from(VFW_E_NO_FILTERS));
        Ok(())
    }
}

fn dshow_error_text(hr: u32) -> &'static str {
    match hr {
        0x8004_0227 => "No filters were found to process the stream",
        0x8004_0228 => "No decompressor was found to process the stream",
        0x8004_0214 => "The filter graph does not support the requested operation",
        0x8004_0207 => "The pins are not connected",
        0x8004_0206 => "The input pin is not connected",
        0x8004_0208 => "The output pin is not connected",
        0x8004_0209 => "No media type was set on the pin",
        0x8004_020a => "The pins are already connected",
        0x8004_0211 => "The media type is not set",
        0x8004_0212 => "The filter is already in the graph",
        0x8004_0213 => "The filter is not in the graph",
        0x8004_0217 => "The clock is already set on the graph",
        0x8004_0218 => "The clock is not set on the graph",
        0x8004_0219 => "The renderer cannot render the media type",
        0x8004_0201 => "The operation is not supported",
        0x8004_0202 => "The media type is not supported",
        0x8004_0203 => "The operation cannot be performed",
        0x8004_0204 => "The operation was canceled",
        0x8004_0205 => "The filter is already active",
        _ => "DirectShow error",
    }
}

/// The IClassFactory vtable: IUnknown preamble + CreateInstance + LockServer.
#[allow(dead_code)] // the class-factory vtable builder
pub(crate) fn dshow_class_factory_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::DshowClassFactoryCreateInstance);
    methods.push(HostThunk::DshowClassFactoryLockServer);
    methods
}

/// The IGraphBuilder vtable: IUnknown preamble + the minimal graph surface.
#[allow(dead_code)] // the filter-graph vtable builder
pub(crate) fn dshow_filter_graph_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::DshowFilterGraphRenderFile);
    methods.push(HostThunk::DshowFilterGraphRender);
    methods
}
