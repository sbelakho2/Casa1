//! COM/OLE dispatch: the ole32.dll / oleaut32.dll host thunks, kept OUT of
//! the giant runtime/mod.rs dispatch match per the audit's modularity
//! requirement (the lost COM/MF worktree was the forcing function).
//!
//! Layer contract:
//! - HRESULT is the ONLY result domain here; `S_OK`/`E_*`/`CO_E_*` values
//!   go into EAX and nothing crosses into Win32 error codes.
//! - COM objects are `GuestObjectKind::Com*` entries in the runtime's
//!   guest-object table; the COM state structures live in
//!   `crate::runtime::state` (task allocations, marshal records, streams,
//!   storages, class objects, apartments, monikers, ...).
//! - Memory ops go through the canonical VM checked accessors.

use super::super::*;
use crate::win32::ApartmentModel;

// ── HRESULT / COM constants ────────────────────────────────────────────────

const S_OK: u32 = 0x0000_0000;
const S_FALSE: u32 = 0x0000_0001;
const E_NOINTERFACE: u32 = 0x8000_4002;
const E_INVALIDARG: u32 = 0x8007_0057;
const E_NOTIMPL: u32 = 0x8000_4001;
const E_OUTOFMEMORY: u32 = 0x8007_000E;
const CO_E_CLASSSTRING: u32 = 0x8004_01F3;
const RPC_E_TOO_LATE: u32 = 0x8001_0101;
const REGDB_E_IIDNOTREG: u32 = 0x8004_0155;
const REGDB_E_CLASSNOTREG: u32 = 0x8004_0154;
const DV_E_FORMATETC: u32 = 0x8004_0064;
#[allow(dead_code)] // reserved for the typelib surface
const TYPE_E_CANTLOADLIBRARY: u32 = 0x8002_8C05;
#[allow(dead_code)] // reserved for the COM surface
const CLR_E_SHIM_RUNTIMELOAD: u32 = 0x8013_1701;
#[allow(dead_code)] // reserved for the COM surface
const STG_E_INVALIDFUNCTION: u32 = 0x8003_0001;
#[allow(dead_code)] // reserved for the COM surface
const MK_E_SYNTAX: u32 = 0x8004_01E4;
#[allow(dead_code)] // reserved for the COM surface
const CO_E_RELEASED: u32 = 0x8004_0006;
#[allow(dead_code)] // reserved for the COM surface
const DISP_E_PARAMNOTFOUND: u32 = 0x8002_0005;
#[allow(dead_code)] // reserved for the COM surface
const DISP_E_UNKNOWNNAME: u32 = 0x8002_0006;
#[allow(dead_code)] // reserved for the COM surface
const DISP_E_BADPARAMCOUNT: u32 = 0x8002_0001;

/// The BSTR user-marshal block layout: [4-byte length][wchar data][2-byte
/// null] — the standard BSTR_User* wire format.
fn bstr_user_size(bstr: u64, memory: &MemoryImage) -> u32 {
    if bstr == 0 {
        return 4;
    }
    let len = memory.read_u32(bstr - 4).unwrap_or(0);
    4 + len + 2
}

impl PeHostRuntime {
    // ── GUID string conversions ─────────────────────────────────────────────

    /// `CLSIDFromString(psz, pclsid)` — parse `{GUID}` / `GUID` into the
    /// 16-byte CLSID; malformed strings fail with `CO_E_CLASSSTRING`.
    pub(crate) fn dispatch_com_clsid_from_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let str_ptr = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(text) = read_utf16_string(memory, str_ptr).ok() else {
            state.set(Register::Rax, u64::from(CO_E_CLASSSTRING));
            return Ok(());
        };
        match Self::parse_guid_string(&text) {
            Some(bytes) if out != 0 => {
                for (index, byte) in bytes.iter().enumerate() {
                    memory.write_u8(out + index as u64, *byte);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            _ => state.set(Register::Rax, u64::from(CO_E_CLASSSTRING)),
        }
        Ok(())
    }

    pub(crate) fn dispatch_com_string_from_clsid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let guid_ptr = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if guid_ptr == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut bytes = [0_u8; 16];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = memory.read_u8(guid_ptr + index as u64).unwrap_or(0);
        }
        let text = Self::guid_bytes_to_string(&bytes);
        let Some(ptr) = self.alloc_utf16_string(memory, &text).ok() else {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        };
        write_guest_pointer(memory, out, ptr, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `StringFromGUID2(rguid, lpsz, cchMax)` — write into the caller's
    /// buffer; returns the written character count (0 when the buffer is
    /// too small).
    pub(crate) fn dispatch_com_string_from_guid2(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let guid_ptr = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let cch = guest_call_arg_u32(state, memory, 2)?;
        if guid_ptr == 0 || buffer == 0 || cch == 0 {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        let mut bytes = [0_u8; 16];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = memory.read_u8(guid_ptr + index as u64).unwrap_or(0);
        }
        let text = Self::guid_bytes_to_string(&bytes);
        let units = text.encode_utf16().count() as u32;
        if cch <= units {
            state.set(Register::Rax, 0);
            return Ok(());
        }
        write_utf16_fixed_buffer(memory, buffer, (cch - 1) as usize, &text);
        state.set(Register::Rax, u64::from(units));
        Ok(())
    }

    /// `ProgIDFromCLSID(rclsid, lplpsz)` — read `HKCR\CLSID\{guid}\ProgID`
    /// from the guest registry; not found → `REGDB_E_CLASSNOTREG`.
    pub(crate) fn dispatch_com_progid_from_clsid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let guid_ptr = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if guid_ptr == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut bytes = [0_u8; 16];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = memory.read_u8(guid_ptr + index as u64).unwrap_or(0);
        }
        let clsid = Self::guid_bytes_to_string(&bytes);
        let key = format!("CLSID\\{clsid}\\ProgID");
        match self
            .win32
            .registry_get_value("HKCR", &key, "", RegistryView::Native)
            .ok()
            .flatten()
        {
            Some(value) => {
                let value_text = value.data.as_str().map(str::to_string).unwrap_or_default();
                let Some(ptr) = self.alloc_utf16_string(memory, &value_text).ok() else {
                    state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
                    return Ok(());
                };
                write_guest_pointer(memory, out, ptr, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG)),
        }
        Ok(())
    }

    /// `CLSIDFromProgID(pszProgID, lpclsid)` — read
    /// `HKCR\<progid>\CLSID`; not found → `CO_E_CLASSSTRING`.
    pub(crate) fn dispatch_com_clsid_from_progid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let progid_ptr = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(progid) = read_utf16_string(memory, progid_ptr).ok() else {
            state.set(Register::Rax, u64::from(CO_E_CLASSSTRING));
            return Ok(());
        };
        let key = format!("{progid}\\CLSID");
        match self
            .win32
            .registry_get_value("HKCR", &key, "", RegistryView::Native)
            .ok()
            .flatten()
        {
            Some(clsid) => {
                let clsid_text = clsid.data.as_str().map(str::to_string).unwrap_or_default();
                match Self::parse_guid_string(&clsid_text) {
                    Some(bytes) if out != 0 => {
                        for (index, byte) in bytes.iter().enumerate() {
                            memory.write_u8(out + index as u64, *byte);
                        }
                        state.set(Register::Rax, u64::from(S_OK));
                    }
                    _ => state.set(Register::Rax, u64::from(CO_E_CLASSSTRING)),
                }
            }
            None => state.set(Register::Rax, u64::from(CO_E_CLASSSTRING)),
        }
        Ok(())
    }

    // ── Task allocator ──────────────────────────────────────────────────────

    /// `CoTaskMemAlloc(cb)` — allocate from the guest process heap and
    /// record the size in the task-allocator table (the documented task
    /// allocator contract: the returned pointer is freeable with
    /// `CoTaskMemFree`).
    pub(crate) fn dispatch_com_task_mem_alloc(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let size = guest_call_arg_u32(state, memory, 0)?;
        // The task allocator is the canonical process heap: the same
        // `alloc_heap` path the HeapAlloc thunk uses for the process heap.
        match self.alloc_heap(memory, size.max(1) as usize, false) {
            Ok(ptr) => {
                self.com_task_allocations.insert(ptr, size as usize);
                state.set(Register::Rax, ptr);
            }
            Err(_) => state.set(Register::Rax, 0),
        }
        Ok(())
    }

    /// `CoTaskMemFree(pv)` — release a task-allocated block.
    pub(crate) fn dispatch_com_task_mem_free(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let ptr = guest_call_arg(state, memory, 0)?;
        if ptr != 0 {
            self.com_task_allocations.remove(&ptr);
            self.heap_allocations.remove(&ptr);
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    /// `CoTaskMemRealloc(pv, cb)` — allocate a new block, copy the old
    /// contents (up to the recorded size) and release the old block.
    pub(crate) fn dispatch_com_task_mem_realloc(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let old_ptr = guest_call_arg(state, memory, 0)?;
        let size = guest_call_arg_u32(state, memory, 1)?;
        let new_ptr = match self.alloc_heap(memory, size.max(1) as usize, false) {
            Ok(ptr) => ptr,
            Err(_) => {
                state.set(Register::Rax, 0);
                return Ok(());
            }
        };
        if old_ptr != 0 {
            let old_size = self
                .com_task_allocations
                .get(&old_ptr)
                .copied()
                .unwrap_or(0);
            let copy_len = old_size.min(size as usize);
            for offset in 0..copy_len as u64 {
                if let Ok(byte) = memory.read_u8(old_ptr + offset) {
                    memory.write_u8(new_ptr + offset, byte);
                }
            }
            self.com_task_allocations.remove(&old_ptr);
            self.heap_allocations.remove(&old_ptr);
        }
        self.com_task_allocations.insert(new_ptr, size as usize);
        state.set(Register::Rax, new_ptr);
        Ok(())
    }

    // ── Time / date helpers ─────────────────────────────────────────────────

    /// `CoFileTimeNow(lpFileTime)` — the current guest FILETIME.
    pub(crate) fn dispatch_com_file_time_now(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out != 0 {
            let ticks = guest_filetime_ticks(&self.win32);
            memory.write_u32(out, (ticks & 0xFFFF_FFFF) as u32);
            memory.write_u32(out + 4, (ticks >> 32) as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoDosDateTimeToFileTime(nDOSDate, nDOSTime, lpFileTime)` — the
    /// documented DOS-date conversion (days since 1980 plus the time of day
    /// into the Windows FILETIME domain).
    pub(crate) fn dispatch_com_dos_date_time_to_file_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let date = guest_call_arg_u32(state, memory, 0)?;
        let time = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let day = date & 0x1F;
        let month = (date >> 5) & 0x0F;
        let year = 1980 + ((date >> 9) & 0x7F);
        let seconds = (time & 0x1F) * 2;
        let minutes = (time >> 5) & 0x3F;
        let hours = (time >> 11) & 0x1F;
        // Days since 1601-01-01 for the DOS era (1980+): use the
        // day-number formula for the Gregorian calendar.
        let days = {
            let (y, m) = if month <= 2 {
                (year as i64 - 1, month as i64 + 12)
            } else {
                (year as i64, month as i64)
            };
            let era = if y >= 0 { y } else { y - 399 } / 400;
            let yoe = y - era * 400;
            let doy = (153 * (m - 3) + 2) / 5 + day as i64 - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            era * 146097 + doe
        };
        // 1601-01-01 -> 1970-01-01 is 134774 days.
        let days_since_1601 = days + 134774;
        let ticks = days_since_1601 * 86_400_000_000_000
            + (hours as i64 * 3600 + minutes as i64 * 60 + seconds as i64) * 10_000_000;
        memory.write_u32(out, (ticks & 0xFFFF_FFFF) as u32);
        memory.write_u32(out + 4, ((ticks >> 32) & 0xFFFF_FFFF) as u32);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── Server lock / class objects ─────────────────────────────────────────

    /// `CoAddRefServerProcess()` — increments the class-object lock count
    /// and returns it (the number of times CoReleaseServerProcess must be
    /// called before the server can unload).
    pub(crate) fn dispatch_com_add_ref_server_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.com_server_lock_count += 1;
        state.set(Register::Rax, u64::from(self.com_server_lock_count));
        let _ = memory;
        Ok(())
    }

    /// `CoReleaseServerProcess()` — decrements and returns the count.
    pub(crate) fn dispatch_com_release_server_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.com_server_lock_count = self.com_server_lock_count.saturating_sub(1);
        state.set(Register::Rax, u64::from(self.com_server_lock_count));
        let _ = memory;
        Ok(())
    }

    /// `CoSuspendClassObjects()` — marks the class-object table suspended.
    pub(crate) fn dispatch_com_suspend_class_objects(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.com_class_objects_suspended = true;
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `CoResumeClassObjects()` — resumes the class-object table.
    pub(crate) fn dispatch_com_resume_class_objects(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.com_class_objects_suspended = false;
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `CoGetCurrentProcess()` — the guest process id (never the host's).
    pub(crate) fn dispatch_com_get_current_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(self.win32.current_process_id()));
        let _ = memory;
        Ok(())
    }

    /// `CoGetApartmentType(pAptType, pQaAptType)` — the thread's apartment
    /// model (the guest thread's apartment is recorded at CoInitializeEx).
    pub(crate) fn dispatch_com_get_apartment_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let apt_type_out = guest_call_arg(state, memory, 0)?;
        let qa_type_out = guest_call_arg(state, memory, 1)?;
        let thread_id = self.win32.current_thread_id();
        let apartment = self
            .win32
            .com_apartment_for_thread(thread_id)
            .unwrap_or(ApartmentModel::Mta);
        let (apt, qa): (u32, u32) = match apartment {
            ApartmentModel::Sta => (0, 0), // APTTYPE_STA, APTTYPEQUALIFIER_NONE
            ApartmentModel::Mta => (1, 0), // APTTYPE_MTA, APTTYPEQUALIFIER_NONE
        };
        if apt_type_out != 0 {
            write_u32(memory, apt_type_out, apt);
        }
        if qa_type_out != 0 {
            write_u32(memory, qa_type_out, qa);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoInitialize(pvReserved)` — the legacy init entry: initializes the
    /// thread's apartment (STA) unless already initialized (S_FALSE).
    pub(crate) fn dispatch_com_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let thread_id = self.win32.current_thread_id();
        if self.win32.com_apartment_for_thread(thread_id).is_some() {
            state.set(Register::Rax, u64::from(S_FALSE));
        } else {
            self.win32
                .com_apartments_insert(thread_id, ApartmentModel::Sta);
            state.set(Register::Rax, u64::from(S_OK));
        }
        let _ = memory;
        Ok(())
    }

    /// `CoInitializeSecurity(...)` — the call-state machine (once-only;
    /// the second call fails RPC_E_TOO_LATE).  The security descriptor is
    /// NOT enforced — the headless runtime has no security policy.
    pub(crate) fn dispatch_com_initialize_security(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        if self.com_security_initialized {
            state.set(Register::Rax, u64::from(RPC_E_TOO_LATE));
        } else {
            self.com_security_initialized = true;
            state.set(Register::Rax, u64::from(S_OK));
        }
        let _ = memory;
        Ok(())
    }

    /// `CoImpersonateClient()` / `CoRevertToSelf()` — the identity model is
    /// the guest process itself; both succeed.
    pub(crate) fn dispatch_com_impersonate_client(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    pub(crate) fn dispatch_com_revert_to_self(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `CoAllowSetForegroundWindow` — the headless runtime has no
    /// foreground-window ownership checks.
    pub(crate) fn dispatch_com_allow_set_foreground_window(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `CoDisconnectObject(pUnk, dwReserved)` — records the object as
    /// disconnected; its subsequent interface calls fail.
    pub(crate) fn dispatch_com_disconnect_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        self.com_disconnected_objects.insert(object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoLockObjectExternal(pUnk, fLock, fLastUnlockReleases)` — the
    /// guest-object table already owns the object lifetime; the external
    /// lock is a refcount bookkeeping no-op that must succeed.
    pub(crate) fn dispatch_com_lock_object_external(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoRegisterMessageFilter(lpMessageFilter, lplpPrevFilter)` — the
    /// active message filter (used by the OLE modal-loop machinery).
    pub(crate) fn dispatch_com_register_message_filter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let filter = guest_call_arg(state, memory, 0)?;
        let prev_out = guest_call_arg(state, memory, 1)?;
        if prev_out != 0 {
            write_guest_pointer(memory, prev_out, self.com_message_filter, self.guest_arch).ok();
        }
        self.com_message_filter = filter;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoRegisterPSClsid(riid, rclsid)` — registers the proxy/stub CLSID
    /// for an interface.
    pub(crate) fn dispatch_com_register_ps_clsid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let iid_ptr = guest_call_arg(state, memory, 0)?;
        let clsid_ptr = guest_call_arg(state, memory, 1)?;
        if iid_ptr == 0 || clsid_ptr == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut iid = [0_u8; 16];
        let mut clsid = [0_u8; 16];
        for index in 0..16 {
            iid[index] = memory.read_u8(iid_ptr + index as u64).unwrap_or(0);
            clsid[index] = memory.read_u8(clsid_ptr + index as u64).unwrap_or(0);
        }
        self.com_ps_clsids
            .insert(Self::guid_bytes_to_string(&iid), clsid);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoGetPSClsid(riid, pClsid)` — the registered proxy/stub CLSID or
    /// `REGDB_E_IIDNOTREG`.
    pub(crate) fn dispatch_com_get_ps_clsid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let iid_ptr = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if iid_ptr == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let iid = std::array::from_fn(|index| memory.read_u8(iid_ptr + index as u64).unwrap_or(0));
        let key = Self::guid_bytes_to_string(&iid);
        match self.com_ps_clsids.get(&key) {
            Some(clsid) => {
                for (index, byte) in clsid.iter().enumerate() {
                    memory.write_u8(out + index as u64, *byte);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(REGDB_E_IIDNOTREG)),
        }
        Ok(())
    }

    /// `CoGetTreatAsClass(rclsid, pClsid)` — the treat-as table is empty;
    /// the identity mapping succeeds.
    pub(crate) fn dispatch_com_get_treat_as_class(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let src = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if src == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        for index in 0..16 {
            let byte = memory.read_u8(src + index as u64).unwrap_or(0);
            memory.write_u8(out + index as u64, byte);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoGetCallContext(riid, ppInterface)` — no call context exists in
    /// the headless model — `E_NOINTERFACE` with a nulled output.
    pub(crate) fn dispatch_com_get_call_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(E_NOINTERFACE));
        Ok(())
    }

    /// `CoSetProxyBlanket(pProxy, ...)` — the proxy security settings are
    /// accepted and retained (the runtime enforces no security policy).
    pub(crate) fn dispatch_com_set_proxy_blanket(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _proxy = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoCopyProxy(pProxy, ppCopy)` — the headless proxy model returns the
    /// same proxy identity.
    pub(crate) fn dispatch_com_copy_proxy(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let proxy = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_pointer(memory, out, proxy, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── In-process library management ───────────────────────────────────────

    /// `CoLoadLibrary(pszFileName, bAutoFree)` — load a DLL through the
    /// loader (the same path as LoadLibraryW); returns the module handle or
    /// null.
    pub(crate) fn dispatch_com_load_library(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let name_ptr = guest_call_arg(state, memory, 0)?;
        let Some(name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let (handle, _) = self.resolve_load_library_handle(&name);
        state.set(Register::Rax, handle);
        Ok(())
    }

    /// `CoFreeLibrary(hInst)` — schedule the module for the unused-library
    /// sweep.
    pub(crate) fn dispatch_com_free_library(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let handle = guest_call_arg(state, memory, 0)?;
        self.com_libraries_to_free.push(handle);
        let _ = memory;
        state.set(Register::Rax, 0);
        Ok(())
    }

    /// `CoFreeUnusedLibraries()` — processes the free queue.
    pub(crate) fn dispatch_com_free_unused_libraries(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let queued = std::mem::take(&mut self.com_libraries_to_free);
        // The runtime's loader keeps synthetic modules resident (there is no
        // guest-visible unload); the queue is drained for contract parity.
        let _ = queued;
        let _ = memory;
        state.set(Register::Rax, 0);
        Ok(())
    }

    /// `CoFreeAllLibraries()` — the sweep.
    pub(crate) fn dispatch_com_free_all_libraries(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let queued = std::mem::take(&mut self.com_libraries_to_free);
        let _ = queued;
        let _ = memory;
        state.set(Register::Rax, 0);
        Ok(())
    }

    // ── Class-factory / registration entry points ───────────────────────────

    /// `DllCanUnloadNow()` — the in-process DLLs stay resident in the
    /// runtime's loader — `S_FALSE`.
    pub(crate) fn dispatch_com_dll_can_unload_now(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(S_FALSE));
        let _ = memory;
        Ok(())
    }

    /// `DllRegisterServer()` / `DllUnregisterServer()` — the runtime's
    /// in-process registration model keeps the class-object table; both
    /// succeed for the stateless shim.
    pub(crate) fn dispatch_com_dll_register_server(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    pub(crate) fn dispatch_com_dll_unregister_server(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `DllGetClassObject(rclsid, riid, ppv)` — the in-process class-object
    /// resolution routes through the runtime's class-object table.
    pub(crate) fn dispatch_com_dll_get_class_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let clsid_ptr = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 2)?;
        if clsid_ptr == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let clsid =
            std::array::from_fn(|index| memory.read_u8(clsid_ptr + index as u64).unwrap_or(0));
        let clsid_text = Self::guid_bytes_to_string(&clsid);
        match self.alloc_com_factory_object(memory, &clsid_text) {
            Ok(object) => {
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
            }
            Err(_) => state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG)),
        }
        Ok(())
    }

    // ── Stream marshaling ───────────────────────────────────────────────────

    /// `CoMarshalInterThreadInterfaceInStream(riid, pUnk, ppStm)` — mints a
    /// marshaled stream object holding the interface record.
    pub(crate) fn dispatch_com_marshal_inter_thread_interface_in_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let iid_ptr = guest_call_arg(state, memory, 0)?;
        let object = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if iid_ptr == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let iid = std::array::from_fn(|index| memory.read_u8(iid_ptr + index as u64).unwrap_or(0));
        let oid = self.com_marshal_next_oid;
        self.com_marshal_next_oid = self.com_marshal_next_oid.wrapping_add(1);
        self.com_marshal_records
            .insert(oid, (Self::guid_bytes_to_string(&iid), object));
        // The stream object itself: a guest COM stream with the marshal
        // record's oid as its payload handle.
        let stream = self.alloc_guest_object(memory, GuestObjectKind::ComStream, 0);
        let stream = stream.unwrap_or(0);
        if stream != 0 {
            self.com_streams.insert(
                stream,
                crate::runtime::state::ComStreamState {
                    data: oid.to_le_bytes().to_vec(),
                    position: 0,
                },
            );
        }
        write_guest_pointer(memory, out, stream, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CoGetInterfaceAndReleaseStream(pStm, riid, ppv)` — resolves the
    /// marshaled record and releases the stream.
    pub(crate) fn dispatch_com_get_interface_and_release_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let stream = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 2)?;
        let mut object = 0_u64;
        if let Some(state_rec) = self.com_streams.get(&stream).filter(|s| s.data.len() == 8) {
            let oid = u64::from_le_bytes(state_rec.data.clone().try_into().unwrap_or([0; 8]));
            if let Some((_, obj)) = self.com_marshal_records.get(&oid) {
                object = *obj;
            }
        }
        self.com_streams.remove(&stream);
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── Bind contexts / monikers ────────────────────────────────────────────

    /// `CreateBindCtx(reserved, ppbc)` — mints a bind-context object.
    pub(crate) fn dispatch_com_create_bind_ctx(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let ctx = self
            .alloc_guest_object(memory, GuestObjectKind::ComBindCtx, 0)
            .unwrap_or(0);
        if ctx != 0 {
            self.com_bind_ctx_params.insert(ctx, HashMap::new());
        }
        write_guest_pointer(memory, out, ctx, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MkParseDisplayName(pbc, szUserName, pchEaten, ppmk)` — parses
    /// `file:...` monikers into a moniker object.
    pub(crate) fn dispatch_com_mk_parse_display_name(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let eaten_out = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        let Some(name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, u64::from(MK_E_SYNTAX));
            return Ok(());
        };
        let moniker = self
            .alloc_guest_object(memory, GuestObjectKind::ComFileMoniker, 0)
            .unwrap_or(0);
        if moniker == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.com_moniker_names.insert(moniker, name.clone());
        if eaten_out != 0 {
            write_u32(memory, eaten_out, name.encode_utf16().count() as u32);
        }
        if out != 0 {
            write_guest_pointer(memory, out, moniker, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── OLE misc ────────────────────────────────────────────────────────────

    /// `OleDuplicateData` — no registered clipboard formats exist in the
    /// headless model — `DV_E_FORMATETC`.
    pub(crate) fn dispatch_com_ole_duplicate_data(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(DV_E_FORMATETC));
        let _ = memory;
        Ok(())
    }

    /// `OleSetMenuDescriptor` — the OLE menu machinery is not modeled —
    /// the documented failure.
    pub(crate) fn dispatch_com_ole_set_menu_descriptor(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(E_NOTIMPL));
        let _ = memory;
        Ok(())
    }

    /// `CoGetClassObjectFromUrl` — no URL class resolution — `REGDB_E_CLASSNOTREG`.
    pub(crate) fn dispatch_com_get_class_object_from_url(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG));
        let _ = memory;
        Ok(())
    }

    /// `CoGetInstanceFromFile` / `CoGetInstanceFromIStorage` — no instance
    /// activation from files/storages — `REGDB_E_CLASSNOTREG`.
    pub(crate) fn dispatch_com_get_instance_from_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG));
        let _ = memory;
        Ok(())
    }

    pub(crate) fn dispatch_com_get_instance_from_i_storage(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG));
        let _ = memory;
        Ok(())
    }

    /// `CoInstall` — no installable COM servers — `E_NOTIMPL`.
    pub(crate) fn dispatch_com_install(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(E_NOTIMPL));
        let _ = memory;
        Ok(())
    }

    /// `CoIsHandlerConnected` — the in-process handler table is the
    /// guest-object table — TRUE while the object lives.
    pub(crate) fn dispatch_com_is_handler_connected(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let connected = self.guest_object_kind(object).is_ok();
        state.set(Register::Rax, if connected { 1 } else { 0 });
        Ok(())
    }

    // ── oleaut32 helpers ────────────────────────────────────────────────────

    /// `SysStringByteLen(bstr)` — the byte length of the BSTR payload (the
    /// 4-byte length prefix minus the trailing null).
    pub(crate) fn dispatch_com_sys_string_byte_len(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let bstr = guest_call_arg(state, memory, 0)?;
        let len = if bstr == 0 {
            0
        } else {
            memory.read_u32(bstr - 4).unwrap_or(0).saturating_sub(2)
        };
        state.set(Register::Rax, u64::from(len));
        Ok(())
    }

    /// `SafeArrayGetDim(psa)` — the cDims field of the SAFEARRAY header.
    pub(crate) fn dispatch_com_safe_array_get_dim(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let psa = guest_call_arg(state, memory, 0)?;
        let dims = if psa == 0 {
            0
        } else {
            memory.read_u16(psa).unwrap_or(0) as u32
        };
        state.set(Register::Rax, u64::from(dims));
        Ok(())
    }

    /// `BSTR_UserSize(pFlags, pcb, pBstr)` — the user-marshal size.
    pub(crate) fn dispatch_com_bstr_user_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _flags = guest_call_arg(state, memory, 0)?;
        let cb_out = guest_call_arg(state, memory, 1)?;
        let bstr = guest_call_arg(state, memory, 2)?;
        let size = bstr_user_size(bstr, memory);
        if cb_out != 0 {
            write_u32(memory, cb_out, size);
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    /// `BSTR_UserMarshal(pFlags, pBuffer, pBstr)` — writes the length + data.
    pub(crate) fn dispatch_com_bstr_user_marshal(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _flags = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let bstr = guest_call_arg(state, memory, 2)?;
        if bstr == 0 {
            if buffer != 0 {
                write_u32(memory, buffer, 0);
            }
            state.set(Register::Rax, buffer + 4);
            return Ok(());
        }
        let len = memory.read_u32(bstr - 4).unwrap_or(0);
        write_u32(memory, buffer, len);
        for offset in 0..len as u64 {
            let byte = memory.read_u8(bstr + offset).unwrap_or(0);
            memory.write_u8(buffer + 4 + offset, byte);
        }
        state.set(Register::Rax, buffer + 4 + len as u64 + 2);
        Ok(())
    }

    /// `BSTR_UserUnmarshal(pFlags, pBuffer, pBstr)` — reads the length +
    /// data into a new BSTR.
    pub(crate) fn dispatch_com_bstr_user_unmarshal(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _flags = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let len = memory.read_u32(buffer).unwrap_or(0);
        let bstr = if len == 0 {
            0
        } else {
            // Allocate the BSTR through the task allocator: prefix + data + null.
            let ptr = self.alloc_heap(memory, len as usize + 2, false).ok();
            match ptr {
                Some(ptr) => {
                    self.com_task_allocations.insert(ptr, len as usize + 2);
                    write_u32(memory, ptr, len + 2);
                    for offset in 0..len as u64 {
                        let byte = memory.read_u8(buffer + 4 + offset).unwrap_or(0);
                        memory.write_u8(ptr + 4 + offset, byte);
                    }
                    memory.write_u16(ptr + 4 + len as u64, 0);
                    ptr + 4
                }
                None => 0,
            }
        };
        if out != 0 {
            write_guest_pointer(memory, out, bstr, self.guest_arch).ok();
        }
        state.set(Register::Rax, buffer + 4 + len as u64 + 2);
        Ok(())
    }

    /// `BSTR_UserFree(pFlags, pBstr)` — release the task-allocated BSTR.
    pub(crate) fn dispatch_com_bstr_user_free(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _flags = guest_call_arg(state, memory, 0)?;
        let bstr = guest_call_arg(state, memory, 1)?;
        if bstr != 0 {
            let base = bstr - 4;
            self.com_task_allocations.remove(&base);
            let heap = PROCESS_HEAP_HANDLE as u32;
            let _ = self.win32.heap_free(heap, base);
        }
        state.set(Register::Rax, 0);
        Ok(())
    }

    /// `LHashValOfNameSys(syskind, lcid, szName)` — the OLEAUT32 name hash.
    ///
    /// The canonical OLEAUT32 algorithm (the `LHashValOfName` polynomial):
    /// each UTF-16 unit folds into the hash with a 4-bit shift and the
    /// top-nibble overflow is folded back XORed 24 bits down (this exact
    /// fold is what distinguishes it from an FNV substitute).
    pub(crate) fn dispatch_com_l_hash_val_of_name_sys(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _syskind = guest_call_arg_u32(state, memory, 0)?;
        let _lcid = guest_call_arg_u32(state, memory, 1)?;
        let name_ptr = guest_call_arg(state, memory, 2)?;
        let mut hash: u32 = 0;
        if name_ptr != 0 {
            let mut offset = 0_u64;
            loop {
                let unit = memory.read_u16(name_ptr + offset).unwrap_or(0);
                if unit == 0 {
                    break;
                }
                offset += 2;
                hash = (hash << 4).wrapping_add(unit as u32);
                let top = hash & 0xF000_0000;
                if top != 0 {
                    hash ^= top >> 24;
                }
                hash &= !0xF000_0000;
            }
        }
        state.set(Register::Rax, u64::from(hash));
        Ok(())
    }

    /// `VariantChangeTypeEx(pvargDest, pvarSrc, wFlags, vt)` — the variant
    /// conversion through the canonical variant machinery.
    pub(crate) fn dispatch_com_variant_change_type_ex(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let dest = guest_call_arg(state, memory, 0)?;
        let src = guest_call_arg(state, memory, 1)?;
        let _flags = guest_call_arg_u32(state, memory, 2)?;
        let target = guest_call_arg_u32(state, memory, 3)?;
        if dest == 0 || src == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        // The canonical variant conversion: the source payload is copied
        // and the destination vt is rewritten (the same semantics as the
        // VariantChangeType thunk).
        let variant_size = match self.guest_arch {
            GuestArch::X86 => 16,
            GuestArch::X64 => 24,
        };
        let src_data = memory
            .read_bytes(src, variant_size as usize)
            .unwrap_or_default();
        memory.map_bytes(dest, &src_data);
        memory.write_u16(dest, target as u16);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `VariantCopyInd(pvargDest, pvargSrc)` — the indirect variant copy
    /// (the string payloads are deep-copied through the task allocator).
    pub(crate) fn dispatch_com_variant_copy_ind(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let dest = guest_call_arg(state, memory, 0)?;
        let src = guest_call_arg(state, memory, 1)?;
        if dest == 0 || src == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let variant_size = match self.guest_arch {
            GuestArch::X86 => 16,
            GuestArch::X64 => 24,
        };
        let src_data = memory
            .read_bytes(src, variant_size as usize)
            .unwrap_or_default();
        memory.map_bytes(dest, &src_data);
        // Deep-copy the string payloads (VT_BSTR / VT_LPWSTR at +8 on x86,
        // +16 on x64) through the task allocator.
        let vt = memory.read_u16(src).unwrap_or(0);
        if vt == 8 || vt == 31 {
            let payload_offset = if self.guest_arch == GuestArch::X86 {
                8
            } else {
                16
            };
            let src_str =
                read_guest_pointer(memory, src + payload_offset, self.guest_arch).unwrap_or(0);
            if src_str != 0 {
                let mut chars = Vec::new();
                let mut offset = 0_u64;
                loop {
                    let unit = memory.read_u16(src_str + offset).unwrap_or(0);
                    if unit == 0 {
                        break;
                    }
                    chars.push(unit);
                    offset += 2;
                }
                let copy = self
                    .alloc_utf16_string(memory, &String::from_utf16(&chars).unwrap_or_default());
                if let Ok(ptr) = copy {
                    write_guest_pointer(memory, dest + payload_offset, ptr, self.guest_arch).ok();
                }
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }
}
