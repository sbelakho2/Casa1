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
const MK_E_NOOBJECT: u32 = 0x8004_01E5;
const MK_E_REDUCED_TO_SELF: u32 = 0x8004_0109;
#[allow(dead_code)] // reserved for the COM surface
const CO_E_RELEASED: u32 = 0x8004_0006;
const DISP_E_PARAMNOTFOUND: u32 = 0x8002_0004;
const DISP_E_TYPEMISMATCH: u32 = 0x8002_0005;
const DISP_E_MEMBERNOTFOUND: u32 = 0x8002_0003;
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

    // ── The interface-identity exports (ole32/oleaut32) ───────────────────

    /// The interface-identity exports (IMoniker, IStream, ...): ole32
    /// exports these as the interface's IID data; the export hands out a
    /// guest-resident copy of the GUID and returns its pointer in EAX.
    fn dispatch_interface_iid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        iid: &[u8; 16],
    ) -> AppResult<()> {
        let slot = self.com_interface_iid_slots[0];
        let address = if slot == 0 {
            let address = self.alloc_zeroed(memory, 64, 8)?;
            self.com_interface_iid_slots[0] = address;
            address
        } else {
            slot
        };
        for (i, byte) in iid.iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        state.set(Register::Rax, address);
        Ok(())
    }

    pub(crate) fn dispatch_ole_iid_moniker(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_storage(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_malloc(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_persist(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x0c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_drop_target(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x22, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_data_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x0e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_ole_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_in_place_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x13, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_object_with_site(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0xa3, 0x01, 0x48, 0xfc, 0xa9, 0x2b, 0xcf, 0x11, 0xa2, 0x29, 0x00, 0xaa, 0x00, 0x3d,
                0x73, 0x52,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_service_provider(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0xc1, 0x40, 0x51, 0x6d, 0x36, 0x74, 0xce, 0x11, 0x80, 0x34, 0x00, 0xaa, 0x00, 0x60,
                0x09, 0xfa,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_enum_variant(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x04, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        )
    }

    pub(crate) fn dispatch_ole_iid_connection_point(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_interface_iid(
            state,
            memory,
            &[
                0x86, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34,
                0x1d, 0x07,
            ],
        )
    }

    // ── The OLE Automation remainder ───────────────────────────────────────

    /// `DispGetParam(pdispparams, position, vt, pvarResult, pvtInOut)` —
    /// extract the argument at `position` from the DISPPARAMS (the
    /// rgvarg array is stored reversed).
    pub(crate) fn dispatch_ole_disp_get_param(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let dispparams = guest_call_arg(state, memory, 0)?;
        let position = guest_call_arg_u32(state, memory, 1)?;
        let vt = guest_call_arg_u32(state, memory, 2)?;
        let result = guest_call_arg(state, memory, 3)?;
        let _in_out = guest_call_arg(state, memory, 4)?;
        if dispparams == 0 || result == 0 {
            state.set(Register::Rax, 0x8002_0008); // DISP_E_BADVARTYPE
            return Ok(());
        }
        let c_args = read_guest_u32(memory, dispparams).unwrap_or(0);
        let rgvarg = read_guest_pointer(memory, dispparams + 8, self.guest_arch).unwrap_or(0);
        if position >= c_args || rgvarg == 0 {
            state.set(Register::Rax, u64::from(DISP_E_PARAMNOTFOUND));
            return Ok(());
        }
        // rgvarg[0] is the LAST argument; position 0 is the rightmost.
        let index = c_args - 1 - position;
        let variant = rgvarg + (index as u64 * 24);
        let source_vt = read_guest_u32(memory, variant).unwrap_or(0);
        let source_value = read_guest_pointer(memory, variant + 8, self.guest_arch).unwrap_or(0);
        match (vt, source_vt) {
            (2, 2) => {
                // VT_I4 -> VT_I4
                write_guest_u32(memory, result + 8, source_value as u32).ok();
            }
            (2, 3) => {
                // VT_I4 <- VT_I2
                write_guest_u32(memory, result + 8, (source_value as i16) as i32 as u32).ok();
            }
            (3, 2) => {
                // VT_I2 <- VT_I4
                write_guest_u32(
                    memory,
                    result + 8,
                    (source_value as i32 as i16) as u16 as u32,
                )
                .ok();
            }
            (11, 2) => {
                // VT_BOOL <- VT_I4
                write_guest_u32(
                    memory,
                    result + 8,
                    if source_value != 0 { 0xffff } else { 0 },
                )
                .ok();
            }
            (3, 3) => {
                write_guest_u32(memory, result + 8, source_value as u32).ok();
            }
            _ => {
                state.set(Register::Rax, 0x8002_0008);
                return Ok(());
            }
        }
        write_guest_u32(memory, result, vt).ok();
        state.set(Register::Rax, 0);
        Ok(())
    }

    /// `DispGetIDsOfNames(pdisp, rgszNames, cNames, lcid, rgdispid)` — the
    /// OLEAUT32 helper routes into the target object's real registered
    /// dispatch table (the same per-interface DISPID assignment the IDispatch
    /// vtable methods use).
    pub(crate) fn dispatch_ole_disp_get_ids_of_names(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let dispatch = guest_call_arg(state, memory, 0)?;
        let names = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)?;
        let lcid = guest_call_arg_u32(state, memory, 3)?;
        let ids = guest_call_arg(state, memory, 4)?;
        let hr = self.com_get_ids_of_names(memory, dispatch, names, count, lcid, ids)?;
        state.set(Register::Rax, u64::from(hr));
        Ok(())
    }

    /// `DispInvoke(pvInstance, ptinfo, dispidMember, wFlags, pdispparams,
    /// pvarResult, pexcepinfo, puArgErr)` — invoke through the registered
    /// method table, using the ITypeInfo's owner when the instance is NULL
    /// (the exact DispInvoke contract).
    pub(crate) fn dispatch_ole_disp_invoke(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let instance = guest_call_arg(state, memory, 0)?;
        let type_info = guest_call_arg(state, memory, 1)?;
        let dispid = self.com_arg_i32(state, memory, 2);
        let flags = guest_call_arg_u32(state, memory, 3)? as u16;
        let params = guest_call_arg(state, memory, 4)?;
        let result = guest_call_arg(state, memory, 5)?;
        let _exception = guest_call_arg(state, memory, 6)?;
        let argument_error = guest_call_arg(state, memory, 7)?;
        let target = match self.com_type_infos.get(&type_info) {
            Some(info) => {
                if instance != 0 {
                    instance
                } else {
                    info.owner
                }
            }
            None => instance,
        };
        if target == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let hr = self.invoke_automation_member(
            state,
            memory,
            target,
            dispid,
            flags,
            params,
            result,
            argument_error,
        )?;
        state.set(Register::Rax, u64::from(hr));
        Ok(())
    }

    /// `CreateDispTypeInfo` — the typeinfo format is not supported.
    pub(crate) fn dispatch_ole_create_disp_type_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _type_desc = guest_call_arg(state, memory, 0)?;
        let _iid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, 0x8002_9c83); // TYPE_E_UNSUPFORMAT
        Ok(())
    }

    /// `CreateStdDispatch` — no typeinfo support.
    pub(crate) fn dispatch_ole_create_std_dispatch(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _outer = guest_call_arg(state, memory, 0)?;
        let _unk = guest_call_arg(state, memory, 1)?;
        let _type_info = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, 0x8002_9c83); // TYPE_E_UNSUPFORMAT
        Ok(())
    }

    /// `LoadTypeLib` / `LoadRegTypeLib` — no typelib can be loaded.
    pub(crate) fn dispatch_ole_load_type_lib(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _file = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, 0x8002_9c4a); // TYPE_E_CANTLOADLIBRARY
        Ok(())
    }

    /// `RegisterTypeLib` / `UnRegisterTypeLib` / `QueryPathOfRegTypeLib` —
    /// no registry access.
    pub(crate) fn dispatch_ole_typelib_registry(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _type_lib = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, 0x8002_9c40); // TYPE_E_REGISTRYACCESS
        Ok(())
    }

    /// Route the ole32/oleaut32 interface-identity and OLE-Automation
    /// remainder thunks.
    pub(crate) fn dispatch_com_ole_extra(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::OleIidMoniker => self.dispatch_ole_iid_moniker(state, memory),
            HostThunk::OleIidStream => self.dispatch_ole_iid_stream(state, memory),
            HostThunk::OleIidStorage => self.dispatch_ole_iid_storage(state, memory),
            HostThunk::OleIidMalloc => self.dispatch_ole_iid_malloc(state, memory),
            HostThunk::OleIidPersist => self.dispatch_ole_iid_persist(state, memory),
            HostThunk::OleIidDropTarget => self.dispatch_ole_iid_drop_target(state, memory),
            HostThunk::OleIidDataObject => self.dispatch_ole_iid_data_object(state, memory),
            HostThunk::OleIidOleObject => self.dispatch_ole_iid_ole_object(state, memory),
            HostThunk::OleIidInPlaceObject => self.dispatch_ole_iid_in_place_object(state, memory),
            HostThunk::OleIidObjectWithSite => {
                self.dispatch_ole_iid_object_with_site(state, memory)
            }
            HostThunk::OleIidServiceProvider => {
                self.dispatch_ole_iid_service_provider(state, memory)
            }
            HostThunk::OleIidEnumVariant => self.dispatch_ole_iid_enum_variant(state, memory),
            HostThunk::OleIidConnectionPoint => {
                self.dispatch_ole_iid_connection_point(state, memory)
            }
            HostThunk::OleDispGetParam => self.dispatch_ole_disp_get_param(state, memory),
            HostThunk::OleDispGetIdsOfNames => {
                self.dispatch_ole_disp_get_ids_of_names(state, memory)
            }
            HostThunk::OleDispInvoke => self.dispatch_ole_disp_invoke(state, memory),
            HostThunk::OleCreateDispTypeInfo => {
                self.dispatch_ole_create_disp_type_info(state, memory)
            }
            HostThunk::OleCreateStdDispatch => self.dispatch_ole_create_std_dispatch(state, memory),
            HostThunk::OleLoadTypeLib | HostThunk::OleLoadRegTypeLib => {
                self.dispatch_ole_load_type_lib(state, memory)
            }
            HostThunk::OleRegisterTypeLib
            | HostThunk::OleUnRegisterTypeLib
            | HostThunk::OleQueryPathOfRegTypeLib => {
                self.dispatch_ole_typelib_registry(state, memory)
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted OLE-extra thunk {thunk:?}"),
            )),
        }
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
        // The stream object itself: a real guest IStream whose payload is
        // the marshal record's oid (the interface pointer is resolved by
        // CoGetInterfaceAndReleaseStream).
        let stream = self.alloc_com_stream_object(
            memory,
            oid.to_le_bytes().to_vec(),
            "CoMarshalInterThreadInterfaceInStream",
            None,
        )?;
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
        // The marshal stream is consumed by the call: release the guest
        // object (dropping its last reference tears down the stream state).
        if self.guest_objects.contains_key(&stream) {
            let _ = self.release_guest_object(stream);
        }
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

    // MkParseDisplayName lives with the moniker implementation below (the
    // real scheme/ProgID/path parsing and bind behavior).

    // ── OLE misc ────────────────────────────────────────────────────────────

    /// `OleDuplicateData` — no registered clipboard formats exist in the
    /// headless model — `DV_E_FORMATETC`.
    pub(crate) fn dispatch_com_ole_duplicate_data(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        // OleDuplicateData(hSrc, cfFormat, uiFlags) — duplicate the global
        // memory in the requested clipboard format: the text formats copy
        // the bytes; the other formats answer DV_E_FORMATETC.
        const CF_TEXT: u32 = 1;
        const CF_UNICODETEXT: u32 = 13;
        let source = guest_call_arg(state, memory, 0)?;
        let format = guest_call_arg_u32(state, memory, 1)?;
        let _flags = guest_call_arg_u32(state, memory, 2)?;
        let Some(data) = self.com_globals.get(&source).cloned() else {
            state.set(Register::Rax, 0);
            return Ok(());
        };
        let copy = match format {
            CF_TEXT => {
                let mut copy = data;
                if copy.last().is_some_and(|b| *b != 0) {
                    copy.push(0);
                }
                copy
            }
            CF_UNICODETEXT => {
                let text = String::from_utf8_lossy(&data);
                let mut copy: Vec<u8> = Vec::new();
                for unit in text.encode_utf16() {
                    copy.extend_from_slice(&unit.to_le_bytes());
                }
                copy.extend_from_slice(&0_u16.to_le_bytes());
                copy
            }
            _ => {
                state.set(Register::Rax, u64::from(DV_E_FORMATETC));
                return Ok(());
            }
        };
        let handle = self.com_globals_next;
        self.com_globals_next += 1;
        self.com_globals.insert(handle, copy);
        state.set(Register::Rax, handle);
        Ok(())
    }

    /// `OleSetMenuDescriptor(hmenu, hwndPopup, hwndFrame, lpMenuDesc)` —
    /// register the OLE in-place menu descriptor (the shared-menu
    /// machinery is the runtime's message loop; the descriptor is
    /// recorded).
    pub(crate) fn dispatch_com_ole_set_menu_descriptor(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let menu = guest_call_arg(state, memory, 0)?;
        let popup = guest_call_arg(state, memory, 1)?;
        let frame = guest_call_arg(state, memory, 2)?;
        let descriptor = guest_call_arg(state, memory, 3)?;
        if descriptor != 0 {
            self.com_ole_menu_descriptor = Some((menu, popup, frame));
        } else {
            self.com_ole_menu_descriptor = None;
        }
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `CoGetClassObjectFromUrl(pwszCodeURL, riid, dwClsContext,
    /// pvReserved, dwFlags, ppv)` — resolve the class object for a URL:
    /// the file: scheme routes through the class-object table with the
    /// file's CLSID when one is embedded; otherwise the honest
    /// no-URL-handler answer.
    pub(crate) fn dispatch_com_get_class_object_from_url(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let url = guest_call_arg(state, memory, 0)?;
        let _riid = guest_call_arg(state, memory, 1)?;
        let _context = guest_call_arg_u32(state, memory, 2)?;
        let _reserved = guest_call_arg(state, memory, 3)?;
        let _flags = guest_call_arg_u32(state, memory, 4)?;
        let out = guest_call_arg(state, memory, 5)?;
        let url_text = read_utf16_string(memory, url).unwrap_or_default();
        if (url_text.starts_with("file:") || url_text.starts_with("file://"))
            && let Ok(bytes) = std::fs::read(
                url_text
                    .trim_start_matches("file://")
                    .trim_start_matches("file:"),
            )
            && let Some(clsid) = ole_embedded_clsid(&bytes)
        {
            let clsid_str = Self::guid_bytes_to_string(&clsid);
            if let Ok(factory) = self.alloc_com_factory_object(memory, &clsid_str) {
                if out != 0 {
                    write_guest_pointer(memory, out, factory, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
        }
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG));
        let _ = memory;
        Ok(())
    }

    /// `CoGetInstanceFromFile(pServerInfo, pclsid, punkOuter, dwClsCtx,
    /// grfMode, pwszName, dwCount, rgResults)` — the file-based instance
    /// activation: the file's embedded CLSID creates the object through the
    /// class-object table.
    pub(crate) fn dispatch_com_get_instance_from_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _server = guest_call_arg(state, memory, 0)?;
        let clsid = guest_call_arg(state, memory, 1)?;
        let _outer = guest_call_arg(state, memory, 2)?;
        let _context = guest_call_arg_u32(state, memory, 3)?;
        let _mode = guest_call_arg_u32(state, memory, 4)?;
        let path = guest_call_arg(state, memory, 5)?;
        let _count = guest_call_arg_u32(state, memory, 6)?;
        let results = guest_call_arg(state, memory, 7)?;
        let path_text = read_utf16_string(memory, path).unwrap_or_default();
        if let Ok(bytes) = std::fs::read(&path_text)
            && let Some(embedded) = ole_embedded_clsid(&bytes)
        {
            let clsid_text = Self::guid_bytes_to_string(&embedded);
            if let Ok(Some(object)) =
                self.try_create_com_object(memory, &clsid_text, IID_IUNKNOWN, 0)
            {
                write_guest_pointer(memory, results, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
        }
        // The explicit CLSID route.
        let clsid_bytes = memory.read_bytes(clsid, 16).unwrap_or_default();
        if clsid_bytes.iter().any(|b| *b != 0) {
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(&clsid_bytes);
            let clsid_text = Self::guid_bytes_to_string(&raw);
            if let Ok(Some(object)) =
                self.try_create_com_object(memory, &clsid_text, IID_IUNKNOWN, 0)
            {
                write_guest_pointer(memory, results, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
        }
        if results != 0 {
            write_guest_pointer(memory, results, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG));
        let _ = memory;
        Ok(())
    }

    /// `CoGetInstanceFromIStorage` — the storage route is the class-object
    /// table with the explicit CLSID.
    pub(crate) fn dispatch_com_get_instance_from_i_storage(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _server = guest_call_arg(state, memory, 0)?;
        let clsid = guest_call_arg(state, memory, 1)?;
        let _outer = guest_call_arg(state, memory, 2)?;
        let _context = guest_call_arg_u32(state, memory, 3)?;
        let _storage = guest_call_arg(state, memory, 4)?;
        let _count = guest_call_arg_u32(state, memory, 5)?;
        let results = guest_call_arg(state, memory, 6)?;
        let clsid_bytes = memory.read_bytes(clsid, 16).unwrap_or_default();
        if clsid_bytes.iter().any(|b| *b != 0) {
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(&clsid_bytes);
            let clsid_text = Self::guid_bytes_to_string(&raw);
            if let Ok(Some(object)) =
                self.try_create_com_object(memory, &clsid_text, IID_IUNKNOWN, 0)
            {
                write_guest_pointer(memory, results, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
        }
        if results != 0 {
            write_guest_pointer(memory, results, 0, self.guest_arch).ok();
        }
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
        // CoInstall(pServerInfo, pclsid, punkOuter, dwClsCtx, pvReserved,
        // dwFlags, pFile, pPath, pbc, pProgress, ppv) — the in-place
        // installation of a COM server: the runtime's class-object table
        // registers the CLSID, so the install succeeds.
        let _server = guest_call_arg(state, memory, 0)?;
        let _clsid = guest_call_arg(state, memory, 1)?;
        let _outer = guest_call_arg(state, memory, 2)?;
        let _context = guest_call_arg_u32(state, memory, 3)?;
        let _reserved = guest_call_arg(state, memory, 4)?;
        let _flags = guest_call_arg_u32(state, memory, 5)?;
        let _file = guest_call_arg(state, memory, 6)?;
        let _path = guest_call_arg(state, memory, 7)?;
        let _bind_ctx = guest_call_arg(state, memory, 8)?;
        let _progress = guest_call_arg(state, memory, 9)?;
        let out = guest_call_arg(state, memory, 10)?;
        let clsid_bytes = memory.read_bytes(_clsid, 16).unwrap_or_default();
        if clsid_bytes.iter().any(|b| *b != 0) {
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(&clsid_bytes);
            let clsid_text = Self::guid_bytes_to_string(&raw);
            if let Ok(factory) = self.alloc_com_factory_object(memory, &clsid_text) {
                if out != 0 {
                    write_guest_pointer(memory, out, factory, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
        }
        state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG));
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

    // ── The COM interface method surface (vtable thunks) ────────────────────

    /// Dispatch one method of a runtime COM interface vtable.  Every object
    /// built by the `alloc_com_*` allocators carries these thunks; `this`
    /// (argument 0) identifies the guest object and its state map.
    pub(crate) fn dispatch_com_method(
        &mut self,
        method: ComMethod,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match method {
            ComMethod::QueryInterface => self.com_query_interface_method(state, memory),
            // IStream / ISequentialStream
            ComMethod::StreamRead => self.com_stream_read(state, memory),
            ComMethod::StreamWrite => self.com_stream_write(state, memory),
            ComMethod::StreamSeek => self.com_stream_seek(state, memory),
            ComMethod::StreamSetSize => self.com_stream_set_size(state, memory),
            ComMethod::StreamCopyTo => self.com_stream_copy_to(state, memory),
            ComMethod::StreamCommit => self.com_stream_commit(state, memory),
            ComMethod::StreamRevert => self.com_stream_revert(state, memory),
            ComMethod::StreamLockRegion => self.com_stream_lock_region(state, memory),
            ComMethod::StreamUnlockRegion => self.com_stream_unlock_region(state, memory),
            ComMethod::StreamStat => self.com_stream_stat(state, memory),
            ComMethod::StreamClone => self.com_stream_clone(state, memory),
            // IStorage
            ComMethod::StorageCreateStream => self.com_storage_create_stream(state, memory),
            ComMethod::StorageOpenStream => self.com_storage_open_stream(state, memory),
            ComMethod::StorageCreateStorage => self.com_storage_create_storage(state, memory),
            ComMethod::StorageOpenStorage => self.com_storage_open_storage(state, memory),
            ComMethod::StorageCopyTo => self.com_storage_copy_to(state, memory),
            ComMethod::StorageMoveElement => self.com_storage_move_element(state, memory),
            ComMethod::StorageCommit => self.com_storage_commit(state, memory),
            ComMethod::StorageRevert => self.com_storage_revert(state, memory),
            ComMethod::StorageEnumElements => self.com_storage_enum_elements(state, memory),
            ComMethod::StorageDestroyElement => self.com_storage_destroy_element(state, memory),
            ComMethod::StorageRenameElement => self.com_storage_rename_element(state, memory),
            ComMethod::StorageSetElementTimes => self.com_storage_set_element_times(state, memory),
            ComMethod::StorageSetClass => self.com_storage_set_class(state, memory),
            ComMethod::StorageSetStateBits => self.com_storage_set_state_bits(state, memory),
            ComMethod::StorageStat => self.com_storage_stat(state, memory),
            // IConnectionPointContainer
            ComMethod::EnumConnectionPoints => {
                self.com_container_enum_connection_points(state, memory)
            }
            ComMethod::FindConnectionPoint => {
                self.com_container_find_connection_point(state, memory)
            }
            // IConnectionPoint
            ComMethod::GetConnectionInterface => {
                self.com_connection_point_get_interface(state, memory)
            }
            ComMethod::GetConnectionPointContainer => {
                self.com_connection_point_get_container(state, memory)
            }
            ComMethod::Advise => self.com_connection_point_advise(state, memory),
            ComMethod::Unadvise => self.com_connection_point_unadvise(state, memory),
            ComMethod::EnumConnections => self.com_connection_point_enum_connections(state, memory),
            // IEnum{ConnectionPoints,Connections} and IEnumSTATSTG share the
            // snapshot-enumerator implementation.
            ComMethod::EnumNext => self.com_enum_next(state, memory),
            ComMethod::EnumSkip => self.com_enum_skip(state, memory),
            ComMethod::EnumReset => self.com_enum_reset(state, memory),
            ComMethod::EnumClone => self.com_enum_clone(state, memory),
            // IDispatch
            ComMethod::DispatchGetTypeInfoCount => {
                self.com_dispatch_get_type_info_count(state, memory)
            }
            ComMethod::DispatchGetTypeInfo => self.com_dispatch_get_type_info(state, memory),
            ComMethod::DispatchGetIDsOfNames => {
                self.com_dispatch_get_ids_of_names_impl(state, memory)
            }
            ComMethod::DispatchInvoke => self.com_dispatch_invoke_impl(state, memory),
            // ITypeInfo
            ComMethod::TypeInfoGetTypeAttr => self.com_type_info_get_type_attr(state, memory),
            ComMethod::TypeInfoGetTypeComp => self.com_type_info_get_type_comp(state, memory),
            ComMethod::TypeInfoGetFuncDesc => self.com_type_info_get_func_desc(state, memory),
            ComMethod::TypeInfoGetVarDesc => self.com_type_info_get_var_desc(state, memory),
            ComMethod::TypeInfoGetNames => self.com_type_info_get_names(state, memory),
            ComMethod::TypeInfoGetRefTypeOfImplType => {
                self.com_type_info_get_ref_type_of_impl_type(state, memory)
            }
            ComMethod::TypeInfoGetImplTypeFlags => {
                self.com_type_info_get_impl_type_flags(state, memory)
            }
            ComMethod::TypeInfoGetIDsOfNames => self.com_type_info_get_ids_of_names(state, memory),
            ComMethod::TypeInfoInvoke => self.com_type_info_invoke(state, memory),
            ComMethod::TypeInfoGetDocumentation => {
                self.com_type_info_get_documentation(state, memory)
            }
            ComMethod::TypeInfoGetDllEntry => self.com_type_info_get_dll_entry(state, memory),
            ComMethod::TypeInfoGetRefTypeInfo => {
                self.com_type_info_get_ref_type_info(state, memory)
            }
            ComMethod::TypeInfoAddressOfMember => {
                self.com_type_info_address_of_member(state, memory)
            }
            ComMethod::TypeInfoCreateInstance => self.com_type_info_create_instance(state, memory),
            ComMethod::TypeInfoGetMops => self.com_type_info_get_mops(state, memory),
            ComMethod::TypeInfoGetContainingTypeLib => {
                self.com_type_info_get_containing_type_lib(state, memory)
            }
            ComMethod::TypeLibGetLibAttr => self.com_type_lib_get_lib_attr(state, memory),
            ComMethod::TypeLibReleaseTLibAttr => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            ComMethod::TypeLibGetTypeInfoCount => {
                self.com_type_lib_get_type_info_count(state, memory)
            }
            ComMethod::TypeLibGetTypeInfo => self.com_type_lib_get_type_info(state, memory),
            ComMethod::TypeLibGetTypeInfoOfGuid => {
                self.com_type_lib_get_type_info_of_guid(state, memory)
            }
            ComMethod::TypeLibGetTypeComp => self.com_type_lib_get_type_comp(state, memory),
            ComMethod::TypeLibUnsupported => self.com_type_info_unsupported(state, memory),
            ComMethod::TypeCompBind => self.com_type_comp_bind(state, memory, false),
            ComMethod::TypeCompBindType => self.com_type_comp_bind(state, memory, true),
            ComMethod::TypeInfoReleaseTypeAttr
            | ComMethod::TypeInfoReleaseFuncDesc
            | ComMethod::TypeInfoReleaseVarDesc => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            ComMethod::TypeInfoUnsupported => self.com_type_info_unsupported(state, memory),
            // The automation server's dual interface.
            ComMethod::ServerGetValue => self.com_server_get_value(state, memory),
            ComMethod::ServerPutValue => self.com_server_put_value(state, memory),
            ComMethod::ServerGetName => self.com_server_get_name(state, memory),
            ComMethod::ServerPutName => self.com_server_put_name(state, memory),
            ComMethod::ServerGetCount => self.com_server_get_count(state, memory),
            ComMethod::ServerAdd => self.com_server_add(state, memory),
            ComMethod::ServerReset => self.com_server_reset(state, memory),
            ComMethod::ServerFireValueChanged => self.com_server_fire_value_changed(state, memory),
            // The runtime's modeled event sink.
            ComMethod::SinkInvoke => self.com_sink_invoke(state, memory),
        }
    }

    /// Read one guest call argument as a signed i32.
    fn com_arg_i32(&self, state: &CpuState, memory: &MemoryImage, index: usize) -> i32 {
        guest_call_arg(state, memory, index).unwrap_or(0) as u32 as i32
    }

    /// Read one guest call argument as a signed 64-bit value: x86 stdcall
    /// passes LARGE_INTEGER by value across two 4-byte stack slots; x64 uses
    /// the register/stack convention.
    fn com_arg_i64(&self, state: &CpuState, memory: &MemoryImage, index: usize) -> i64 {
        match self.guest_arch {
            GuestArch::X86 => memory
                .read_u64(state.get(Register::Rsp) + (index as u64 * 4))
                .unwrap_or(0) as i64,
            GuestArch::X64 => match index {
                0 => state.get(Register::Rcx) as i64,
                1 => state.get(Register::Rdx) as i64,
                2 => state.get(Register::R8) as i64,
                3 => state.get(Register::R9) as i64,
                _ => memory
                    .read_u64(state.get(Register::Rsp) + 0x20 + ((index - 4) as u64 * 8))
                    .unwrap_or(0) as i64,
            },
        }
    }

    fn com_variant_size(&self) -> u64 {
        match self.guest_arch {
            GuestArch::X86 => 16,
            GuestArch::X64 => 24,
        }
    }

    fn com_variant_data_offset(&self) -> u64 {
        match self.guest_arch {
            GuestArch::X86 => 8,
            GuestArch::X64 => 16,
        }
    }

    /// Allocate a guest BSTR (the CoTaskMem/SysAllocString layout) holding
    /// `text` and return the data pointer.
    pub(crate) fn alloc_com_bstr(
        &mut self,
        memory: &mut MemoryImage,
        text: &str,
    ) -> AppResult<u64> {
        let units: Vec<u16> = text.encode_utf16().collect();
        let len = (units.len() * 2) as u32;
        let base = self.alloc_heap(memory, units.len() * 2 + 2, false)?;
        self.com_task_allocations.insert(base, units.len() * 2 + 2);
        write_u32(memory, base, len + 2);
        for (index, unit) in units.iter().enumerate() {
            memory.write_u16(base + 4 + (index as u64 * 2), *unit);
        }
        memory.write_u16(base + 4 + (units.len() as u64 * 2), 0);
        Ok(base + 4)
    }

    /// Write a VT_EMPTY guest VARIANT.
    fn write_variant_empty(&self, memory: &mut MemoryImage, ptr: u64) {
        if ptr == 0 {
            return;
        }
        let size = self.com_variant_size() as usize;
        let _ = memory.map_bytes(ptr, &vec![0_u8; size]);
    }

    fn write_variant_i4(&self, memory: &mut MemoryImage, ptr: u64, value: i32) {
        self.write_variant_empty(memory, ptr);
        memory.write_u16(ptr, 3); // VT_I4
        memory.write_u32(ptr + self.com_variant_data_offset(), value as u32);
    }

    fn write_variant_bool(&self, memory: &mut MemoryImage, ptr: u64, value: bool) {
        self.write_variant_empty(memory, ptr);
        memory.write_u16(ptr, 11); // VT_BOOL
        memory.write_u16(
            ptr + self.com_variant_data_offset(),
            if value { 0xffff } else { 0 },
        );
    }

    fn write_variant_bstr(&self, memory: &mut MemoryImage, ptr: u64, bstr: u64) {
        self.write_variant_empty(memory, ptr);
        memory.write_u16(ptr, 8); // VT_BSTR
        write_guest_pointer(
            memory,
            ptr + self.com_variant_data_offset(),
            bstr,
            self.guest_arch,
        )
        .ok();
    }

    fn write_variant_object(&self, memory: &mut MemoryImage, ptr: u64, object: u64) {
        self.write_variant_empty(memory, ptr);
        memory.write_u16(ptr, 9); // VT_DISPATCH
        write_guest_pointer(
            memory,
            ptr + self.com_variant_data_offset(),
            object,
            self.guest_arch,
        )
        .ok();
    }

    fn write_variant_double(&self, memory: &mut MemoryImage, ptr: u64, value: f64) {
        self.write_variant_empty(memory, ptr);
        memory.write_u16(ptr, 5); // VT_R8
        memory.write_u64(ptr + self.com_variant_data_offset(), value.to_bits());
    }

    fn write_variant_value(
        &mut self,
        memory: &mut MemoryImage,
        ptr: u64,
        value: &ComValue,
    ) -> AppResult<()> {
        if ptr == 0 {
            return Ok(());
        }
        match value {
            ComValue::Empty => self.write_variant_empty(memory, ptr),
            ComValue::I4(number) => self.write_variant_i4(memory, ptr, *number),
            ComValue::Bool(flag) => self.write_variant_bool(memory, ptr, *flag),
            ComValue::Double(number) => self.write_variant_double(memory, ptr, *number),
            ComValue::Bstr(text) => {
                let bstr = self.alloc_com_bstr(memory, text)?;
                self.write_variant_bstr(memory, ptr, bstr);
            }
            ComValue::Object(object) => self.write_variant_object(memory, ptr, *object),
        }
        Ok(())
    }

    /// Read a guest VARIANT into a typed `ComValue`; `None` for a VARIANT
    /// type the automation surface does not model.
    fn read_variant_value(
        &mut self,
        memory: &mut MemoryImage,
        ptr: u64,
    ) -> AppResult<Option<ComValue>> {
        if ptr == 0 {
            return Ok(None);
        }
        let vt = memory.read_u16(ptr).unwrap_or(0);
        let offset = self.com_variant_data_offset();
        Ok(match vt {
            0 | 1 => Some(ComValue::Empty), // VT_EMPTY / VT_NULL
            2 => Some(ComValue::I4(
                memory.read_u16(ptr + offset).unwrap_or(0) as i16 as i32,
            )), // VT_I2
            3 | 22 => Some(ComValue::I4(
                memory.read_u32(ptr + offset).unwrap_or(0) as i32
            )), // VT_I4 / VT_INT
            11 => Some(ComValue::Bool(
                memory.read_u16(ptr + offset).unwrap_or(0) != 0,
            )),
            5 => Some(ComValue::Double(f64::from_bits(
                memory.read_u64(ptr + offset).unwrap_or(0),
            ))),
            8 | 31 => {
                let bstr = read_guest_pointer(memory, ptr + offset, self.guest_arch).unwrap_or(0);
                Some(ComValue::Bstr(
                    read_utf16_string(memory, bstr).unwrap_or_default(),
                ))
            }
            9 | 13 => {
                let object = read_guest_pointer(memory, ptr + offset, self.guest_arch).unwrap_or(0);
                Some(ComValue::Object(object))
            }
            _ => None,
        })
    }

    fn write_statstg(
        &mut self,
        memory: &mut MemoryImage,
        ptr: u64,
        name: &str,
        kind: u32,
        size: u64,
        mode: u32,
        locks_supported: u32,
        clsid: Option<[u8; 16]>,
    ) -> AppResult<()> {
        if ptr == 0 {
            return Ok(());
        }
        let name_ptr = if name.is_empty() {
            0
        } else {
            self.alloc_utf16_string(memory, name)?
        };
        let ticks = guest_filetime_ticks(&self.win32);
        match self.guest_arch {
            GuestArch::X86 => {
                memory.map_bytes(ptr, &[0_u8; 72]);
                write_u32(memory, ptr, name_ptr as u32);
                write_u32(memory, ptr + 4, kind);
                write_u64(memory, ptr + 8, size);
                write_u32(memory, ptr + 16, (ticks & 0xFFFF_FFFF) as u32);
                write_u32(memory, ptr + 20, (ticks >> 32) as u32);
                write_u32(memory, ptr + 24, (ticks & 0xFFFF_FFFF) as u32);
                write_u32(memory, ptr + 28, (ticks >> 32) as u32);
                write_u32(memory, ptr + 32, (ticks & 0xFFFF_FFFF) as u32);
                write_u32(memory, ptr + 36, (ticks >> 32) as u32);
                write_u32(memory, ptr + 40, mode);
                write_u32(memory, ptr + 44, locks_supported);
                if let Some(bytes) = clsid {
                    for (index, byte) in bytes.iter().enumerate() {
                        memory.write_u8(ptr + 48 + index as u64, *byte);
                    }
                }
                write_u32(memory, ptr + 64, 0);
                write_u32(memory, ptr + 68, 0);
            }
            GuestArch::X64 => {
                memory.map_bytes(ptr, &[0_u8; 80]);
                write_u64(memory, ptr, name_ptr);
                write_u32(memory, ptr + 8, kind);
                write_u64(memory, ptr + 16, size);
                write_u32(memory, ptr + 24, (ticks & 0xFFFF_FFFF) as u32);
                write_u32(memory, ptr + 28, (ticks >> 32) as u32);
                write_u32(memory, ptr + 32, (ticks & 0xFFFF_FFFF) as u32);
                write_u32(memory, ptr + 36, (ticks >> 32) as u32);
                write_u32(memory, ptr + 40, (ticks & 0xFFFF_FFFF) as u32);
                write_u32(memory, ptr + 44, (ticks >> 32) as u32);
                write_u32(memory, ptr + 48, mode);
                write_u32(memory, ptr + 52, locks_supported);
                if let Some(bytes) = clsid {
                    for (index, byte) in bytes.iter().enumerate() {
                        memory.write_u8(ptr + 56 + index as u64, *byte);
                    }
                }
                write_u32(memory, ptr + 72, 0);
                write_u32(memory, ptr + 76, 0);
            }
        }
        Ok(())
    }

    // ── IUnknown ────────────────────────────────────────────────────────────

    fn com_query_interface_method(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        if riid_ptr == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let iid: [u8; 16] =
            std::array::from_fn(|index| memory.read_u8(riid_ptr + index as u64).unwrap_or(0));
        let kind = self.guest_object_kind(this).ok();
        let mut interface = 0_u64;
        let mut supported = false;
        if iid == COM_IID_IUNKNOWN {
            supported = kind.is_some();
            interface = this;
        } else if let Some(kind) = kind {
            supported = match kind {
                GuestObjectKind::ComStream => {
                    if iid == COM_IID_ISTREAM || iid == COM_IID_ISEQUENTIALSTREAM {
                        interface = this;
                        true
                    } else {
                        false
                    }
                }
                GuestObjectKind::ComStorage => {
                    if iid == COM_IID_ISTORAGE {
                        interface = this;
                        true
                    } else {
                        false
                    }
                }
                GuestObjectKind::ComFileMoniker | GuestObjectKind::UrlMoniker => {
                    if iid == COM_IID_IMONIKER {
                        interface = this;
                        true
                    } else {
                        false
                    }
                }
                GuestObjectKind::ComEnumVariant => {
                    if iid == COM_IID_IENUMVARIANT {
                        interface = this;
                        true
                    } else {
                        false
                    }
                }
                GuestObjectKind::ComBindCtx => {
                    if iid == COM_IID_IBINDCTX {
                        interface = this;
                        true
                    } else {
                        false
                    }
                }
                GuestObjectKind::ComConnectionPoint => {
                    let is_container = self
                        .com_connection_points
                        .get(&this)
                        .map(|entry| entry.is_container)
                        .unwrap_or(false);
                    if is_container && iid == COM_IID_ICONNECTIONPOINTCONTAINER {
                        interface = this;
                        true
                    } else if !is_container && iid == COM_IID_ICONNECTIONPOINT {
                        interface = this;
                        true
                    } else {
                        false
                    }
                }
                GuestObjectKind::ComTypeInfo => {
                    let marker = self
                        .com_type_infos
                        .get(&this)
                        .map(|info| info.table.as_str())
                        .unwrap_or("");
                    let wanted = if marker == COM_TYPELIB_MARKER {
                        COM_IID_ITYPELIB
                    } else if marker.starts_with(COM_TYPECOMP_MARKER) {
                        COM_IID_ITYPECOMP
                    } else {
                        COM_IID_ITYPEINFO
                    };
                    if iid == wanted {
                        interface = this;
                        true
                    } else {
                        false
                    }
                }
                GuestObjectKind::ComDispatch => {
                    if iid == COM_IID_IDISPATCH {
                        interface = this;
                        true
                    } else if iid == COM_IID_ICONNECTIONPOINTCONTAINER
                        && self
                            .com_servers
                            .get(&this)
                            .and_then(|server| com_dispatch_table(&server.table))
                            .is_some()
                    {
                        self.alloc_com_connection_point_container(memory, this)?;
                        interface = self
                            .com_servers
                            .get(&this)
                            .map(|server| server.container)
                            .unwrap_or(0);
                        interface != 0
                    } else {
                        false
                    }
                }
                _ => false,
            };
        }
        if supported && interface != 0 {
            self.add_ref_guest_object(interface)?;
            write_guest_pointer(memory, out, interface, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    // ── IStream / ISequentialStream ─────────────────────────────────────────

    fn com_stream_read(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)? as usize;
        let read_out = guest_call_arg(state, memory, 3)?;
        if count > 0 && buffer == 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let Some(stream) = self.com_streams.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let position = stream.position as usize;
        let available = stream.data.len().saturating_sub(position);
        let to_read = count.min(available);
        if to_read > 0 {
            let bytes = stream.data[position..position + to_read].to_vec();
            memory.map_bytes(buffer, &bytes);
        }
        if let Some(stream) = self.com_streams.get_mut(&this) {
            stream.position = (position + to_read) as u64;
        }
        if read_out != 0 {
            write_u32(memory, read_out, to_read as u32);
        }
        state.set(
            Register::Rax,
            if to_read == count {
                u64::from(S_OK)
            } else {
                u64::from(S_FALSE)
            },
        );
        Ok(())
    }

    fn com_stream_write(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)? as usize;
        let written_out = guest_call_arg(state, memory, 3)?;
        if count > 0 && buffer == 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let Some(stream) = self.com_streams.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let position = stream.position as usize;
        let bytes = if count > 0 {
            memory.read_bytes(buffer, count).unwrap_or_default()
        } else {
            Vec::new()
        };
        if let Some(stream) = self.com_streams.get_mut(&this) {
            let end = position + bytes.len();
            if stream.data.len() < end {
                stream.data.resize(end, 0);
            }
            stream.data[position..end].copy_from_slice(&bytes);
            stream.position = end as u64;
            stream.dirty = true;
        }
        if written_out != 0 {
            write_u32(memory, written_out, bytes.len() as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_seek(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let movement = self.com_arg_i64(state, memory, 1);
        let (origin_index, new_index) = match self.guest_arch {
            GuestArch::X86 => (3, 4),
            GuestArch::X64 => (2, 3),
        };
        let origin = guest_call_arg(state, memory, origin_index)? as u32;
        let new_out = guest_call_arg(state, memory, new_index)?;
        let Some(stream) = self.com_streams.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let base = match origin {
            0 => 0_i128,                    // STREAM_SEEK_SET
            1 => stream.position as i128,   // STREAM_SEEK_CUR
            2 => stream.data.len() as i128, // STREAM_SEEK_END
            _ => {
                state.set(Register::Rax, u64::from(STG_E_INVALIDFUNCTION));
                return Ok(());
            }
        };
        let target = base + movement as i128;
        if target < 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDFUNCTION));
            return Ok(());
        }
        if let Some(stream) = self.com_streams.get_mut(&this) {
            stream.position = target as u64;
        }
        if new_out != 0 {
            write_u64(memory, new_out, target as u64);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_set_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let new_size = self.com_arg_i64(state, memory, 1);
        if new_size < 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDFUNCTION));
            return Ok(());
        }
        let Some(stream) = self.com_streams.get_mut(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        stream.data.resize(new_size as usize, 0);
        stream.dirty = true;
        if stream.position > new_size as u64 {
            stream.position = new_size as u64;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_copy_to(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let destination = guest_call_arg(state, memory, 1)?;
        let count = self.com_arg_i64(state, memory, 2);
        let (read_index, written_index) = match self.guest_arch {
            GuestArch::X86 => (4, 5),
            GuestArch::X64 => (3, 4),
        };
        let read_out = guest_call_arg(state, memory, read_index)?;
        let written_out = guest_call_arg(state, memory, written_index)?;
        if count < 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDFUNCTION));
            return Ok(());
        }
        let Some(source) = self.com_streams.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let start = source.position as usize;
        let available = source.data.len().saturating_sub(start);
        let to_copy = (count as usize).min(available);
        let bytes = source.data[start..start + to_copy].to_vec();
        let Some(destination_stream) = self.com_streams.get_mut(&destination) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let destination_position = destination_stream.position as usize;
        let end = destination_position + to_copy;
        if destination_stream.data.len() < end {
            destination_stream.data.resize(end, 0);
        }
        destination_stream.data[destination_position..end].copy_from_slice(&bytes);
        destination_stream.position = end as u64;
        destination_stream.dirty = true;
        if let Some(source) = self.com_streams.get_mut(&this) {
            source.position = (start + to_copy) as u64;
        }
        if read_out != 0 {
            write_u32(memory, read_out, to_copy as u32);
        }
        if written_out != 0 {
            write_u32(memory, written_out, to_copy as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_commit(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(stream) = self.com_streams.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if let (Some(path), true) = (&stream.host_path, stream.dirty) {
            let path = path.clone();
            let bytes = stream.data.clone();
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&path, &bytes).is_err() {
                state.set(Register::Rax, u64::from(STG_E_ACCESSDENIED));
                return Ok(());
            }
            if let Some(stream) = self.com_streams.get_mut(&this) {
                stream.dirty = false;
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_revert(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(stream) = self.com_streams.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if let Some(path) = stream.host_path.clone() {
            let bytes = std::fs::read(&path).unwrap_or_default();
            if let Some(stream) = self.com_streams.get_mut(&this) {
                stream.data = bytes;
                stream.dirty = false;
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_lock_region(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let offset = self.com_arg_i64(state, memory, 1);
        let (size_index, type_index) = match self.guest_arch {
            GuestArch::X86 => (3, 5),
            GuestArch::X64 => (2, 3),
        };
        let size = self.com_arg_i64(state, memory, size_index);
        let lock_type = guest_call_arg(state, memory, type_index)? as u32;
        if offset < 0 || size < 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDFUNCTION));
            return Ok(());
        }
        let Some(stream) = self.com_streams.get_mut(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let lock = crate::runtime::state::ComStreamLock {
            offset: offset as u64,
            size: size as u64,
            lock_type,
        };
        if stream
            .locks
            .iter()
            .any(|held| held.offset == lock.offset && held.size == lock.size)
        {
            // Overlapping/duplicate regions are rejected (STG_E_INVALIDFUNCTION),
            // mirroring the compound-file lock-region contract.
            state.set(Register::Rax, u64::from(STG_E_INVALIDFUNCTION));
            return Ok(());
        }
        stream.locks.push(lock);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_unlock_region(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let offset = self.com_arg_i64(state, memory, 1);
        let (size_index, type_index) = match self.guest_arch {
            GuestArch::X86 => (3, 5),
            GuestArch::X64 => (2, 3),
        };
        let size = self.com_arg_i64(state, memory, size_index);
        let lock_type = guest_call_arg(state, memory, type_index)? as u32;
        let Some(stream) = self.com_streams.get_mut(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let before = stream.locks.len();
        stream.locks.retain(|held| {
            !(held.offset == offset.max(0) as u64
                && held.size == size.max(0) as u64
                && held.lock_type == lock_type)
        });
        state.set(
            Register::Rax,
            if stream.locks.len() == before {
                u64::from(STG_E_INVALIDFUNCTION)
            } else {
                u64::from(S_OK)
            },
        );
        Ok(())
    }

    fn com_stream_stat(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stat_ptr = guest_call_arg(state, memory, 1)?;
        let flags = guest_call_arg(state, memory, 2)? as u32;
        let Some(stream) = self.com_streams.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let name = if flags & STATFLAG_NONAME != 0 {
            String::new()
        } else {
            stream.name.clone()
        };
        let size = stream.data.len() as u64;
        self.write_statstg(memory, stat_ptr, &name, 2, size, 2, 3, None)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_clone(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(stream) = self.com_streams.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let clone = self.alloc_com_stream_object(
            memory,
            stream.data.clone(),
            &stream.name,
            stream.host_path.clone(),
        )?;
        if let Some(clone_stream) = self.com_streams.get_mut(&clone) {
            clone_stream.position = stream.position;
            clone_stream.locks = stream.locks.clone();
        }
        if out != 0 {
            write_guest_pointer(memory, out, clone, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IStorage ────────────────────────────────────────────────────────────

    fn com_storage_element_path(&self, storage: u64, name: &str) -> Option<String> {
        let state = self.com_storages.get(&storage)?;
        let directory = state.host_dir.as_ref()?;
        if directory.starts_with(COM_CFB_PREFIX) {
            return None;
        }
        Some(format!("{directory}/{name}"))
    }

    fn com_storage_compound_path(&self, storage: u64) -> Option<String> {
        self.com_storages
            .get(&storage)
            .and_then(|state| state.host_dir.as_deref())
            .and_then(|directory| directory.strip_prefix(COM_CFB_PREFIX))
            .map(|rest| rest.split('\u{1}').next().unwrap_or_default().to_string())
    }

    /// The path of a compound-backed storage inside its file (empty for the
    /// root storage).
    fn com_storage_compound_relative(&self, storage: u64) -> Option<Vec<String>> {
        let directory = self.com_storages.get(&storage)?.host_dir.as_deref()?;
        let rest = directory.strip_prefix(COM_CFB_PREFIX)?;
        Some(
            rest.split('\u{1}')
                .skip(1)
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect(),
        )
    }

    /// The host directory for a child element: a CFB path component for
    /// compound-backed parents, a nested directory otherwise.
    fn com_storage_child_host_dir(&self, storage: u64, name: &str) -> Option<String> {
        let directory = self.com_storages.get(&storage)?.host_dir.as_ref()?;
        if directory.starts_with(COM_CFB_PREFIX) {
            Some(format!("{directory}\u{1}{name}"))
        } else {
            Some(format!("{directory}/{name}"))
        }
    }

    fn com_compound_file(
        path: &str,
    ) -> std::result::Result<crate::runtime::dispatch::msi::CompoundFile, u32> {
        let bytes = std::fs::read(path).map_err(|_| STG_E_FILENOTFOUND)?;
        crate::runtime::dispatch::msi::CompoundFile::parse(bytes).map_err(|_| STG_E_INVALIDHEADER)
    }

    fn com_storage_tree_timestamp() -> u64 {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (duration.as_secs() + 11_644_473_600) * 10_000_000
            + u64::from(duration.subsec_nanos() / 100)
    }

    /// Rebuild one storage's in-memory view from the directory tree of a
    /// parsed compound file.
    fn com_storage_load_compound_children(
        &mut self,
        memory: &mut MemoryImage,
        storage: u64,
        compound: &crate::runtime::dispatch::msi::CompoundFile,
        path: &str,
    ) -> AppResult<()> {
        for child in compound.children(path).unwrap_or_default() {
            let name = child.decoded_name();
            if name.is_empty() {
                continue;
            }
            match child.kind {
                2 => {
                    if let Some(data) = compound.stream_at(&format!("{path}/{name}")) {
                        if let Some(state) = self.com_storages.get_mut(&storage) {
                            state.streams.insert(name.clone(), data);
                            if !state.element_order.contains(&name) {
                                state.element_order.push(name.clone());
                            }
                        }
                    }
                }
                1 => {
                    let host_dir = self.com_storage_child_host_dir(storage, &name);
                    let child_object = self.alloc_com_storage_object(memory, host_dir, &name, 0)?;
                    if child.clsid.iter().any(|byte| *byte != 0)
                        && let Some(state) = self.com_storages.get_mut(&child_object)
                    {
                        state.clsid = Some(child.clsid);
                    }
                    if let Some(state) = self.com_storages.get_mut(&storage) {
                        state.child_storages.insert(name.clone(), child_object);
                        if !state.element_order.contains(&name) {
                            state.element_order.push(name.clone());
                        }
                    }
                    self.com_storage_load_compound_children(
                        memory,
                        child_object,
                        compound,
                        &format!("{path}/{name}"),
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Reload a storage subtree from disk in place.  Live child storage and
    /// stream objects keep their identity; their bytes and dirty flags are
    /// reset to the committed file state.
    fn com_storage_reload_compound_children(
        &mut self,
        memory: &mut MemoryImage,
        storage: u64,
        compound: &crate::runtime::dispatch::msi::CompoundFile,
        path: &str,
    ) -> AppResult<()> {
        let children = compound.children(path).unwrap_or_default();
        let existing_children = self
            .com_storages
            .get(&storage)
            .map(|state| state.child_storages.clone())
            .unwrap_or_default();
        let existing_streams = self
            .com_storages
            .get(&storage)
            .map(|state| state.stream_objects.clone())
            .unwrap_or_default();

        let mut streams = std::collections::HashMap::new();
        for child in &children {
            if child.kind != 2 {
                continue;
            }
            let name = child.decoded_name();
            if let Some(data) = compound.stream_at(&format!("{path}/{name}")) {
                streams.insert(name, data);
            }
        }
        let mut surviving_streams = std::collections::HashMap::new();
        for (name, object) in &existing_streams {
            if streams.contains_key(name) {
                surviving_streams.insert(name.clone(), *object);
            }
        }
        if let Some(state) = self.com_storages.get_mut(&storage) {
            state.streams = streams.clone();
            state.stream_objects = surviving_streams.clone();
            state.child_storages.clear();
            state.element_order.clear();
        }
        for (name, data) in &streams {
            if let Some(object) = surviving_streams.get(name)
                && let Some(stream) = self.com_streams.get_mut(object)
            {
                stream.data = data.clone();
                stream.position = stream.position.min(data.len() as u64);
                stream.dirty = false;
            }
        }

        for child in children {
            let name = child.decoded_name();
            match child.kind {
                2 => {
                    if let Some(state) = self.com_storages.get_mut(&storage)
                        && !state.element_order.contains(&name)
                    {
                        state.element_order.push(name);
                    }
                }
                1 => {
                    let host_dir = self.com_storage_child_host_dir(storage, &name);
                    let reused = existing_children
                        .get(&name)
                        .copied()
                        .filter(|object| self.com_storages.contains_key(object));
                    let child_object = if let Some(object) = reused {
                        object
                    } else {
                        self.alloc_com_storage_object(memory, host_dir.clone(), &name, 0)?
                    };
                    if let Some(state) = self.com_storages.get_mut(&child_object) {
                        state.name = name.clone();
                        if host_dir.is_some() {
                            state.host_dir = host_dir;
                        }
                        if child.clsid.iter().any(|byte| *byte != 0) {
                            state.clsid = Some(child.clsid);
                        }
                    }
                    if let Some(state) = self.com_storages.get_mut(&storage) {
                        state.child_storages.insert(name.clone(), child_object);
                        if !state.element_order.contains(&name) {
                            state.element_order.push(name.clone());
                        }
                    }
                    self.com_storage_reload_compound_children(
                        memory,
                        child_object,
                        compound,
                        &format!("{path}/{name}"),
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Serialize a live storage subtree, folding dirty stream objects into
    /// their storage's stream map so the committed tree is current.
    fn com_storage_build_compound_tree(
        &mut self,
        storage: u64,
    ) -> crate::runtime::dispatch::msi::CompoundTree {
        use crate::runtime::dispatch::msi::{CompoundTree, CompoundTreeChild};
        let Some(state) = self.com_storages.get(&storage).cloned() else {
            return CompoundTree::default();
        };
        let mut names = state.element_order.clone();
        for name in state.streams.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        for name in state.child_storages.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        let mut children = Vec::new();
        for name in names {
            let live = state
                .stream_objects
                .get(&name)
                .and_then(|stream| self.com_streams.get(stream))
                .map(|stream| stream.data.clone());
            if let Some(data) = live.or_else(|| state.streams.get(&name).cloned()) {
                if let Some(entry) = self.com_storages.get_mut(&storage) {
                    entry.streams.insert(name.clone(), data.clone());
                }
                children.push(CompoundTreeChild::Stream {
                    name,
                    data,
                    created: 0,
                    modified: 0,
                });
            } else if let Some(child) = state.child_storages.get(&name).copied() {
                let mut child_tree = self.com_storage_build_compound_tree(child);
                child_tree.name = name.clone();
                children.push(CompoundTreeChild::Storage(child_tree));
            }
        }
        let timestamp = Self::com_storage_tree_timestamp();
        CompoundTree {
            name: state.name.clone(),
            clsid: state.clsid,
            created: timestamp,
            modified: timestamp,
            children,
        }
    }

    fn com_storage_compound_root(&self, storage: u64) -> Option<u64> {
        if self.com_storage_compound_relative(storage)?.is_empty() {
            return Some(storage);
        }
        let path = self.com_storage_compound_path(storage)?;
        let root_dir = format!("{COM_CFB_PREFIX}{path}");
        let mut first = None;
        for (object, state) in &self.com_storages {
            if state.host_dir.as_deref() != Some(root_dir.as_str()) {
                continue;
            }
            first.get_or_insert(*object);
            if self.com_storage_subtree_objects(*object).contains(&storage) {
                return Some(*object);
            }
        }
        first
    }

    fn com_storage_subtree_objects(&self, storage: u64) -> Vec<u64> {
        let mut seen = Vec::new();
        let mut stack = vec![storage];
        while let Some(current) = stack.pop() {
            if seen.contains(&current) {
                continue;
            }
            seen.push(current);
            if let Some(state) = self.com_storages.get(&current) {
                stack.extend(state.child_storages.values().copied());
            }
        }
        seen
    }

    fn com_storage_forget_subtree(&mut self, storage: u64) {
        let children: Vec<u64> = self
            .com_storages
            .get(&storage)
            .map(|state| state.child_storages.values().copied().collect())
            .unwrap_or_default();
        for child in children {
            self.com_storage_forget_subtree(child);
        }
        self.com_storages.remove(&storage);
    }

    fn com_storage_element_names(&self, storage: u64) -> Vec<String> {
        let Some(state) = self.com_storages.get(&storage) else {
            return Vec::new();
        };
        let mut names = state.element_order.clone();
        for name in state.streams.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        for name in state.child_storages.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }

    /// Deep-copy every element of `source` into `target`.  Collisions are
    /// detected before the first element is written.
    fn com_storage_copy_into(
        &mut self,
        memory: &mut MemoryImage,
        source: u64,
        target: u64,
    ) -> AppResult<u32> {
        let Some(source_state) = self.com_storages.get(&source).cloned() else {
            return Ok(STG_E_INVALIDPOINTER);
        };
        let Some(target_state) = self.com_storages.get(&target).cloned() else {
            return Ok(STG_E_INVALIDPOINTER);
        };
        let names = self.com_storage_element_names(source);
        for name in &names {
            if target_state.streams.contains_key(name)
                || target_state.child_storages.contains_key(name)
                || target_state.stream_objects.contains_key(name)
            {
                return Ok(STG_E_FILEALREADYEXISTS);
            }
        }
        for name in names {
            let live = source_state
                .stream_objects
                .get(&name)
                .and_then(|stream| self.com_streams.get(stream))
                .map(|stream| stream.data.clone());
            if let Some(data) = live.or_else(|| source_state.streams.get(&name).cloned()) {
                if let Some(entry) = self.com_storages.get_mut(&target) {
                    entry.streams.insert(name.clone(), data);
                    if !entry.element_order.contains(&name) {
                        entry.element_order.push(name.clone());
                    }
                }
            } else if let Some(child) = source_state.child_storages.get(&name).copied() {
                let host_dir = self.com_storage_child_host_dir(target, &name);
                let child_object = self.alloc_com_storage_object(memory, host_dir, &name, 0)?;
                if let Some(child_state) = self.com_storages.get(&child).cloned() {
                    if let Some(entry) = self.com_storages.get_mut(&child_object) {
                        entry.clsid = child_state.clsid;
                        entry.mode = child_state.mode;
                    }
                }
                if let Some(entry) = self.com_storages.get_mut(&target) {
                    entry.child_storages.insert(name.clone(), child_object);
                    if !entry.element_order.contains(&name) {
                        entry.element_order.push(name.clone());
                    }
                }
                let result = self.com_storage_copy_into(memory, child, child_object)?;
                if result != S_OK {
                    return Ok(result);
                }
            }
        }
        Ok(S_OK)
    }

    /// Create/open an IStorage over a real on-disk OLE compound file.
    /// `create` distinguishes StgCreateStorage (missing file is a new empty
    /// compound file) from StgOpenStorage (missing file is
    /// STG_E_FILENOTFOUND; a malformed header is STG_E_INVALIDHEADER).
    pub(crate) fn alloc_com_compound_storage(
        &mut self,
        memory: &mut MemoryImage,
        host_file: &str,
        mode: u32,
        create: bool,
    ) -> AppResult<std::result::Result<u64, u32>> {
        let path = std::path::Path::new(host_file);
        let compound = if path.exists() {
            match Self::com_compound_file(host_file) {
                Ok(compound) => Some(compound),
                Err(hr) => return Ok(Err(hr)),
            }
        } else if create {
            None
        } else {
            return Ok(Err(STG_E_FILENOTFOUND));
        };
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("storage")
            .to_string();
        let root_clsid = compound
            .as_ref()
            .and_then(|compound| compound.root_entry())
            .map(|entry| entry.clsid)
            .filter(|clsid| clsid.iter().any(|byte| *byte != 0));
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::StorageCreateStream),
            HostThunk::ComMethod(ComMethod::StorageOpenStream),
            HostThunk::ComMethod(ComMethod::StorageCreateStorage),
            HostThunk::ComMethod(ComMethod::StorageOpenStorage),
            HostThunk::ComMethod(ComMethod::StorageCopyTo),
            HostThunk::ComMethod(ComMethod::StorageMoveElement),
            HostThunk::ComMethod(ComMethod::StorageCommit),
            HostThunk::ComMethod(ComMethod::StorageRevert),
            HostThunk::ComMethod(ComMethod::StorageEnumElements),
            HostThunk::ComMethod(ComMethod::StorageDestroyElement),
            HostThunk::ComMethod(ComMethod::StorageRenameElement),
            HostThunk::ComMethod(ComMethod::StorageSetElementTimes),
            HostThunk::ComMethod(ComMethod::StorageSetClass),
            HostThunk::ComMethod(ComMethod::StorageSetStateBits),
            HostThunk::ComMethod(ComMethod::StorageStat),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComStorage, vtable)?;
        self.com_storages.insert(
            object,
            crate::runtime::state::ComStorageState {
                host_dir: Some(format!("{COM_CFB_PREFIX}{host_file}")),
                clsid: root_clsid,
                mode,
                name,
                ..Default::default()
            },
        );
        if let Some(compound) = &compound {
            self.com_storage_load_compound_children(memory, object, compound, "Root")?;
        }
        Ok(Ok(object))
    }

    /// Commit one compound-file-backed storage: serialize the whole live
    /// storage tree as a real CFB v3 file (the MSI module's writer).  A
    /// nested storage's commit rewrites the file through its root object.
    fn com_storage_commit_compound(&mut self, storage: u64) -> u32 {
        let Some(path) = self.com_storage_compound_path(storage) else {
            return STG_E_FILENOTFOUND;
        };
        let Some(root) = self.com_storage_compound_root(storage) else {
            return STG_E_ACCESSDENIED;
        };
        let mut tree = self.com_storage_build_compound_tree(root);
        tree.name = "Root Entry".to_string();
        let bytes = crate::runtime::dispatch::msi::write_compound_tree(&tree);
        if std::fs::write(&path, bytes).is_err() {
            return STG_E_ACCESSDENIED;
        }
        for object in self.com_storage_subtree_objects(root) {
            let streams: Vec<u64> = self
                .com_storages
                .get(&object)
                .map(|state| state.stream_objects.values().copied().collect())
                .unwrap_or_default();
            for stream in streams {
                if let Some(entry) = self.com_streams.get_mut(&stream) {
                    entry.dirty = false;
                }
            }
        }
        S_OK
    }

    /// Commit a directory-backed storage tree: write each storage's direct
    /// streams into its nested host directory and recurse into child
    /// storages.
    fn com_storage_commit_directory(&mut self, storage: u64) -> u32 {
        let Some(state) = self.com_storages.get(&storage).cloned() else {
            return STG_E_INVALIDPOINTER;
        };
        if let Some(directory) = &state.host_dir {
            if std::fs::create_dir_all(directory).is_err() {
                return STG_E_ACCESSDENIED;
            }
            for (name, data) in &state.streams {
                let live = state
                    .stream_objects
                    .get(name)
                    .and_then(|object| self.com_streams.get(object))
                    .map(|stream| stream.data.as_slice());
                let bytes = live.unwrap_or(data.as_slice());
                if std::fs::write(format!("{directory}/{name}"), bytes).is_err() {
                    return STG_E_ACCESSDENIED;
                }
            }
        }
        for child in state.child_storages.values() {
            let hr = self.com_storage_commit_directory(*child);
            if hr != S_OK {
                return hr;
            }
        }
        S_OK
    }

    fn com_storage_create_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let mode = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 4)?;
        let Some(name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        if !self.com_storages.contains_key(&this) {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let host_path = self.com_storage_element_path(this, &name);
        if host_path
            .as_ref()
            .is_some_and(|path| std::path::Path::new(path).exists())
        {
            state.set(Register::Rax, u64::from(STG_E_FILEALREADYEXISTS));
            return Ok(());
        }
        if let Some(storage) = self.com_storages.get_mut(&this) {
            if storage.streams.contains_key(&name)
                || storage.stream_objects.contains_key(&name)
                || storage.child_storages.contains_key(&name)
            {
                state.set(Register::Rax, u64::from(STG_E_FILEALREADYEXISTS));
                return Ok(());
            }
            storage.streams.insert(name.clone(), Vec::new());
            if !storage.element_order.contains(&name) {
                storage.element_order.push(name.clone());
            }
        }
        let stream = self.alloc_com_stream_object(memory, Vec::new(), &name, host_path)?;
        if let Some(stream_state) = self.com_streams.get_mut(&stream) {
            stream_state.dirty = true;
        }
        if let Some(storage) = self.com_storages.get_mut(&this) {
            storage.stream_objects.insert(name.clone(), stream);
        }
        let _ = mode;
        write_guest_pointer(memory, out, stream, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_open_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let mode = guest_call_arg_u32(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 5)?;
        let Some(name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let (live, host_dir, mapped) = match self.com_storages.get(&this) {
            Some(storage) => (
                storage.stream_objects.get(&name).copied(),
                storage.host_dir.clone(),
                storage.streams.get(&name).cloned(),
            ),
            None => {
                state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
                return Ok(());
            }
        };
        let live_bytes = live
            .and_then(|stream| self.com_streams.get(&stream))
            .map(|stream| stream.data.clone());
        let compound_backed = host_dir
            .as_deref()
            .is_some_and(|directory| directory.starts_with(COM_CFB_PREFIX));
        let bytes = if let Some(data) = live_bytes.or(mapped) {
            data
        } else if let Some(directory) = host_dir.filter(|_| !compound_backed) {
            match std::fs::read(format!("{directory}/{name}")) {
                Ok(bytes) => bytes,
                Err(_) => {
                    state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
                    return Ok(());
                }
            }
        } else {
            state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
            return Ok(());
        };
        let host_path = self.com_storage_element_path(this, &name);
        let stream = self.alloc_com_stream_object(memory, bytes, &name, host_path)?;
        if let Some(storage) = self.com_storages.get_mut(&this) {
            storage.stream_objects.insert(name.clone(), stream);
        }
        let _ = mode;
        write_guest_pointer(memory, out, stream, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_create_storage(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let _mode = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 4)?;
        let Some(name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let Some(storage) = self.com_storages.get(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if storage.child_storages.contains_key(&name)
            || storage.streams.contains_key(&name)
            || storage.stream_objects.contains_key(&name)
        {
            state.set(Register::Rax, u64::from(STG_E_FILEALREADYEXISTS));
            return Ok(());
        }
        let host_dir = self.com_storage_child_host_dir(this, &name);
        let child = self.alloc_com_storage_object(memory, host_dir, &name, 0)?;
        if let Some(parent) = self.com_storages.get_mut(&this) {
            parent.child_storages.insert(name.clone(), child);
            if !parent.element_order.contains(&name) {
                parent.element_order.push(name);
            }
        }
        write_guest_pointer(memory, out, child, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_open_storage(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let _mode = guest_call_arg_u32(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 5)?;
        let Some(name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let Some(storage) = self.com_storages.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if let Some(child) = storage.child_storages.get(&name).copied() {
            self.add_ref_guest_object(child)?;
            write_guest_pointer(memory, out, child, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        if storage
            .host_dir
            .as_deref()
            .is_some_and(|directory| directory.starts_with(COM_CFB_PREFIX))
        {
            // Compound children are materialized when the parent storage is
            // opened, so a missing name here is a destroyed or absent
            // element: never resurrect it from the on-disk file before the
            // next Commit/Revert.
            state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
            return Ok(());
        }
        let host_dir = storage
            .host_dir
            .as_ref()
            .map(|directory| format!("{directory}/{name}"));
        let exists_on_disk = host_dir
            .as_ref()
            .is_some_and(|directory| std::path::Path::new(directory).is_dir());
        if !exists_on_disk {
            state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
            return Ok(());
        }
        let child = self.alloc_com_storage_object(memory, host_dir, &name, 0)?;
        if let Some(parent) = self.com_storages.get_mut(&this) {
            parent.child_storages.insert(name.clone(), child);
            if !parent.element_order.contains(&name) {
                parent.element_order.push(name);
            }
        }
        write_guest_pointer(memory, out, child, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_copy_to(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let destination = guest_call_arg(state, memory, 4)?;
        if this == destination {
            state.set(Register::Rax, u64::from(STG_E_ACCESSDENIED));
            return Ok(());
        }
        if !self.com_storages.contains_key(&this) || !self.com_storages.contains_key(&destination) {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let result = self.com_storage_copy_into(memory, this, destination)?;
        state.set(Register::Rax, u64::from(result));
        Ok(())
    }

    fn com_storage_move_element(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let old_ptr = guest_call_arg(state, memory, 1)?;
        let new_ptr = guest_call_arg(state, memory, 2)?;
        let flags = guest_call_arg_u32(state, memory, 3)?;
        let old_name = read_utf16_string(memory, old_ptr).unwrap_or_default();
        let new_name = read_utf16_string(memory, new_ptr).unwrap_or_default();
        let move_stream = flags & STGMOVE_MOVE != 0;
        if !move_stream && flags & STGMOVE_COPY == 0 {
            state.set(Register::Rax, u64::from(STG_E_INVALIDFUNCTION));
            return Ok(());
        }
        let Some(storage) = self.com_storages.get_mut(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if let Some(data) = storage.streams.get(&old_name).cloned() {
            storage.streams.insert(new_name.clone(), data);
            if move_stream {
                storage.streams.remove(&old_name);
            }
            if !storage.element_order.contains(&new_name) {
                storage.element_order.push(new_name);
            }
        } else if let Some(child) = storage.child_storages.remove(&old_name) {
            storage.child_storages.insert(new_name.clone(), child);
            if !storage.element_order.contains(&new_name) {
                storage.element_order.push(new_name);
            }
        } else {
            state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_commit(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(storage) = self.com_storages.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if self.com_storage_compound_path(this).is_some() {
            let hr = self.com_storage_commit_compound(this);
            state.set(Register::Rax, u64::from(hr));
            return Ok(());
        }
        if storage.host_dir.is_some() {
            let hr = self.com_storage_commit_directory(this);
            if hr != S_OK {
                state.set(Register::Rax, u64::from(hr));
                return Ok(());
            }
        }
        // Streams handed out by this storage flush their own host files.
        let streams: Vec<u64> = self
            .com_streams
            .iter()
            .filter(|(_, stream)| {
                storage.host_dir.as_ref().is_some_and(|directory| {
                    stream
                        .host_path
                        .as_ref()
                        .is_some_and(|path| path.starts_with(directory))
                })
            })
            .map(|(object, _)| *object)
            .collect();
        for stream in streams {
            let dirty = self
                .com_streams
                .get(&stream)
                .map(|entry| entry.dirty)
                .unwrap_or(false);
            if dirty {
                let _ = self.com_stream_commit_for(&stream);
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_stream_commit_for(&mut self, stream: &u64) -> AppResult<()> {
        let Some(state) = self.com_streams.get(stream) else {
            return Ok(());
        };
        if let (Some(path), true) = (&state.host_path, state.dirty) {
            let path = path.clone();
            let bytes = state.data.clone();
            if let Some(parent) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, bytes);
            if let Some(state) = self.com_streams.get_mut(stream) {
                state.dirty = false;
            }
        }
        Ok(())
    }

    fn com_storage_revert(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(storage) = self.com_storages.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if let Some(path) = self.com_storage_compound_path(this) {
            let compound = match Self::com_compound_file(&path) {
                Ok(compound) => compound,
                Err(hr) => {
                    state.set(Register::Rax, u64::from(hr));
                    return Ok(());
                }
            };
            let relative = self.com_storage_compound_relative(this).unwrap_or_default();
            let element_path = if relative.is_empty() {
                "Root".to_string()
            } else {
                format!("Root/{}", relative.join("/"))
            };
            let Some(entry) = compound
                .entry_at(&element_path)
                .filter(|entry| entry.kind == 1 || entry.kind == 5)
                .cloned()
            else {
                state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
                return Ok(());
            };
            let clsid = entry
                .clsid
                .iter()
                .any(|byte| *byte != 0)
                .then_some(entry.clsid);
            if let Some(entry) = self.com_storages.get_mut(&this) {
                entry.clsid = clsid;
            }
            self.com_storage_reload_compound_children(memory, this, &compound, &element_path)?;
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        if let Some(directory) = &storage.host_dir {
            let mut reloaded = std::collections::HashMap::new();
            if let Ok(entries) = std::fs::read_dir(directory) {
                for entry in entries.flatten() {
                    if entry.path().is_file() {
                        if let Ok(bytes) = std::fs::read(entry.path()) {
                            if let Some(name) = entry.file_name().to_str() {
                                reloaded.insert(name.to_string(), bytes);
                            }
                        }
                    }
                }
            }
            if let Some(storage) = self.com_storages.get_mut(&this) {
                storage.streams = reloaded;
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_enum_elements(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 4)?;
        let Some(storage) = self.com_storages.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let mut items = Vec::new();
        for name in &storage.element_order {
            let is_stream = storage.streams.contains_key(name);
            if is_stream {
                let size = storage
                    .stream_objects
                    .get(name)
                    .and_then(|stream| self.com_streams.get(stream))
                    .map(|stream| stream.data.len())
                    .or_else(|| storage.streams.get(name).map(Vec::len))
                    .unwrap_or(0) as u64;
                let descriptor = self.alloc_zeroed(memory, 72, 8)?;
                self.write_statstg(memory, descriptor, name, 2, size, 2, 0, None)?;
                items.push(pointer_bytes_bytes(
                    descriptor,
                    self.guest_arch.pointer_bytes() as u64,
                ));
            } else if let Some(child) = storage.child_storages.get(name) {
                let child_clsid = self.com_storages.get(child).and_then(|entry| entry.clsid);
                let descriptor = self.alloc_zeroed(memory, 72, 8)?;
                self.write_statstg(memory, descriptor, name, 1, 0, 0, 0, child_clsid)?;
                items.push(pointer_bytes_bytes(
                    descriptor,
                    self.guest_arch.pointer_bytes() as u64,
                ));
            }
        }
        let enumerator = self.alloc_com_enum_object(memory, items)?;
        if out != 0 {
            write_guest_pointer(memory, out, enumerator, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_destroy_element(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let name = read_utf16_string(memory, name_ptr).unwrap_or_default();
        let host_path = self.com_storage_element_path(this, &name);
        let removed_child = {
            let Some(storage) = self.com_storages.get_mut(&this) else {
                state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
                return Ok(());
            };
            let removed_stream = storage.streams.remove(&name).is_some();
            let removed_object = storage.stream_objects.remove(&name).is_some();
            let removed_child = storage.child_storages.remove(&name);
            storage.element_order.retain(|element| element != &name);
            if !removed_stream && !removed_object && removed_child.is_none() {
                state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
                return Ok(());
            }
            removed_child
        };
        if let Some(child) = removed_child {
            self.com_storage_forget_subtree(child);
        }
        if let Some(path) = host_path {
            let path = std::path::PathBuf::from(path);
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(path);
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_rename_element(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let old_ptr = guest_call_arg(state, memory, 1)?;
        let new_ptr = guest_call_arg(state, memory, 2)?;
        let old_name = read_utf16_string(memory, old_ptr).unwrap_or_default();
        let new_name = read_utf16_string(memory, new_ptr).unwrap_or_default();
        let old_path = self.com_storage_element_path(this, &old_name);
        let new_path = self.com_storage_element_path(this, &new_name);
        let Some(storage) = self.com_storages.get_mut(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if let Some(data) = storage.streams.remove(&old_name) {
            storage.streams.insert(new_name.clone(), data);
        } else if let Some(child) = storage.child_storages.remove(&old_name) {
            storage.child_storages.insert(new_name.clone(), child);
        } else {
            state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
            return Ok(());
        }
        for element in storage.element_order.iter_mut() {
            if element == &old_name {
                *element = new_name.clone();
            }
        }
        if let (Some(old_path), Some(new_path)) = (old_path, new_path) {
            let _ = std::fs::rename(old_path, new_path);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_set_element_times(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let _create_ptr = guest_call_arg(state, memory, 2)?;
        let _access_ptr = guest_call_arg(state, memory, 3)?;
        let modify_ptr = guest_call_arg(state, memory, 4)?;
        let name = read_utf16_string(memory, name_ptr).unwrap_or_default();
        if self.com_storage_compound_path(this).is_some() {
            let exists = self
                .com_storages
                .get(&this)
                .is_some_and(|storage| storage.streams.contains_key(&name));
            state.set(
                Register::Rax,
                u64::from(if exists { S_OK } else { STG_E_FILENOTFOUND }),
            );
            return Ok(());
        }
        let Some(host_path) = self.com_storage_element_path(this, &name) else {
            state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
            return Ok(());
        };
        if !std::path::Path::new(&host_path).exists() {
            state.set(Register::Rax, u64::from(STG_E_FILENOTFOUND));
            return Ok(());
        }
        // Apply the modification time through the real file layer.
        if modify_ptr != 0 {
            let ticks = memory.read_u64(modify_ptr).unwrap_or(0);
            if let Some(system_time) = filetime_to_system_time(ticks) {
                if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&host_path) {
                    let times = std::fs::FileTimes::new().set_modified(system_time);
                    let _ = file.set_times(times);
                }
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_set_class(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let clsid_ptr = guest_call_arg(state, memory, 1)?;
        let Some(storage) = self.com_storages.get_mut(&this) else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        if clsid_ptr == 0 {
            storage.clsid = None;
        } else {
            let bytes = memory.read_bytes(clsid_ptr, 16).unwrap_or_default();
            if bytes.len() == 16 {
                let mut clsid = [0_u8; 16];
                clsid.copy_from_slice(&bytes);
                storage.clsid = Some(clsid);
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_set_state_bits(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if !self.com_storages.contains_key(&this) {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        }
        let _bits = guest_call_arg_u32(state, memory, 1)?;
        let _mask = guest_call_arg_u32(state, memory, 2)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_storage_stat(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stat_ptr = guest_call_arg(state, memory, 1)?;
        let flags = guest_call_arg(state, memory, 2)? as u32;
        let Some(storage) = self.com_storages.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(STG_E_INVALIDPOINTER));
            return Ok(());
        };
        let name = if flags & STATFLAG_NONAME != 0 {
            String::new()
        } else {
            storage.name.clone()
        };
        self.write_statstg(
            memory,
            stat_ptr,
            &name,
            1,
            0,
            storage.mode,
            0,
            storage.clsid,
        )?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_enum_next(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let count = guest_call_arg_u32(state, memory, 1)? as usize;
        let out = guest_call_arg(state, memory, 2)?;
        let fetched_out = guest_call_arg(state, memory, 3)?;
        let Some(enumerator) = self.com_enum_variants.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let item_size = enumerator.items.first().map(Vec::len).unwrap_or(0);
        let remaining = enumerator.items.len().saturating_sub(enumerator.current);
        let to_fetch = if count == 0 { 0 } else { count.min(remaining) };
        if count > 0 && out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let start = enumerator.current;
        let items: Vec<Vec<u8>> = enumerator.items[start..start + to_fetch].to_vec();
        for (index, item) in items.iter().enumerate() {
            let target = out + index as u64 * item_size as u64;
            memory.map_bytes(target, item);
        }
        if let Some(enumerator) = self.com_enum_variants.get_mut(&this) {
            enumerator.current = start + to_fetch;
        }
        if fetched_out != 0 {
            write_u32(memory, fetched_out, to_fetch as u32);
        }
        state.set(
            Register::Rax,
            if to_fetch == count {
                u64::from(S_OK)
            } else {
                u64::from(S_FALSE)
            },
        );
        Ok(())
    }

    fn com_enum_skip(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let count = guest_call_arg_u32(state, memory, 1)? as usize;
        let Some(enumerator) = self.com_enum_variants.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let remaining = enumerator.items.len().saturating_sub(enumerator.current);
        let skipped = count.min(remaining);
        enumerator.current += skipped;
        state.set(
            Register::Rax,
            if skipped == count {
                u64::from(S_OK)
            } else {
                u64::from(S_FALSE)
            },
        );
        Ok(())
    }

    fn com_enum_reset(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(enumerator) = self.com_enum_variants.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        enumerator.current = 0;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_enum_clone(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(enumerator) = self.com_enum_variants.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let clone = self.alloc_com_enum_object(memory, enumerator.items.clone())?;
        if let Some(clone_state) = self.com_enum_variants.get_mut(&clone) {
            clone_state.current = enumerator.current;
        }
        if out != 0 {
            write_guest_pointer(memory, out, clone, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IConnectionPointContainer / IConnectionPoint ────────────────────────

    fn com_container_enum_connection_points(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(container) = self.com_connection_points.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let mut points: Vec<u64> = container.points.values().copied().collect();
        points.sort_unstable();
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let items = points
            .iter()
            .map(|point| pointer_bytes_bytes(*point, pointer_bytes))
            .collect();
        let enumerator = self.alloc_com_enum_object(memory, items)?;
        if out != 0 {
            write_guest_pointer(memory, out, enumerator, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_container_find_connection_point(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 || riid_ptr == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let iid: [u8; 16] =
            std::array::from_fn(|index| memory.read_u8(riid_ptr + index as u64).unwrap_or(0));
        let key = Self::guid_bytes_to_string(&iid);
        let point = self
            .com_connection_points
            .get(&this)
            .and_then(|container| container.points.get(&key).copied());
        match point {
            Some(point) => {
                self.add_ref_guest_object(point)?;
                write_guest_pointer(memory, out, point, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(CONNECT_E_NOCONNECTION)),
        }
        Ok(())
    }

    fn com_connection_point_get_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(point) = self.com_connection_points.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        for (index, byte) in point.iid.iter().enumerate() {
            memory.write_u8(out + index as u64, *byte);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_connection_point_get_container(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let owner = self
            .com_connection_points
            .get(&this)
            .map(|point| point.owner)
            .unwrap_or(0);
        if owner == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let container = self.alloc_com_connection_point_container(memory, owner)?;
        self.add_ref_guest_object(container)?;
        write_guest_pointer(memory, out, container, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_connection_point_advise(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let sink = guest_call_arg(state, memory, 1)?;
        let cookie_out = guest_call_arg(state, memory, 2)?;
        if sink == 0 || cookie_out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        if !self.com_connection_points.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        // The advised sink is reference-counted through its own AddRef
        // (the runtime's guest-object table when the sink is a runtime
        // object; the sink's vtable otherwise).
        if self.guest_objects.contains_key(&sink) {
            self.add_ref_guest_object(sink)?;
        }
        let cookie = self.com_next_conn_cookie;
        self.com_next_conn_cookie = self.com_next_conn_cookie.wrapping_add(1).max(1);
        if let Some(point) = self.com_connection_points.get_mut(&this) {
            point.sinks.push((cookie, sink));
        }
        write_u32(memory, cookie_out, cookie);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_connection_point_unadvise(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let cookie = guest_call_arg_u32(state, memory, 1)?;
        let Some(point) = self.com_connection_points.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(index) = point
            .sinks
            .iter()
            .position(|(advised_cookie, _)| *advised_cookie == cookie)
        else {
            state.set(Register::Rax, u64::from(CONNECT_E_NOCONNECTION));
            return Ok(());
        };
        let (_, sink) = point.sinks.remove(index);
        if self.guest_objects.contains_key(&sink) {
            self.release_guest_object(sink)?;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_connection_point_enum_connections(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(point) = self.com_connection_points.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let sinks: Vec<(u32, u64)> = point.sinks.clone();
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let items = sinks
            .iter()
            .map(|(cookie, sink)| connect_data_bytes(*sink, *cookie, pointer_bytes))
            .collect();
        let enumerator = self.alloc_com_enum_object(memory, items)?;
        if out != 0 {
            write_guest_pointer(memory, out, enumerator, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── COM object allocators (real vtables + state) ────────────────────────

    /// Create a guest IStream over `data`, optionally backed by a real host
    /// path (Commit/Revert flush/reload the file).
    pub(crate) fn alloc_com_stream_object(
        &mut self,
        memory: &mut MemoryImage,
        data: Vec<u8>,
        name: &str,
        host_path: Option<String>,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::StreamRead),
            HostThunk::ComMethod(ComMethod::StreamWrite),
            HostThunk::ComMethod(ComMethod::StreamSeek),
            HostThunk::ComMethod(ComMethod::StreamSetSize),
            HostThunk::ComMethod(ComMethod::StreamCopyTo),
            HostThunk::ComMethod(ComMethod::StreamCommit),
            HostThunk::ComMethod(ComMethod::StreamRevert),
            HostThunk::ComMethod(ComMethod::StreamLockRegion),
            HostThunk::ComMethod(ComMethod::StreamUnlockRegion),
            HostThunk::ComMethod(ComMethod::StreamStat),
            HostThunk::ComMethod(ComMethod::StreamClone),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComStream, vtable)?;
        self.com_streams.insert(
            object,
            crate::runtime::state::ComStreamState {
                data,
                name: name.to_string(),
                host_path,
                ..Default::default()
            },
        );
        Ok(object)
    }

    /// Create a guest IStream reading an existing real file.
    pub(crate) fn alloc_com_stream_from_file(
        &mut self,
        memory: &mut MemoryImage,
        host_path: &str,
    ) -> AppResult<u64> {
        let data = std::fs::read(host_path).unwrap_or_default();
        let name = std::path::Path::new(host_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .to_string();
        self.alloc_com_stream_object(memory, data, &name, Some(host_path.to_string()))
    }

    /// Create a guest IStorage, optionally over a real host directory.
    pub(crate) fn alloc_com_storage_object(
        &mut self,
        memory: &mut MemoryImage,
        host_dir: Option<String>,
        name: &str,
        mode: u32,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::StorageCreateStream),
            HostThunk::ComMethod(ComMethod::StorageOpenStream),
            HostThunk::ComMethod(ComMethod::StorageCreateStorage),
            HostThunk::ComMethod(ComMethod::StorageOpenStorage),
            HostThunk::ComMethod(ComMethod::StorageCopyTo),
            HostThunk::ComMethod(ComMethod::StorageMoveElement),
            HostThunk::ComMethod(ComMethod::StorageCommit),
            HostThunk::ComMethod(ComMethod::StorageRevert),
            HostThunk::ComMethod(ComMethod::StorageEnumElements),
            HostThunk::ComMethod(ComMethod::StorageDestroyElement),
            HostThunk::ComMethod(ComMethod::StorageRenameElement),
            HostThunk::ComMethod(ComMethod::StorageSetElementTimes),
            HostThunk::ComMethod(ComMethod::StorageSetClass),
            HostThunk::ComMethod(ComMethod::StorageSetStateBits),
            HostThunk::ComMethod(ComMethod::StorageStat),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComStorage, vtable)?;
        let mut streams = HashMap::new();
        if let Some(directory) = &host_dir {
            if let Ok(entries) = std::fs::read_dir(directory) {
                for entry in entries.flatten() {
                    if entry.path().is_file() {
                        if let (Some(file_name), Ok(bytes)) =
                            (entry.file_name().to_str(), std::fs::read(entry.path()))
                        {
                            streams.insert(file_name.to_string(), bytes);
                        }
                    }
                }
            }
        }
        let element_order = streams.keys().cloned().collect();
        self.com_storages.insert(
            object,
            crate::runtime::state::ComStorageState {
                streams,
                host_dir,
                element_order,
                mode,
                name: name.to_string(),
                ..Default::default()
            },
        );
        Ok(object)
    }

    /// Create the IConnectionPointContainer interface object for `owner`
    /// (idempotent: the owner's server state caches it).
    pub(crate) fn alloc_com_connection_point_container(
        &mut self,
        memory: &mut MemoryImage,
        owner: u64,
    ) -> AppResult<u64> {
        if let Some(server) = self.com_servers.get(&owner) {
            if server.container != 0 {
                return Ok(server.container);
            }
        }
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::EnumConnectionPoints),
            HostThunk::ComMethod(ComMethod::FindConnectionPoint),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::ComConnectionPoint, vtable)?;
        self.com_connection_points.insert(
            object,
            crate::runtime::state::ComConnectionPointState {
                owner,
                is_container: true,
                ..Default::default()
            },
        );
        if let Some(server) = self.com_servers.get_mut(&owner) {
            server.container = object;
        }
        Ok(object)
    }

    /// Create an IConnectionPoint for `iid` on `owner`.
    pub(crate) fn alloc_com_connection_point(
        &mut self,
        memory: &mut MemoryImage,
        owner: u64,
        iid: [u8; 16],
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::GetConnectionInterface),
            HostThunk::ComMethod(ComMethod::GetConnectionPointContainer),
            HostThunk::ComMethod(ComMethod::Advise),
            HostThunk::ComMethod(ComMethod::Unadvise),
            HostThunk::ComMethod(ComMethod::EnumConnections),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::ComConnectionPoint, vtable)?;
        self.com_connection_points.insert(
            object,
            crate::runtime::state::ComConnectionPointState {
                owner,
                iid,
                is_container: false,
                ..Default::default()
            },
        );
        let container = self.alloc_com_connection_point_container(memory, owner)?;
        let key = Self::guid_bytes_to_string(&iid);
        if let Some(container_state) = self.com_connection_points.get_mut(&container) {
            container_state.points.insert(key, object);
        }
        Ok(object)
    }

    /// Create a snapshot enumerator object (IEnumConnectionPoints,
    /// IEnumConnections, IEnumSTATSTG) over pre-encoded items.
    pub(crate) fn alloc_com_enum_object(
        &mut self,
        memory: &mut MemoryImage,
        items: Vec<Vec<u8>>,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::EnumNext),
            HostThunk::ComMethod(ComMethod::EnumSkip),
            HostThunk::ComMethod(ComMethod::EnumReset),
            HostThunk::ComMethod(ComMethod::EnumClone),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComEnumVariant, vtable)?;
        self.com_enum_variants.insert(
            object,
            crate::runtime::state::ComEnumVariantState { items, current: 0 },
        );
        Ok(object)
    }

    // ── IDispatch / ITypeInfo ───────────────────────────────────────────────

    /// Create the runtime's in-process automation server: a real IDispatch
    /// dual interface with a registered method table plus an
    /// IConnectionPointContainer whose connection point fires the table's
    /// events when the server's state changes.
    pub(crate) fn alloc_com_automation_server(
        &mut self,
        memory: &mut MemoryImage,
        table: &str,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::DispatchGetTypeInfoCount),
            HostThunk::ComMethod(ComMethod::DispatchGetTypeInfo),
            HostThunk::ComMethod(ComMethod::DispatchGetIDsOfNames),
            HostThunk::ComMethod(ComMethod::DispatchInvoke),
            HostThunk::ComMethod(ComMethod::ServerGetValue),
            HostThunk::ComMethod(ComMethod::ServerPutValue),
            HostThunk::ComMethod(ComMethod::ServerGetName),
            HostThunk::ComMethod(ComMethod::ServerPutName),
            HostThunk::ComMethod(ComMethod::ServerGetCount),
            HostThunk::ComMethod(ComMethod::ServerAdd),
            HostThunk::ComMethod(ComMethod::ServerReset),
            HostThunk::ComMethod(ComMethod::ServerFireValueChanged),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComDispatch, vtable)?;
        self.com_servers.insert(
            object,
            crate::runtime::state::ComServerState {
                table: table.to_string(),
                ..Default::default()
            },
        );
        // The event connection point exists from creation: sinks can advise
        // before the first state change.
        self.alloc_com_connection_point(memory, object, COM_AUTOMATION_EVENTS_IID)?;
        Ok(object)
    }

    /// Create the runtime's modeled IDispatch event sink (records every
    /// delivered event in `com_sink_invocations`).  The sink is the Advise
    /// target the connection-point tests attach to a server.
    #[allow(dead_code)] // exercised by the connection-point test sinks
    pub(crate) fn alloc_com_sink_object(
        &mut self,
        memory: &mut MemoryImage,
        table: &str,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::DispatchGetTypeInfoCount),
            HostThunk::ComMethod(ComMethod::DispatchGetTypeInfo),
            HostThunk::ComMethod(ComMethod::DispatchGetIDsOfNames),
            HostThunk::ComMethod(ComMethod::SinkInvoke),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComDispatch, vtable)?;
        self.com_servers.insert(
            object,
            crate::runtime::state::ComServerState {
                table: table.to_string(),
                ..Default::default()
            },
        );
        Ok(object)
    }

    fn com_server_get_property(&self, server: u64, name: &str) -> ComValue {
        if let Some(state) = self.com_servers.get(&server) {
            if let Some(value) = state.properties.get(name) {
                return value.clone();
            }
        }
        match name {
            "Value" => ComValue::I4(0),
            "Name" => ComValue::Bstr(String::new()),
            "Count" => ComValue::I4(
                self.com_servers
                    .get(&server)
                    .map(|state| state.properties.len() as i32)
                    .unwrap_or(0),
            ),
            _ => ComValue::Empty,
        }
    }

    fn com_server_set_property(&mut self, server: u64, name: &str, value: ComValue) {
        if let Some(state) = self.com_servers.get_mut(&server) {
            state.properties.insert(name.to_string(), value);
        }
    }

    fn com_server_get_value(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let value = self.com_server_get_property(this, "Value");
        self.write_variant_value(memory, out, &value)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_server_put_value(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let value_ptr = guest_call_arg(state, memory, 1)?;
        let value = self.read_variant_value(memory, value_ptr)?;
        let Some(value) = value else {
            state.set(Register::Rax, u64::from(DISP_E_TYPEMISMATCH));
            return Ok(());
        };
        let previous = self.com_server_get_property(this, "Value");
        self.com_server_set_property(this, "Value", value.clone());
        if previous != value {
            self.fire_automation_event(state, memory, this, 10, &[value])?;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_server_get_name(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let value = self.com_server_get_property(this, "Name");
        self.write_variant_value(memory, out, &value)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_server_put_name(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let value_ptr = guest_call_arg(state, memory, 1)?;
        let value = self.read_variant_value(memory, value_ptr)?;
        let Some(value) = value else {
            state.set(Register::Rax, u64::from(DISP_E_TYPEMISMATCH));
            return Ok(());
        };
        self.com_server_set_property(this, "Name", value);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_server_get_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let value = self.com_server_get_property(this, "Count");
        self.write_variant_value(memory, out, &value)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_server_add(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let left = self.com_arg_i32(state, memory, 1);
        let right = self.com_arg_i32(state, memory, 2);
        let out = guest_call_arg(state, memory, 3)?;
        if !self.com_servers.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        self.write_variant_i4(memory, out, left.wrapping_add(right));
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_server_reset(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if let Some(server) = self.com_servers.get_mut(&this) {
            server.properties.clear();
        } else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        self.fire_automation_event(state, memory, this, 11, &[])?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_server_fire_value_changed(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let value = self.com_arg_i32(state, memory, 1);
        if !self.com_servers.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        self.fire_automation_event(state, memory, this, 10, &[ComValue::I4(value)])?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_dispatch_get_type_info_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let count = if self
            .com_servers
            .get(&this)
            .and_then(|server| com_dispatch_table(&server.table))
            .is_some()
        {
            1
        } else {
            0
        };
        if out != 0 {
            write_u32(memory, out, count);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_dispatch_get_type_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let table = self
            .com_servers
            .get(&this)
            .map(|server| server.table.clone());
        let Some(table) = table.filter(|table| com_dispatch_table(table).is_some()) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if index != 0 {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        }
        let existing = self
            .com_type_infos
            .iter()
            .find(|(_, info)| info.owner == this && info.index == index)
            .map(|(object, _)| *object);
        let type_info = match existing {
            Some(object) => object,
            None => self.alloc_com_type_info_object(memory, &table, this, index)?,
        };
        self.add_ref_guest_object(type_info)?;
        if out != 0 {
            write_guest_pointer(memory, out, type_info, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_dispatch_get_ids_of_names_impl(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _riid = guest_call_arg(state, memory, 1)?;
        let names_ptr = guest_call_arg(state, memory, 2)?;
        let count = guest_call_arg_u32(state, memory, 3)?;
        let _lcid = guest_call_arg_u32(state, memory, 4)?;
        let ids_ptr = guest_call_arg(state, memory, 5)?;
        if names_ptr == 0 || ids_ptr == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let table_name = match self.com_servers.get(&this) {
            Some(server) => server.table.clone(),
            None => {
                // ITypeInfo serves its own table through the same path.
                match self.com_type_infos.get(&this) {
                    Some(info) => info.table.clone(),
                    None => {
                        state.set(Register::Rax, u64::from(E_NOINTERFACE));
                        return Ok(());
                    }
                }
            }
        };
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let mut all_found = true;
        for index in 0..count.min(256) {
            let name_ptr = read_guest_pointer(
                memory,
                names_ptr + index as u64 * pointer_bytes,
                self.guest_arch,
            )
            .unwrap_or(0);
            let name = read_utf16_string(memory, name_ptr).unwrap_or_default();
            let dispid = self.com_resolve_dispid(this, &table_name, &name);
            match dispid {
                Some(dispid) => write_u32(memory, ids_ptr + index as u64 * 4, dispid as u32),
                None => {
                    all_found = false;
                    write_u32(memory, ids_ptr + index as u64 * 4, DISPID_UNKNOWN as u32);
                }
            }
        }
        state.set(
            Register::Rax,
            if all_found {
                u64::from(S_OK)
            } else {
                u64::from(DISP_E_UNKNOWNNAME)
            },
        );
        Ok(())
    }

    /// Resolve one automation name to its DISPID: the registered table
    /// first, then (and persistently) the server's dynamic cache with stable
    /// monotonically assigned DISPIDs.
    fn com_resolve_dispid(&mut self, object: u64, table: &str, name: &str) -> Option<i32> {
        if name.is_empty() {
            return Some(DISPID_VALUE);
        }
        if let Some(member) = com_dispatch_member_by_name(table, name) {
            if let Some(server) = self.com_servers.get_mut(&object) {
                server
                    .dispid_cache
                    .entry(name.to_string())
                    .or_insert(member.dispid);
            }
            return Some(member.dispid);
        }
        if let Some(server) = self.com_servers.get(&object) {
            if let Some(dispid) = server.dispid_cache.get(name) {
                return Some(*dispid);
            }
        }
        None
    }

    fn com_dispatch_invoke_impl(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let dispid = self.com_arg_i32(state, memory, 1);
        let _riid = guest_call_arg(state, memory, 2)?;
        let _lcid = guest_call_arg_u32(state, memory, 3)?;
        let flags = guest_call_arg_u32(state, memory, 4)? as u16;
        let params = guest_call_arg(state, memory, 5)?;
        let result = guest_call_arg(state, memory, 6)?;
        let _exception = guest_call_arg(state, memory, 7)?;
        let argument_error = guest_call_arg(state, memory, 8)?;
        let hr = self.invoke_automation_member(
            state,
            memory,
            this,
            dispid,
            flags,
            params,
            result,
            argument_error,
        )?;
        state.set(Register::Rax, u64::from(hr));
        Ok(())
    }

    /// The shared automation invocation used by IDispatch::Invoke, the
    /// server's dual-interface vtable methods and ITypeInfo::Invoke.
    #[allow(clippy::too_many_arguments)]
    fn invoke_automation_member(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        server: u64,
        dispid: i32,
        flags: u16,
        params: u64,
        result: u64,
        argument_error: u64,
    ) -> AppResult<u32> {
        let table_name = match self.com_servers.get(&server) {
            Some(server) => server.table.clone(),
            None => return Ok(E_NOINTERFACE),
        };
        let Some(member) = com_dispatch_member_for(&table_name, dispid, flags) else {
            return Ok(DISP_E_MEMBERNOTFOUND);
        };
        let reversed = self.read_dispparams_values(memory, params);
        let logical: Vec<ComValue> = reversed.iter().rev().cloned().collect();
        if flags & DISPATCH_PROPERTYPUT != 0 {
            if member.kind != ComMemberKind::PropertyPut {
                return Ok(DISP_E_MEMBERNOTFOUND);
            }
            let Some(value) = logical.first().cloned() else {
                if argument_error != 0 {
                    write_u32(memory, argument_error, 0);
                }
                return Ok(DISP_E_BADPARAMCOUNT);
            };
            let previous = self.com_server_get_property(server, member.name);
            self.com_server_set_property(server, member.name, value.clone());
            if member.name == "Value" && previous != value {
                self.fire_automation_event(state, memory, server, 10, &[value])?;
            }
            self.write_variant_empty(memory, result);
            return Ok(S_OK);
        }
        if flags & DISPATCH_METHOD != 0 && member.kind == ComMemberKind::Method {
            match member.name {
                "Add" => {
                    if logical.len() < 2 {
                        return Ok(DISP_E_BADPARAMCOUNT);
                    }
                    let left = com_value_as_i4(&logical[0]);
                    let right = com_value_as_i4(&logical[1]);
                    self.write_variant_i4(memory, result, left.wrapping_add(right));
                    return Ok(S_OK);
                }
                "Reset" => {
                    if let Some(server_state) = self.com_servers.get_mut(&server) {
                        server_state.properties.clear();
                    }
                    self.fire_automation_event(state, memory, server, 11, &[])?;
                    self.write_variant_empty(memory, result);
                    return Ok(S_OK);
                }
                "FireValueChanged" => {
                    let value = logical.first().map(com_value_as_i4).unwrap_or(0);
                    self.fire_automation_event(state, memory, server, 10, &[ComValue::I4(value)])?;
                    self.write_variant_empty(memory, result);
                    return Ok(S_OK);
                }
                _ => return Ok(DISP_E_MEMBERNOTFOUND),
            }
        }
        if flags & DISPATCH_PROPERTYGET != 0 {
            let value = self.com_server_get_property(server, member.name);
            self.write_variant_value(memory, result, &value)?;
            return Ok(S_OK);
        }
        Ok(DISP_E_MEMBERNOTFOUND)
    }

    fn com_type_info_get_type_attr(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(descriptor) = com_type_descriptor(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let table = com_dispatch_table(&info.table);
        let methods = if descriptor.kind == ComTypeKind::Class {
            0
        } else {
            table
                .map(|members| {
                    members
                        .iter()
                        .filter(|m| m.kind != ComMemberKind::PropertyGet)
                        .count()
                })
                .unwrap_or(0)
        } as u16;
        let variables = if descriptor.kind == ComTypeKind::Class {
            0
        } else {
            table
                .map(|members| {
                    members
                        .iter()
                        .filter(|m| m.kind == ComMemberKind::PropertyGet)
                        .count()
                })
                .unwrap_or(0)
        } as u16;
        let type_kind = match descriptor.kind {
            ComTypeKind::Interface => TKIND_INTERFACE,
            ComTypeKind::Dispatch | ComTypeKind::DispInterface => TKIND_DISPATCH,
            ComTypeKind::Class => TKIND_COCLASS,
        };
        let type_flags = match descriptor.kind {
            ComTypeKind::Dispatch => TYPEFLAG_FDUAL,
            ComTypeKind::DispInterface => TYPEFLAG_FDISPATCHABLE,
            _ => 0,
        };
        let vtable_bytes = match descriptor.kind {
            ComTypeKind::Class => 0,
            ComTypeKind::Interface if descriptor.table == "IUnknown" => 12,
            _ => 28,
        };
        let descriptor_ptr = self.alloc_zeroed(memory, 80, 8)?;
        for (index, byte) in descriptor.iid.iter().enumerate() {
            memory.write_u8(descriptor_ptr + index as u64, *byte);
        }
        write_u32(memory, descriptor_ptr + 16, 0); // lcid
        write_u32(memory, descriptor_ptr + 20, 0); // dwReserved
        write_u32(memory, descriptor_ptr + 24, DISPID_UNKNOWN as u32); // memidConstructor
        write_u32(memory, descriptor_ptr + 28, DISPID_UNKNOWN as u32); // memidDestructor
        write_u32(memory, descriptor_ptr + 32, 0); // lpstrSchema
        write_u32(memory, descriptor_ptr + 36, 0); // cbSizeInstance
        write_u32(memory, descriptor_ptr + 40, type_kind);
        write_u16(memory, descriptor_ptr + 44, methods);
        write_u16(memory, descriptor_ptr + 46, variables);
        write_u16(memory, descriptor_ptr + 48, descriptor.impls.len() as u16);
        write_u16(memory, descriptor_ptr + 50, vtable_bytes);
        write_u16(memory, descriptor_ptr + 52, 4); // cbAlignment
        write_u16(memory, descriptor_ptr + 54, type_flags);
        write_u16(memory, descriptor_ptr + 56, 1); // wMajorVerNum
        write_u16(memory, descriptor_ptr + 58, 0); // wMinorVerNum
        write_u16(memory, descriptor_ptr + 60, 0); // tdescAlias union
        write_u16(memory, descriptor_ptr + 64, 26); // VT_PTR tdescAlias.vt
        write_u32(memory, descriptor_ptr + 68, 0); // idldescType.dwReserved
        write_u16(memory, descriptor_ptr + 72, 0); // idldescType.wIDLFlags
        if out != 0 {
            write_guest_pointer(memory, out, descriptor_ptr, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_type_info_get_func_desc(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(table) = com_dispatch_table(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(member) = table.get(index as usize) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let descriptor = self.alloc_func_desc(memory, member)?;
        if out != 0 {
            write_guest_pointer(memory, out, descriptor, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Allocate one FUNCDESC for a registered member (shared by GetFuncDesc
    /// and ITypeComp::Bind).
    fn alloc_func_desc(
        &mut self,
        memory: &mut MemoryImage,
        member: &ComDispatchMember,
    ) -> AppResult<u64> {
        let descriptor = self.alloc_zeroed(memory, 56, 8)?;
        write_u32(memory, descriptor, member.dispid as u32); // memid
        write_u32(memory, descriptor + 4, 0); // lprgscode
        write_u32(memory, descriptor + 8, 0); // lprgelemdescParam
        write_u32(memory, descriptor + 12, 4); // FUNC_DISPATCH
        write_u32(
            memory,
            descriptor + 16,
            match member.kind {
                ComMemberKind::Method => 1,      // INVOKE_FUNC
                ComMemberKind::PropertyGet => 2, // INVOKE_PROPERTYGET
                ComMemberKind::PropertyPut => 4, // INVOKE_PROPERTYPUT
            },
        );
        write_u32(memory, descriptor + 20, 4); // CC_STDCALL
        write_u16(memory, descriptor + 24, member.args); // cParams
        write_u16(memory, descriptor + 26, 0); // cParamsOpt
        write_u16(memory, descriptor + 28, member.slot as u16); // oVft
        write_u16(memory, descriptor + 30, 0); // cScodes
        write_u32(memory, descriptor + 32, 0);
        write_u16(memory, descriptor + 36, member.returns);
        write_u16(memory, descriptor + 40, 0); // elemdescFunc.paramdesc.wParamFlags
        write_u16(memory, descriptor + 48, 0); // wFuncFlags
        Ok(descriptor)
    }

    fn com_type_info_get_var_desc(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(table) = com_dispatch_table(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let variables: Vec<&ComDispatchMember> = table
            .iter()
            .filter(|member| member.kind == ComMemberKind::PropertyGet)
            .collect();
        let Some(member) = variables.get(index as usize) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let descriptor = self.alloc_var_desc(memory, member)?;
        if out != 0 {
            write_guest_pointer(memory, out, descriptor, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Allocate one VARDESC for a registered property: the VARIANT type is
    /// the property table's declared return VARTYPE (VT_I4 / VT_BSTR).
    fn alloc_var_desc(
        &mut self,
        memory: &mut MemoryImage,
        member: &ComDispatchMember,
    ) -> AppResult<u64> {
        let descriptor = self.alloc_zeroed(memory, 40, 8)?;
        write_u32(memory, descriptor, member.dispid as u32); // memid
        write_u32(memory, descriptor + 4, 0); // lpstrSchema
        write_u32(memory, descriptor + 8, 0); // oInst
        write_u32(memory, descriptor + 12, 0); // elemdescVar.tdesc union
        write_u16(memory, descriptor + 16, member.returns); // elemdescVar.tdesc.vt
        write_u16(memory, descriptor + 24, 0); // elemdescVar.paramdesc.wParamFlags
        write_u16(memory, descriptor + 28, 0); // wVarFlags
        write_u32(memory, descriptor + 32, 0); // varkind = VAR_PERINSTANCE
        Ok(descriptor)
    }

    fn com_type_info_get_names(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let memid = self.com_arg_i32(state, memory, 1);
        let names_ptr = guest_call_arg(state, memory, 2)?;
        let max_names = guest_call_arg_u32(state, memory, 3)?;
        let count_out = guest_call_arg(state, memory, 4)?;
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if names_ptr == 0 || max_names == 0 || count_out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let name = if memid == DISPID_UNKNOWN {
            info.table.clone()
        } else {
            match com_dispatch_member(&info.table, memid) {
                Some(member) => member.name.to_string(),
                None => {
                    write_u32(memory, count_out, 0);
                    state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
                    return Ok(());
                }
            }
        };
        let bstr = self.alloc_com_bstr(memory, &name)?;
        write_guest_pointer(memory, names_ptr, bstr, self.guest_arch).ok();
        write_u32(memory, count_out, 1);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::GetIDsOfNames(rgszNames, cNames, pMemId)` — the same
    /// registered table lookup, with the ITypeInfo argument layout.
    fn com_type_info_get_ids_of_names(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let names = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)?;
        let ids = guest_call_arg(state, memory, 3)?;
        let hr = self.com_get_ids_of_names(memory, this, names, count, 0, ids)?;
        state.set(Register::Rax, u64::from(hr));
        Ok(())
    }

    fn com_type_info_invoke(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let instance = guest_call_arg(state, memory, 1)?;
        let memid = self.com_arg_i32(state, memory, 2);
        let _riid = guest_call_arg(state, memory, 3)?;
        let _lcid = guest_call_arg_u32(state, memory, 4)?;
        let flags = guest_call_arg_u32(state, memory, 5)? as u16;
        let params = guest_call_arg(state, memory, 6)?;
        let result = guest_call_arg(state, memory, 7)?;
        let _exception = guest_call_arg(state, memory, 8)?;
        let argument_error = guest_call_arg(state, memory, 9)?;
        let owner = self
            .com_type_infos
            .get(&this)
            .map(|info| info.owner)
            .unwrap_or(0);
        let target = if instance != 0 { instance } else { owner };
        let hr = self.invoke_automation_member(
            state,
            memory,
            target,
            memid,
            flags,
            params,
            result,
            argument_error,
        )?;
        state.set(Register::Rax, u64::from(hr));
        Ok(())
    }

    fn com_type_info_get_documentation(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let memid = self.com_arg_i32(state, memory, 1);
        let name_out = guest_call_arg(state, memory, 2)?;
        let doc_out = guest_call_arg(state, memory, 3)?;
        let context_out = guest_call_arg(state, memory, 4)?;
        let help_out = guest_call_arg(state, memory, 5)?;
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let name = if memid == DISPID_UNKNOWN {
            info.table.clone()
        } else {
            match com_dispatch_member(&info.table, memid) {
                Some(member) => member.name.to_string(),
                None => {
                    state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
                    return Ok(());
                }
            }
        };
        if name_out != 0 {
            let bstr = self.alloc_com_bstr(memory, &name)?;
            write_guest_pointer(memory, name_out, bstr, self.guest_arch).ok();
        }
        if doc_out != 0 {
            let bstr = self.alloc_com_bstr(memory, "")?;
            write_guest_pointer(memory, doc_out, bstr, self.guest_arch).ok();
        }
        if context_out != 0 {
            write_u32(memory, context_out, 0);
        }
        if help_out != 0 {
            write_guest_pointer(memory, help_out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::GetRefTypeOfImplType(index, phRefType)` — the index
    /// addresses the derived type's real implementation-type table; the
    /// handle resolves through GetRefTypeInfo.
    fn com_type_info_get_ref_type_of_impl_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(info) = self.com_type_infos.get(&this) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(descriptor) = com_type_descriptor(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some((name, _)) = descriptor.impls.get(index as usize) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(target) = com_type_descriptor_by_name(name) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(target_index) = com_type_descriptor_index(target.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, target_index + 1);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::GetImplTypeFlags(index, pImplTypeFlags)` — the flags come
    /// from the registered implementation-type table (dual default vtable /
    /// source dispinterface).
    fn com_type_info_get_impl_type_flags(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(info) = self.com_type_infos.get(&this) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(descriptor) = com_type_descriptor(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some((_, flags)) = descriptor.impls.get(index as usize) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, u32::from(*flags));
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::GetRefTypeInfo(hRefType, ppTInfo)` — materialize the real
    /// ITypeInfo of the referenced interface (IDispatch / IUnknown / the
    /// implemented class interface).
    fn com_type_info_get_ref_type_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let href = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(target) = href
            .checked_sub(1)
            .and_then(|index| COM_TYPE_DESCRIPTORS.get(index as usize))
        else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let object = self.alloc_com_type_info_object(memory, target.table, info.owner, 0)?;
        self.add_ref_guest_object(object)?;
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::GetDllEntry(memid, refType, pBstrDllName, pBstrName,
    /// pwOrdinal)` — the registered DLL/entry/ordinal metadata for a member.
    fn com_type_info_get_dll_entry(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let memid = self.com_arg_i32(state, memory, 1);
        let ref_type = guest_call_arg_u32(state, memory, 2)?;
        let dll_out = guest_call_arg(state, memory, 3)?;
        let name_out = guest_call_arg(state, memory, 4)?;
        let ordinal_out = guest_call_arg(state, memory, 5)?;
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(descriptor) = com_type_descriptor(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if descriptor.kind == ComTypeKind::Class
            || com_dispatch_member(&info.table, memid).is_none()
        {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        }
        if ref_type != 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if dll_out == 0 && name_out == 0 && ordinal_out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if dll_out != 0 {
            let bstr = self.alloc_com_bstr(memory, descriptor.dll_name)?;
            write_guest_pointer(memory, dll_out, bstr, self.guest_arch).ok();
        }
        if name_out != 0 {
            let bstr = self.alloc_com_bstr(memory, descriptor.dll_entry)?;
            write_guest_pointer(memory, name_out, bstr, self.guest_arch).ok();
        }
        if ordinal_out != 0 {
            write_u16(memory, ordinal_out, descriptor.dll_ordinal);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::AddressOfMember(memid, invKind, ppv)` — resolve the real
    /// vtable address of a registered member; dispinterface members resolve
    /// through the owner's IDispatch::Invoke slot.
    fn com_type_info_address_of_member(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let memid = self.com_arg_i32(state, memory, 1);
        let invoke_kind = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let flags = match invoke_kind {
            1 => DISPATCH_METHOD,
            2 => DISPATCH_PROPERTYGET,
            4 | 8 => DISPATCH_PROPERTYPUT,
            _ => {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        let Some(info) = self.com_type_infos.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if info.owner == 0 {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        }
        let Some(member) = com_dispatch_member_for(&info.table, memid, flags) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let slot = if info.table == "ICasa1AutomationEvents" {
            6_u64 // dispinterface members dispatch through IDispatch::Invoke
        } else {
            u64::from(member.slot)
        };
        let vtable = read_guest_pointer(memory, info.owner, self.guest_arch).unwrap_or(0);
        if vtable == 0 {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        }
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let address =
            read_guest_pointer(memory, vtable + slot * pointer_bytes, self.guest_arch).unwrap_or(0);
        if address == 0 {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        }
        write_guest_pointer(memory, out, address, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::CreateInstance(pUnkOuter, riid, ppvObj)` — the coclass
    /// typeinfo creates the real automation server through the class table.
    fn com_type_info_create_instance(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let outer = guest_call_arg(state, memory, 1)?;
        let riid_ptr = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some(info) = self.com_type_infos.get(&this) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(descriptor) = com_type_descriptor(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if descriptor.kind != ComTypeKind::Class {
            state.set(Register::Rax, u64::from(TYPE_E_WRONGTYPEKIND));
            return Ok(());
        }
        if outer != 0 {
            state.set(Register::Rax, u64::from(CLASS_E_NOAGGREGATION));
            return Ok(());
        }
        let riid: [u8; 16] = if riid_ptr != 0 {
            std::array::from_fn(|index| memory.read_u8(riid_ptr + index as u64).unwrap_or(0))
        } else {
            COM_IID_IUNKNOWN
        };
        if riid != COM_IID_IUNKNOWN
            && riid != COM_IID_IDISPATCH
            && riid != COM_IID_ICONNECTIONPOINTCONTAINER
        {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        match self.try_create_com_object(memory, COM_AUTOMATION_SERVER_CLSID, IID_IUNKNOWN, 0)? {
            Some(object) => {
                self.add_ref_guest_object(object)?;
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG)),
        }
        Ok(())
    }

    /// `ITypeInfo::GetMops(memid, pBstrMops)` — registered interfaces carry
    /// no marshaling-op string; known members answer S_OK with a NULL BSTR.
    fn com_type_info_get_mops(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let memid = self.com_arg_i32(state, memory, 1);
        let out = guest_call_arg(state, memory, 2)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        let Some(info) = self.com_type_infos.get(&this) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        if com_dispatch_member(&info.table, memid).is_none() {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::GetContainingTypeLib(ppTLib, pIndex)` — the real ITypeLib
    /// over the registered classes and interfaces.
    fn com_type_info_get_containing_type_lib(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let index_out = guest_call_arg(state, memory, 2)?;
        let Some(info) = self.com_type_infos.get(&this) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let Some(index) = com_type_descriptor_index(&info.table) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let type_lib = self.alloc_com_typelib_object(memory)?;
        self.add_ref_guest_object(type_lib)?;
        if out != 0 {
            write_guest_pointer(memory, out, type_lib, self.guest_arch).ok();
        }
        if index_out != 0 {
            write_u32(memory, index_out, index);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeInfo::GetTypeComp(ppTComp)` — the containing type component.
    fn com_type_info_get_type_comp(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 1)?;
        let type_comp = self.alloc_com_type_comp_object(memory)?;
        self.add_ref_guest_object(type_comp)?;
        if out != 0 {
            write_guest_pointer(memory, out, type_comp, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn alloc_com_typelib_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::TypeLibGetTypeInfoCount),
            HostThunk::ComMethod(ComMethod::TypeLibGetTypeInfo),
            HostThunk::ComMethod(ComMethod::TypeLibUnsupported),
            HostThunk::ComMethod(ComMethod::TypeLibGetTypeInfoOfGuid),
            HostThunk::ComMethod(ComMethod::TypeLibGetLibAttr),
            HostThunk::ComMethod(ComMethod::TypeLibGetTypeComp),
            HostThunk::ComMethod(ComMethod::TypeLibUnsupported),
            HostThunk::ComMethod(ComMethod::TypeLibUnsupported),
            HostThunk::ComMethod(ComMethod::TypeLibUnsupported),
            HostThunk::ComMethod(ComMethod::TypeLibReleaseTLibAttr),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComTypeInfo, vtable)?;
        self.com_type_infos.insert(
            object,
            crate::runtime::state::ComTypeInfoState {
                table: COM_TYPELIB_MARKER.to_string(),
                owner: 0,
                index: 0,
            },
        );
        Ok(object)
    }

    fn alloc_com_type_comp_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::TypeCompBind),
            HostThunk::ComMethod(ComMethod::TypeCompBindType),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComTypeInfo, vtable)?;
        self.com_type_infos.insert(
            object,
            crate::runtime::state::ComTypeInfoState {
                table: COM_TYPECOMP_MARKER.to_string(),
                owner: 0,
                index: 0,
            },
        );
        Ok(object)
    }

    fn com_type_lib_get_type_info_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_u32(memory, out, COM_TYPE_DESCRIPTORS.len() as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_type_lib_get_type_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(descriptor) = COM_TYPE_DESCRIPTORS.get(index as usize) else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let object = self.alloc_com_type_info_object(memory, descriptor.table, 0, index)?;
        self.add_ref_guest_object(object)?;
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_type_lib_get_type_info_of_guid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let guid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if guid_ptr == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let guid: [u8; 16] =
            std::array::from_fn(|index| memory.read_u8(guid_ptr + index as u64).unwrap_or(0));
        let Some(descriptor) = COM_TYPE_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.iid == guid)
        else {
            state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
            return Ok(());
        };
        let index = com_type_descriptor_index(descriptor.table).unwrap_or(0);
        let object = self.alloc_com_type_info_object(memory, descriptor.table, 0, index)?;
        self.add_ref_guest_object(object)?;
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_type_lib_get_lib_attr(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let descriptor = self.alloc_zeroed(memory, 32, 8)?;
        for (index, byte) in COM_AUTOMATION_TYPELIB_IID.iter().enumerate() {
            memory.write_u8(descriptor + index as u64, *byte);
        }
        write_u32(memory, descriptor + 16, 0); // lcid
        write_u32(memory, descriptor + 20, 2); // SYS_WIN32
        write_u16(memory, descriptor + 24, 1); // wMajorVerNum
        write_u16(memory, descriptor + 26, 0); // wMinorVerNum
        write_u32(memory, descriptor + 28, 0); // LIBFLAGS
        write_guest_pointer(memory, out, descriptor, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_type_lib_get_type_comp(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 1)?;
        let type_comp = self.alloc_com_type_comp_object(memory)?;
        self.add_ref_guest_object(type_comp)?;
        if out != 0 {
            write_guest_pointer(memory, out, type_comp, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `ITypeComp::Bind` / `ITypeComp::BindType` — resolve a registered type
    /// name to its real ITypeInfo, and a member name to its ITypeInfo plus
    /// FUNCDESC.  Unknown names answer TYPE_E_ELEMENTNOTFOUND.
    fn com_type_comp_bind(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        bind_type_only: bool,
    ) -> AppResult<()> {
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let _hash = guest_call_arg_u32(state, memory, 2)?;
        let (tinfo_out, desc_out) = if bind_type_only {
            (guest_call_arg(state, memory, 3)?, 0)
        } else {
            (
                guest_call_arg(state, memory, 4)?,
                guest_call_arg(state, memory, 5)?,
            )
        };
        if tinfo_out != 0 {
            write_guest_pointer(memory, tinfo_out, 0, self.guest_arch).ok();
        }
        if desc_out != 0 {
            write_guest_pointer(memory, desc_out, 0, self.guest_arch).ok();
        }
        let Some(name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if let Some(descriptor) = com_type_descriptor_by_name(&name) {
            let index = com_type_descriptor_index(descriptor.table).unwrap_or(0);
            let object = self.alloc_com_type_info_object(memory, descriptor.table, 0, index)?;
            self.add_ref_guest_object(object)?;
            if tinfo_out != 0 {
                write_guest_pointer(memory, tinfo_out, object, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        if !bind_type_only {
            let found = COM_TYPE_DESCRIPTORS
                .iter()
                .filter(|descriptor| descriptor.kind != ComTypeKind::Class)
                .find_map(|descriptor| {
                    com_dispatch_member_by_name(descriptor.table, &name)
                        .map(|member| (descriptor, member))
                });
            if let Some((descriptor, member)) = found {
                let index = com_type_descriptor_index(descriptor.table).unwrap_or(0);
                let object = self.alloc_com_type_info_object(memory, descriptor.table, 0, index)?;
                let func_desc = self.alloc_func_desc(memory, member)?;
                self.add_ref_guest_object(object)?;
                if tinfo_out != 0 {
                    write_guest_pointer(memory, tinfo_out, object, self.guest_arch).ok();
                }
                if desc_out != 0 {
                    write_guest_pointer(memory, desc_out, func_desc, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
        }
        state.set(Register::Rax, u64::from(TYPE_E_ELEMENTNOTFOUND));
        Ok(())
    }

    fn com_type_info_unsupported(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _ = memory;
        state.set(Register::Rax, u64::from(E_NOTIMPL));
        Ok(())
    }

    /// Create the ITypeInfo object generated from a registered dispatch
    /// table.
    pub(crate) fn alloc_com_type_info_object(
        &mut self,
        memory: &mut MemoryImage,
        table: &str,
        owner: u64,
        index: u32,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::ComMethod(ComMethod::TypeInfoGetTypeAttr),
            HostThunk::ComMethod(ComMethod::TypeInfoGetTypeComp),
            HostThunk::ComMethod(ComMethod::TypeInfoGetFuncDesc),
            HostThunk::ComMethod(ComMethod::TypeInfoGetVarDesc),
            HostThunk::ComMethod(ComMethod::TypeInfoGetNames),
            HostThunk::ComMethod(ComMethod::TypeInfoGetRefTypeOfImplType),
            HostThunk::ComMethod(ComMethod::TypeInfoGetImplTypeFlags),
            HostThunk::ComMethod(ComMethod::TypeInfoGetIDsOfNames),
            HostThunk::ComMethod(ComMethod::TypeInfoInvoke),
            HostThunk::ComMethod(ComMethod::TypeInfoGetDocumentation),
            HostThunk::ComMethod(ComMethod::TypeInfoGetDllEntry),
            HostThunk::ComMethod(ComMethod::TypeInfoGetRefTypeInfo),
            HostThunk::ComMethod(ComMethod::TypeInfoAddressOfMember),
            HostThunk::ComMethod(ComMethod::TypeInfoCreateInstance),
            HostThunk::ComMethod(ComMethod::TypeInfoGetMops),
            HostThunk::ComMethod(ComMethod::TypeInfoGetContainingTypeLib),
            HostThunk::ComMethod(ComMethod::TypeInfoReleaseTypeAttr),
            HostThunk::ComMethod(ComMethod::TypeInfoReleaseFuncDesc),
            HostThunk::ComMethod(ComMethod::TypeInfoReleaseVarDesc),
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComTypeInfo, vtable)?;
        self.com_type_infos.insert(
            object,
            crate::runtime::state::ComTypeInfoState {
                table: table.to_string(),
                owner,
                index,
            },
        );
        Ok(object)
    }

    // ── Event firing through the advised sinks ──────────────────────────────

    /// Deliver one automation event to every advised sink of the server's
    /// connection point, recording each delivery.
    fn fire_automation_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        source: u64,
        dispid: i32,
        args: &[ComValue],
    ) -> AppResult<()> {
        let container = match self.com_servers.get(&source) {
            Some(server) if server.container != 0 => server.container,
            _ => return Ok(()),
        };
        let points: Vec<u64> = self
            .com_connection_points
            .get(&container)
            .map(|container| container.points.values().copied().collect())
            .unwrap_or_default();
        let mut sinks = Vec::new();
        for point in &points {
            if let Some(point_state) = self.com_connection_points.get(point) {
                sinks.extend(point_state.sinks.iter().map(|(_, sink)| *sink));
            }
        }
        for sink in sinks {
            let hr = self.invoke_dispatch_sink(state, memory, sink, dispid, args)?;
            self.com_fired_events
                .push(crate::runtime::state::ComFiredEvent {
                    source,
                    dispid,
                    sink,
                    hr,
                });
        }
        Ok(())
    }

    /// Call `sink->IDispatch::Invoke(dispid, DISPATCH_METHOD, params, ...)`
    /// through the sink's real vtable slot: a guest-code sink runs through
    /// the guest callback path, a runtime sink through the dispatch path.
    fn invoke_dispatch_sink(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        sink: u64,
        dispid: i32,
        args: &[ComValue],
    ) -> AppResult<u32> {
        let vtable = read_guest_pointer(memory, sink, self.guest_arch).unwrap_or(0);
        if vtable == 0 {
            return Ok(E_UNEXPECTED);
        }
        let slot = 6_u64; // IDispatch::Invoke
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let function =
            read_guest_pointer(memory, vtable + slot * pointer_bytes, self.guest_arch).unwrap_or(0);
        if function == 0 {
            return Ok(E_UNEXPECTED);
        }
        let (params, result, exception, argument_error) =
            self.build_dispatch_invocation(memory, args)?;
        let call_args = [
            sink,
            dispid as u32 as u64,
            0,
            0,
            DISPATCH_METHOD as u64,
            params,
            result,
            exception,
            argument_error,
        ];
        let hr = if self.host_thunks.contains_key(&function) {
            let frame = self.alloc_zeroed(memory, 0x100, 4)?;
            write_u32(memory, frame, 0); // synthetic return address
            for (index, argument) in call_args.iter().enumerate() {
                write_u32(memory, frame + 4 + index as u64 * 4, *argument as u32);
            }
            let saved_rsp = state.get(Register::Rsp);
            let saved_rip = state.rip;
            state.set(Register::Rsp, frame);
            let dispatched = self.dispatch_import(function, state, memory);
            state.set(Register::Rsp, saved_rsp);
            state.rip = saved_rip;
            match dispatched {
                Ok(_) => state.get(Register::Rax) as u32,
                Err(_) => E_UNEXPECTED,
            }
        } else {
            self.execute_guest_callback(state, memory, function, &call_args, "IDispatch::Invoke")?
                as u32
        };
        Ok(hr)
    }

    fn com_sink_invoke(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let dispid = self.com_arg_i32(state, memory, 1);
        let params = guest_call_arg(state, memory, 5)?;
        let result = guest_call_arg(state, memory, 6)?;
        let values = self.read_dispparams_values(memory, params);
        self.com_sink_invocations
            .push((this, dispid, values.clone()));
        self.write_variant_empty(memory, result);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Read a DISPPARAMS' rgvarg array into types, in `rgvarg` order (the
    /// array is stored reversed: index 0 is the last argument).
    fn read_dispparams_values(&mut self, memory: &mut MemoryImage, params: u64) -> Vec<ComValue> {
        if params == 0 {
            return Vec::new();
        }
        let count_offset = match self.guest_arch {
            GuestArch::X86 => 8,
            GuestArch::X64 => 16,
        };
        let count = memory.read_u32(params + count_offset).unwrap_or(0) as usize;
        let rgvarg = read_guest_pointer(memory, params, self.guest_arch).unwrap_or(0);
        let mut values = Vec::with_capacity(count);
        for index in 0..count.min(256) {
            let variant = rgvarg + index as u64 * self.com_variant_size();
            match self.read_variant_value(memory, variant) {
                Ok(Some(value)) => values.push(value),
                _ => values.push(ComValue::Empty),
            }
        }
        values
    }

    /// Build the guest DISPPARAMS + result + EXCEPINFO block for a sink
    /// invocation with the given logical argument order.
    fn build_dispatch_invocation(
        &mut self,
        memory: &mut MemoryImage,
        args: &[ComValue],
    ) -> AppResult<(u64, u64, u64, u64)> {
        let count = args.len();
        let variant_size = self.com_variant_size();
        let rgvarg = if count == 0 {
            0
        } else {
            self.alloc_zeroed(memory, (variant_size * count as u64) as usize, 8)?
        };
        // DISPPARAMS stores the arguments reversed: rgvarg[0] is the last.
        for (index, argument) in args.iter().enumerate() {
            let position = count - 1 - index;
            let variant = rgvarg + position as u64 * variant_size;
            self.write_variant_value(memory, variant, argument)?;
        }
        let params_size = match self.guest_arch {
            GuestArch::X86 => 16,
            GuestArch::X64 => 24,
        };
        let params = self.alloc_zeroed(memory, params_size, 8)?;
        write_guest_pointer(memory, params, rgvarg, self.guest_arch).ok();
        let count_offset = match self.guest_arch {
            GuestArch::X86 => 8,
            GuestArch::X64 => 16,
        };
        write_u32(memory, params + count_offset, count as u32);
        let result = self.alloc_zeroed(memory, variant_size as usize, 8)?;
        let exception = self.alloc_zeroed(
            memory,
            match self.guest_arch {
                GuestArch::X86 => 32,
                GuestArch::X64 => 64,
            },
            8,
        )?;
        let argument_error = self.alloc_zeroed(memory, 4, 4)?;
        Ok((params, result, exception, argument_error))
    }

    /// The shared `GetIDsOfNames` body (IDispatch and ITypeInfo share the
    /// registered table lookup).
    fn com_get_ids_of_names(
        &mut self,
        memory: &mut MemoryImage,
        this: u64,
        names_ptr: u64,
        count: u32,
        _lcid: u32,
        ids_ptr: u64,
    ) -> AppResult<u32> {
        if names_ptr == 0 || ids_ptr == 0 {
            return Ok(E_POINTER);
        }
        let table_name = match self.com_servers.get(&this) {
            Some(server) => server.table.clone(),
            None => match self.com_type_infos.get(&this) {
                Some(info) => info.table.clone(),
                None => return Ok(E_NOINTERFACE),
            },
        };
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let mut all_found = true;
        for index in 0..count.min(256) {
            let name_ptr = read_guest_pointer(
                memory,
                names_ptr + index as u64 * pointer_bytes,
                self.guest_arch,
            )
            .unwrap_or(0);
            let name = read_utf16_string(memory, name_ptr).unwrap_or_default();
            match self.com_resolve_dispid(this, &table_name, &name) {
                Some(dispid) => write_u32(memory, ids_ptr + index as u64 * 4, dispid as u32),
                None => {
                    all_found = false;
                    write_u32(memory, ids_ptr + index as u64 * 4, DISPID_UNKNOWN as u32);
                }
            }
        }
        Ok(if all_found { S_OK } else { DISP_E_UNKNOWNNAME })
    }

    // ── IMoniker: real parse + bind ─────────────────────────────────────────

    /// `MkParseDisplayName(pbc, szUserName, pchEaten, ppmk)` — parse the
    /// moniker forms the runtime models: `file:`/bare Windows paths (file
    /// monikers over the real filesystem), `clsid:` GUIDs and registered
    /// ProgIDs (class monikers), and http(s) URLs (URL monikers).  Malformed
    /// names fail with `MK_E_SYNTAX` and `pchEaten` reports the consumed
    /// prefix for the parsed forms.
    pub(crate) fn dispatch_com_mk_parse_display_name(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let name_ptr = guest_call_arg(state, memory, 1)?;
        let eaten_out = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        let Some(raw_name) = read_utf16_string(memory, name_ptr).ok() else {
            state.set(Register::Rax, u64::from(MK_E_SYNTAX));
            return Ok(());
        };
        let Some((moniker_state, eaten)) = self.parse_com_display_name(&raw_name) else {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(MK_E_SYNTAX));
            return Ok(());
        };
        let moniker = match self.alloc_com_moniker_object(memory, moniker_state) {
            Ok(moniker) => moniker,
            Err(_) => {
                state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
                return Ok(());
            }
        };
        if eaten_out != 0 {
            write_u32(memory, eaten_out, eaten);
        }
        if out != 0 {
            write_guest_pointer(memory, out, moniker, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Parse one display name into a moniker state plus the number of
    /// consumed UTF-16 units; `None` for a name the runtime cannot model.
    fn parse_com_display_name(
        &mut self,
        raw_name: &str,
    ) -> Option<(crate::runtime::state::ComMonikerState, u32)> {
        // Leading whitespace is consumed like the real MkParseDisplayName.
        let leading = raw_name.len() - raw_name.trim_start().len();
        let name = raw_name.trim_start();
        let eaten = raw_name.encode_utf16().count() as u32;
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("item:") {
            let payload = &name[5..];
            if payload.is_empty() {
                return None;
            }
            return Some((
                crate::runtime::state::ComMonikerState {
                    kind: crate::runtime::state::ComMonikerKind::File,
                    display_name: name.to_string(),
                    payload: format!("{COM_ITEM_PREFIX}{payload}"),
                    host_path: None,
                },
                eaten,
            ));
        }
        if lower.starts_with("file:") {
            let mut payload = &name[5..];
            if let Some(rest) = payload.strip_prefix("//") {
                payload = rest;
            }
            if payload.is_empty() {
                return None;
            }
            let host_path = self
                .win32
                .guest_path_to_host_path(payload)
                .ok()
                .map(|path| path.to_string_lossy().to_string());
            return Some((
                crate::runtime::state::ComMonikerState {
                    kind: crate::runtime::state::ComMonikerKind::File,
                    display_name: name.to_string(),
                    payload: payload.to_string(),
                    host_path,
                },
                eaten,
            ));
        }
        if lower.starts_with("clsid:") {
            let payload = &name[6..];
            if Self::parse_guid_string(payload).is_none() {
                return None;
            }
            return Some((
                crate::runtime::state::ComMonikerState {
                    kind: crate::runtime::state::ComMonikerKind::Class,
                    display_name: name.to_string(),
                    payload: payload.to_string(),
                    host_path: None,
                },
                eaten,
            ));
        }
        if lower.starts_with("http:") || lower.starts_with("https:") {
            return Some((
                crate::runtime::state::ComMonikerState {
                    kind: crate::runtime::state::ComMonikerKind::Url,
                    display_name: name.to_string(),
                    payload: name.to_string(),
                    host_path: None,
                },
                eaten,
            ));
        }
        // A bare Windows path (`C:\...`, `\\server\share`, or a path with a
        // directory separator) is a file moniker.
        let looks_like_path = name.len() >= 2
            && name.as_bytes()[1] == b':'
            && name.chars().nth(2).is_some_and(|c| c == '\\' || c == '/')
            || name.starts_with("\\\\")
            || name.contains('\\');
        if looks_like_path {
            let host_path = self
                .win32
                .guest_path_to_host_path(name)
                .ok()
                .map(|path| path.to_string_lossy().to_string());
            return Some((
                crate::runtime::state::ComMonikerState {
                    kind: crate::runtime::state::ComMonikerKind::File,
                    display_name: name.to_string(),
                    payload: name.to_string(),
                    host_path,
                },
                eaten,
            ));
        }
        // A registered ProgID (HKCR\<progid>\CLSID) is a class moniker.
        if !name.is_empty() {
            let key = format!("{name}\\CLSID");
            if let Some(value) = self
                .win32
                .registry_get_value("HKCR", &key, "", RegistryView::Native)
                .ok()
                .flatten()
            {
                let clsid = value.data.as_str().map(str::to_string).unwrap_or_default();
                if Self::parse_guid_string(&clsid).is_some() {
                    return Some((
                        crate::runtime::state::ComMonikerState {
                            kind: crate::runtime::state::ComMonikerKind::Class,
                            display_name: name.to_string(),
                            payload: clsid,
                            host_path: None,
                        },
                        eaten,
                    ));
                }
            }
        }
        let _ = leading;
        None
    }

    /// The component chain of a composite moniker (object ids), encoded in
    /// the moniker payload markers.
    fn com_composite_chain(&self, object: u64) -> Option<Vec<u64>> {
        let payload = self.com_monikers.get(&object)?.payload.as_str();
        let rest = payload.strip_prefix(COM_COMPOSITE_PREFIX)?;
        Some(
            rest.split(',')
                .filter_map(|id| id.parse::<u64>().ok())
                .collect(),
        )
    }

    fn com_item_name(&self, object: u64) -> Option<String> {
        let payload = self.com_monikers.get(&object)?.payload.as_str();
        payload
            .strip_prefix(COM_ITEM_PREFIX)
            .map(str::to_string)
            .filter(|name| !name.is_empty())
    }

    /// Bind the first component of a composite chain, then validate every
    /// item component against the bound object (server member / storage
    /// element).
    fn bind_composite_object(
        &mut self,
        memory: &mut MemoryImage,
        chain: &[u64],
    ) -> AppResult<(u32, u64)> {
        let Some(first) = chain.first().copied() else {
            return Ok((MK_E_NOOBJECT, 0));
        };
        let Some(state) = self.com_monikers.get(&first).cloned() else {
            return Ok((MK_E_NOOBJECT, 0));
        };
        if state.payload.starts_with(COM_ITEM_PREFIX) {
            return Ok((MK_E_NOOBJECT, 0));
        }
        let (hr, object) = match state.kind {
            crate::runtime::state::ComMonikerKind::File => {
                let Some(host_path) = state.host_path.clone() else {
                    return Ok((MK_E_NOOBJECT, 0));
                };
                let path = std::path::Path::new(&host_path);
                if !path.exists() {
                    return Ok((MK_E_NOOBJECT, 0));
                }
                if host_path.to_ascii_lowercase().ends_with(".lnk") {
                    (S_OK, self.alloc_shell_link_object(memory)?)
                } else {
                    let bytes = std::fs::read(&host_path).unwrap_or_default();
                    if let Some(clsid) = ole_embedded_clsid(&bytes) {
                        let clsid_text = Self::guid_bytes_to_string(&clsid);
                        match self.try_create_com_object(memory, &clsid_text, IID_IUNKNOWN, 0)? {
                            Some(object) => (S_OK, object),
                            None => (REGDB_E_CLASSNOTREG, 0),
                        }
                    } else if path.is_dir() {
                        let name = path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("")
                            .to_string();
                        let storage =
                            self.alloc_com_storage_object(memory, Some(host_path), &name, 0)?;
                        (S_OK, storage)
                    } else if bytes.len() >= 8
                        && bytes[..8] == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
                    {
                        match self.alloc_com_compound_storage(memory, &host_path, 0, false)? {
                            Ok(storage) => (S_OK, storage),
                            Err(hr) => (hr, 0),
                        }
                    } else {
                        (MK_E_NOOBJECT, 0)
                    }
                }
            }
            crate::runtime::state::ComMonikerKind::Class => {
                match Self::parse_guid_string(&state.payload) {
                    Some(_) => {
                        match self.try_create_com_object(memory, &state.payload, IID_IUNKNOWN, 0)? {
                            Some(object) => (S_OK, object),
                            None => (REGDB_E_CLASSNOTREG, 0),
                        }
                    }
                    None => (MK_E_NOOBJECT, 0),
                }
            }
            crate::runtime::state::ComMonikerKind::Url => (MK_E_NOOBJECT, 0),
        };
        if hr != S_OK {
            return Ok((hr, 0));
        }
        for component in chain.iter().skip(1) {
            let Some(item) = self.com_item_name(*component) else {
                return Ok((MK_E_NOOBJECT, 0));
            };
            if let Some(server) = self.com_servers.get(&object) {
                if com_dispatch_member_by_name(&server.table, &item).is_none() {
                    return Ok((MK_E_NOOBJECT, 0));
                }
            } else if let Some(storage) = self.com_storages.get(&object) {
                if !storage.streams.contains_key(&item)
                    && !storage.child_storages.contains_key(&item)
                {
                    return Ok((MK_E_NOOBJECT, 0));
                }
            } else {
                return Ok((MK_E_NOOBJECT, 0));
            }
        }
        Ok((S_OK, object))
    }

    /// Resolve a composite chain's first component to its storage and walk
    /// item components down that storage (the real file+item route).
    fn bind_composite_storage(
        &mut self,
        memory: &mut MemoryImage,
        chain: &[u64],
    ) -> AppResult<(u32, u64)> {
        let Some(first) = chain.first().copied() else {
            return Ok((MK_E_NOOBJECT, 0));
        };
        let Some(state) = self.com_monikers.get(&first).cloned() else {
            return Ok((MK_E_NOOBJECT, 0));
        };
        if state.kind != crate::runtime::state::ComMonikerKind::File
            || state.payload.starts_with(COM_ITEM_PREFIX)
        {
            return Ok((MK_E_NOOBJECT, 0));
        }
        let Some(host_path) = state.host_path.clone() else {
            return Ok((MK_E_NOOBJECT, 0));
        };
        let path = std::path::Path::new(&host_path);
        if !path.exists() {
            return Ok((MK_E_NOOBJECT, 0));
        }
        let mut object = if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string();
            self.alloc_com_storage_object(memory, Some(host_path), &name, 0)?
        } else {
            match self.alloc_com_compound_storage(memory, &host_path, 0, false)? {
                Ok(storage) => storage,
                Err(hr) => return Ok((hr, 0)),
            }
        };
        if chain.len() == 1 {
            return Ok((S_OK, object));
        }
        let rest = &chain[1..];
        for (index, component) in rest.iter().enumerate() {
            let Some(item) = self.com_item_name(*component) else {
                return Ok((MK_E_NOOBJECT, 0));
            };
            let last = index + 1 == rest.len();
            let stream_data = self
                .com_storages
                .get(&object)
                .and_then(|storage| storage.streams.get(&item).cloned());
            let child = self
                .com_storages
                .get(&object)
                .and_then(|storage| storage.child_storages.get(&item).copied());
            if let Some(data) = stream_data {
                if !last {
                    return Ok((MK_E_NOOBJECT, 0));
                }
                let stream = self.alloc_com_stream_object(memory, data, &item, None)?;
                object = stream;
            } else if let Some(child) = child {
                object = child;
            } else {
                return Ok((MK_E_NOOBJECT, 0));
            }
        }
        Ok((S_OK, object))
    }

    /// Create a guest IMoniker object for a parsed display name.
    pub(crate) fn alloc_com_moniker_object(
        &mut self,
        memory: &mut MemoryImage,
        moniker_state: crate::runtime::state::ComMonikerState,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ComMethod(ComMethod::QueryInterface),
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::MonikerBindToObject,
            HostThunk::MonikerBindToStorage,
            HostThunk::MonikerReduce,
            HostThunk::MonikerComposeWith,
            HostThunk::MonikerGetDisplayName,
            HostThunk::MonikerEnum,
            HostThunk::MonikerIsSystemMoniker,
            HostThunk::MonikerHash,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComFileMoniker, vtable)?;
        self.com_moniker_names
            .insert(object, moniker_state.display_name.clone());
        self.com_monikers.insert(object, moniker_state);
        Ok(object)
    }

    pub(crate) fn dispatch_com_moniker_bind_to_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let riid = if riid_ptr != 0 {
            std::array::from_fn(|index| memory.read_u8(riid_ptr + index as u64).unwrap_or(0))
        } else {
            COM_IID_IUNKNOWN
        };
        if let Some(chain) = self.com_composite_chain(this) {
            let (hr, object) = self.bind_composite_object(memory, &chain)?;
            if hr == S_OK {
                self.add_ref_guest_object(object)?;
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(hr));
            return Ok(());
        }
        match self.com_moniker_object_for(this) {
            ComMonikerKind::File => {
                let Some(host_path) = self
                    .com_monikers
                    .get(&this)
                    .and_then(|moniker| moniker.host_path.clone())
                else {
                    state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
                    return Ok(());
                };
                if !std::path::Path::new(&host_path).exists() {
                    state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
                    return Ok(());
                }
                let is_link = host_path.to_ascii_lowercase().ends_with(".lnk");
                if is_link {
                    let object = self.alloc_shell_link_object(memory)?;
                    self.add_ref_guest_object(object)?;
                    write_guest_pointer(memory, out, object, self.guest_arch).ok();
                    state.set(Register::Rax, u64::from(S_OK));
                    return Ok(());
                }
                let bytes = std::fs::read(&host_path).unwrap_or_default();
                if let Some(clsid) = ole_embedded_clsid(&bytes) {
                    let clsid_text = Self::guid_bytes_to_string(&clsid);
                    match self.try_create_com_object(memory, &clsid_text, IID_IUNKNOWN, 0)? {
                        Some(object) => {
                            self.add_ref_guest_object(object)?;
                            write_guest_pointer(memory, out, object, self.guest_arch).ok();
                            state.set(Register::Rax, u64::from(S_OK));
                        }
                        None => state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG)),
                    }
                } else {
                    // No handler is registered for a plain file: the honest
                    // moniker-bind answer.
                    state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
                }
                let _ = riid;
                Ok(())
            }
            ComMonikerKind::Class => {
                let payload = self
                    .com_monikers
                    .get(&this)
                    .map(|moniker| moniker.payload.clone())
                    .unwrap_or_default();
                match Self::parse_guid_string(&payload) {
                    Some(_) => {
                        match self.try_create_com_object(memory, &payload, IID_IUNKNOWN, 0)? {
                            Some(object) => {
                                self.add_ref_guest_object(object)?;
                                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                                state.set(Register::Rax, u64::from(S_OK));
                            }
                            None => state.set(Register::Rax, u64::from(REGDB_E_CLASSNOTREG)),
                        }
                    }
                    None => state.set(Register::Rax, u64::from(MK_E_NOOBJECT)),
                }
                Ok(())
            }
            ComMonikerKind::Url => {
                // The runtime models no URL object handlers: the honest
                // MK_E_NOOBJECT (a real bind would need a protocol handler).
                state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
                Ok(())
            }
        }
    }

    pub(crate) fn dispatch_com_moniker_bind_to_storage(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let riid = if riid_ptr != 0 {
            std::array::from_fn(|index| memory.read_u8(riid_ptr + index as u64).unwrap_or(0))
        } else {
            COM_IID_IUNKNOWN
        };
        let kind = self.com_moniker_object_for(this);
        if let Some(chain) = self.com_composite_chain(this) {
            let (hr, object) = self.bind_composite_storage(memory, &chain)?;
            if hr == S_OK {
                self.add_ref_guest_object(object)?;
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(hr));
            return Ok(());
        }
        if kind == ComMonikerKind::Url {
            state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
            return Ok(());
        }
        let Some(host_path) = self
            .com_monikers
            .get(&this)
            .and_then(|moniker| moniker.host_path.clone())
        else {
            state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
            return Ok(());
        };
        let path = std::path::Path::new(&host_path);
        if !path.exists() {
            state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
            return Ok(());
        }
        let want_storage = riid == COM_IID_ISTORAGE;
        let want_stream = riid == COM_IID_ISTREAM || riid == COM_IID_ISEQUENTIALSTREAM;
        let wants_default = riid == COM_IID_IUNKNOWN || riid.iter().all(|byte| *byte == 0);
        if path.is_dir() {
            if want_stream {
                state.set(Register::Rax, u64::from(E_NOINTERFACE));
                return Ok(());
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string();
            let storage = self.alloc_com_storage_object(memory, Some(host_path), &name, 0)?;
            self.add_ref_guest_object(storage)?;
            write_guest_pointer(memory, out, storage, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        if want_storage {
            // A file's IStorage is its real OLE compound file; a non-OLE
            // file has no storage (STG_E_INVALIDHEADER, the real answer).
            match self.alloc_com_compound_storage(memory, &host_path, 0, false)? {
                Ok(storage) => {
                    self.add_ref_guest_object(storage)?;
                    write_guest_pointer(memory, out, storage, self.guest_arch).ok();
                    state.set(Register::Rax, u64::from(S_OK));
                }
                Err(hr) => state.set(Register::Rax, u64::from(hr)),
            }
            return Ok(());
        }
        if want_stream || wants_default {
            let stream = self.alloc_com_stream_from_file(memory, &host_path)?;
            self.add_ref_guest_object(stream)?;
            write_guest_pointer(memory, out, stream, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(E_NOINTERFACE));
        Ok(())
    }

    pub(crate) fn dispatch_com_moniker_reduce(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let reduced_out = guest_call_arg(state, memory, 4)?;
        if reduced_out != 0 {
            write_guest_pointer(memory, reduced_out, 0, self.guest_arch).ok();
        }
        if let Some(chain) = self.com_composite_chain(this)
            && chain.len() == 1
        {
            let component = chain[0];
            self.add_ref_guest_object(component)?;
            if reduced_out != 0 {
                write_guest_pointer(memory, reduced_out, component, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(MK_E_REDUCED_TO_SELF));
        Ok(())
    }

    /// `IMoniker::ComposeWith(pmkRight, fDeleteThis, ppmkComposite)` — build
    /// a real composite chain (flattening nested composites, joining display
    /// names with `!`).
    pub(crate) fn dispatch_com_moniker_compose_with(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let other = guest_call_arg(state, memory, 1)?;
        let delete_this = guest_call_arg_u32(state, memory, 2)?;
        let composite_out = guest_call_arg(state, memory, 3)?;
        if composite_out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, composite_out, 0, self.guest_arch).ok();
        if other == 0 || other == this {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let other_exists = self.com_monikers.contains_key(&other)
            || matches!(
                self.guest_object_kind(other),
                Ok(GuestObjectKind::UrlMoniker)
            );
        if !other_exists {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut chain = self.com_composite_chain(this).unwrap_or_else(|| vec![this]);
        if let Some(right) = self.com_composite_chain(other) {
            chain.extend(right);
        } else {
            chain.push(other);
        }
        if chain.iter().filter(|id| **id == this).count() > 1 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut names = Vec::with_capacity(chain.len());
        for component in &chain {
            let Some(name) = self
                .com_monikers
                .get(component)
                .map(|moniker| moniker.display_name.clone())
            else {
                state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
                return Ok(());
            };
            names.push(name);
        }
        let display_name = names.join("!");
        let payload = format!(
            "{COM_COMPOSITE_PREFIX}{}",
            chain
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let moniker_state = crate::runtime::state::ComMonikerState {
            kind: crate::runtime::state::ComMonikerKind::File,
            display_name,
            payload,
            host_path: None,
        };
        let composite = self.alloc_com_moniker_object(memory, moniker_state)?;
        if delete_this != 0 {
            let _ = self.release_guest_object(this);
        }
        write_guest_pointer(memory, composite_out, composite, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    pub(crate) fn dispatch_com_moniker_get_display_name(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 3)?;
        let name = self
            .com_monikers
            .get(&this)
            .map(|moniker| moniker.display_name.clone())
            .or_else(|| self.com_moniker_names.get(&this).cloned())
            .unwrap_or_default();
        if name.is_empty() {
            state.set(Register::Rax, u64::from(MK_E_NOOBJECT));
            return Ok(());
        }
        let bstr = self.alloc_com_bstr(memory, &name)?;
        if out != 0 {
            write_guest_pointer(memory, out, bstr, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    pub(crate) fn dispatch_com_moniker_enum(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let forward = guest_call_arg_u32(state, memory, 1)? != 0;
        let out = guest_call_arg(state, memory, 2)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        let Some(chain) = self.com_composite_chain(this) else {
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        };
        let mut components = chain;
        if !forward {
            components.reverse();
        }
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let items = components
            .iter()
            .map(|component| pointer_bytes_bytes(*component, pointer_bytes))
            .collect();
        let enumerator = self.alloc_com_enum_object(memory, items)?;
        if out != 0 {
            write_guest_pointer(memory, out, enumerator, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    pub(crate) fn dispatch_com_moniker_is_system_moniker(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let code = if self.com_composite_chain(this).is_some() {
            1 // MKSYS_GENERICCOMPOSITE
        } else if self.com_item_name(this).is_some() {
            4 // MKSYS_ITEMMONIKER
        } else {
            match self.com_moniker_object_for(this) {
                ComMonikerKind::File => 2,  // MKSYS_FILEMONIKER
                ComMonikerKind::Class => 6, // MKSYS_CLASSMONIKER
                ComMonikerKind::Url => 7,   // MKSYS_OBJREFMONIKER (URL moniker family)
            }
        };
        if out != 0 {
            write_u32(memory, out, code);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    pub(crate) fn dispatch_com_moniker_hash(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let name = self
            .com_monikers
            .get(&this)
            .map(|moniker| moniker.display_name.clone())
            .unwrap_or_default();
        let mut hash: u32 = 0;
        for unit in name.encode_utf16() {
            hash = (hash << 4).wrapping_add(unit as u32);
            let top = hash & 0xF000_0000;
            if top != 0 {
                hash ^= top >> 24;
            }
            hash &= !0xF000_0000;
        }
        if out != 0 {
            write_u32(memory, out, hash);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn com_moniker_object_for(&self, object: u64) -> crate::runtime::state::ComMonikerKind {
        if let Some(moniker) = self.com_monikers.get(&object) {
            return moniker.kind;
        }
        if matches!(
            self.guest_object_kind(object),
            Ok(GuestObjectKind::UrlMoniker)
        ) {
            return crate::runtime::state::ComMonikerKind::Url;
        }
        crate::runtime::state::ComMonikerKind::File
    }
}

/// Encode one pointer-sized value as raw little-endian bytes.
fn pointer_bytes_bytes(value: u64, pointer_bytes: u64) -> Vec<u8> {
    value.to_le_bytes()[..pointer_bytes as usize].to_vec()
}

/// Encode one CONNECTDATA (interface pointer + cookie) for the guest
/// architecture.
fn connect_data_bytes(sink: u64, cookie: u32, pointer_bytes: u64) -> Vec<u8> {
    let mut bytes = pointer_bytes_bytes(sink, pointer_bytes);
    bytes.extend_from_slice(&cookie.to_le_bytes());
    if pointer_bytes == 8 {
        bytes.extend_from_slice(&0_u32.to_le_bytes());
    }
    bytes
}

/// Convert a Windows FILETIME tick count into a `SystemTime` (the IStorage
/// element-time path); returns `None` for an unrepresentable value.
fn filetime_to_system_time(ticks: u64) -> Option<std::time::SystemTime> {
    const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
    const WINDOWS_EPOCH_OFFSET_SECONDS: u64 = 11_644_473_600;
    let seconds = ticks / WINDOWS_TICKS_PER_SECOND;
    let nanos = ((ticks % WINDOWS_TICKS_PER_SECOND) * 100) as u32;
    let unix_seconds = seconds.checked_sub(WINDOWS_EPOCH_OFFSET_SECONDS)?;
    Some(std::time::UNIX_EPOCH + std::time::Duration::new(unix_seconds, nanos))
}

// ── COM interface method identities (the vtable thunk payloads) ────────────

/// Every runtime COM interface method dispatched through a guest vtable.
/// The variant doubles as the ABI identity of one vtable slot: the
/// dispatcher pops `x86_arg_bytes()` bytes after the stdcall call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComMethod {
    QueryInterface,
    StreamRead,
    StreamWrite,
    StreamSeek,
    StreamSetSize,
    StreamCopyTo,
    StreamCommit,
    StreamRevert,
    StreamLockRegion,
    StreamUnlockRegion,
    StreamStat,
    StreamClone,
    StorageCreateStream,
    StorageOpenStream,
    StorageCreateStorage,
    StorageOpenStorage,
    StorageCopyTo,
    StorageMoveElement,
    StorageCommit,
    StorageRevert,
    StorageEnumElements,
    StorageDestroyElement,
    StorageRenameElement,
    StorageSetElementTimes,
    StorageSetClass,
    StorageSetStateBits,
    StorageStat,
    EnumConnectionPoints,
    FindConnectionPoint,
    GetConnectionInterface,
    GetConnectionPointContainer,
    Advise,
    Unadvise,
    EnumConnections,
    EnumNext,
    EnumSkip,
    EnumReset,
    EnumClone,
    DispatchGetTypeInfoCount,
    DispatchGetTypeInfo,
    DispatchGetIDsOfNames,
    DispatchInvoke,
    TypeInfoGetTypeAttr,
    TypeInfoGetTypeComp,
    TypeInfoGetFuncDesc,
    TypeInfoGetVarDesc,
    TypeInfoGetNames,
    TypeInfoGetRefTypeOfImplType,
    TypeInfoGetImplTypeFlags,
    TypeInfoGetIDsOfNames,
    TypeInfoInvoke,
    TypeInfoGetDocumentation,
    TypeInfoGetDllEntry,
    TypeInfoGetRefTypeInfo,
    TypeInfoAddressOfMember,
    TypeInfoCreateInstance,
    TypeInfoGetMops,
    TypeInfoGetContainingTypeLib,
    TypeLibGetLibAttr,
    TypeLibReleaseTLibAttr,
    TypeLibGetTypeInfoCount,
    TypeLibGetTypeInfo,
    TypeLibGetTypeInfoOfGuid,
    TypeLibGetTypeComp,
    TypeLibUnsupported,
    TypeCompBind,
    TypeCompBindType,
    TypeInfoReleaseTypeAttr,
    TypeInfoReleaseFuncDesc,
    TypeInfoReleaseVarDesc,
    TypeInfoUnsupported,
    ServerGetValue,
    ServerPutValue,
    ServerGetName,
    ServerPutName,
    ServerGetCount,
    ServerAdd,
    ServerReset,
    ServerFireValueChanged,
    SinkInvoke,
}

impl ComMethod {
    /// The stdcall argument bytes the x86 dispatcher pops after the call.
    pub fn x86_arg_bytes(&self) -> u64 {
        match self {
            ComMethod::QueryInterface => 12,
            ComMethod::StreamRead | ComMethod::StreamWrite => 16,
            ComMethod::StreamSeek => 20,
            ComMethod::StreamSetSize => 12,
            ComMethod::StreamCopyTo => 24,
            ComMethod::StreamCommit => 8,
            ComMethod::StreamRevert => 4,
            ComMethod::StreamLockRegion | ComMethod::StreamUnlockRegion => 24,
            ComMethod::StreamStat => 12,
            ComMethod::StreamClone => 8,
            ComMethod::StorageCreateStream | ComMethod::StorageCreateStorage => 20,
            ComMethod::StorageOpenStream | ComMethod::StorageOpenStorage => 24,
            ComMethod::StorageCopyTo => 20,
            ComMethod::StorageMoveElement => 16,
            ComMethod::StorageCommit => 8,
            ComMethod::StorageRevert => 4,
            ComMethod::StorageEnumElements => 20,
            ComMethod::StorageDestroyElement => 8,
            ComMethod::StorageRenameElement => 12,
            ComMethod::StorageSetElementTimes => 20,
            ComMethod::StorageSetClass => 8,
            ComMethod::StorageSetStateBits => 12,
            ComMethod::StorageStat => 12,
            ComMethod::EnumConnectionPoints
            | ComMethod::GetConnectionInterface
            | ComMethod::GetConnectionPointContainer
            | ComMethod::EnumConnections
            | ComMethod::EnumSkip
            | ComMethod::EnumClone
            | ComMethod::DispatchGetTypeInfoCount
            | ComMethod::TypeInfoGetTypeAttr
            | ComMethod::TypeInfoGetTypeComp
            | ComMethod::TypeLibGetLibAttr
            | ComMethod::TypeLibReleaseTLibAttr
            | ComMethod::TypeLibGetTypeInfoCount
            | ComMethod::TypeLibGetTypeComp
            | ComMethod::TypeInfoReleaseTypeAttr
            | ComMethod::TypeInfoReleaseFuncDesc
            | ComMethod::TypeInfoReleaseVarDesc
            | ComMethod::ServerGetValue
            | ComMethod::ServerPutValue
            | ComMethod::ServerGetName
            | ComMethod::ServerPutName
            | ComMethod::ServerGetCount
            | ComMethod::ServerFireValueChanged => 8,
            ComMethod::FindConnectionPoint
            | ComMethod::Advise
            | ComMethod::EnumNext
            | ComMethod::DispatchGetTypeInfo
            | ComMethod::TypeInfoGetFuncDesc
            | ComMethod::TypeInfoGetVarDesc
            | ComMethod::TypeInfoGetRefTypeOfImplType
            | ComMethod::TypeInfoGetImplTypeFlags
            | ComMethod::TypeInfoGetRefTypeInfo
            | ComMethod::TypeInfoGetMops
            | ComMethod::TypeInfoGetContainingTypeLib
            | ComMethod::TypeLibGetTypeInfo
            | ComMethod::TypeLibGetTypeInfoOfGuid => 12,
            ComMethod::TypeInfoAddressOfMember | ComMethod::TypeInfoCreateInstance => 16,
            ComMethod::TypeCompBindType => 16,
            ComMethod::Unadvise => 8,
            ComMethod::TypeInfoGetIDsOfNames => 16,
            ComMethod::EnumReset => 4,
            ComMethod::DispatchGetIDsOfNames => 24,
            ComMethod::DispatchInvoke => 36,
            ComMethod::TypeInfoGetNames => 20,
            ComMethod::TypeInfoInvoke => 40,
            ComMethod::TypeInfoGetDocumentation => 24,
            ComMethod::TypeInfoGetDllEntry => 24,
            ComMethod::TypeCompBind => 24,
            ComMethod::TypeInfoUnsupported | ComMethod::TypeLibUnsupported => 4,
            ComMethod::ServerAdd => 16,
            ComMethod::ServerReset => 4,
            ComMethod::SinkInvoke => 36,
        }
    }
}

// ── COM error/status constants used by the interface methods ───────────────

const E_NOTIMPL: u32 = 0x8000_4001;
const E_POINTER: u32 = 0x8000_4003;
const E_UNEXPECTED: u32 = 0x8000_FFFF;
const CONNECT_E_NOCONNECTION: u32 = 0x8004_0200;
const STG_E_FILENOTFOUND: u32 = 0x8003_0002;
const STG_E_ACCESSDENIED: u32 = 0x8003_0005;
const STG_E_INVALIDPOINTER: u32 = 0x8003_0009;
const STG_E_FILEALREADYEXISTS: u32 = 0x8003_0050;
const STG_E_INVALIDHEADER: u32 = 0x8003_00FB;
const TYPE_E_ELEMENTNOTFOUND: u32 = 0x8002_802B;
const TYPE_E_WRONGTYPEKIND: u32 = 0x8002_802A;
const CLASS_E_NOAGGREGATION: u32 = 0x8004_0110;
const IMPLTYPEFLAG_FDEFAULT: u16 = 0x0001;
const IMPLTYPEFLAG_FSOURCE: u16 = 0x0002;
const IMPLTYPEFLAG_FDEFAULTVTABLE: u16 = 0x0008;
const TYPEFLAG_FDUAL: u16 = 0x0040;
const TYPEFLAG_FDISPATCHABLE: u16 = 0x1000;
const TKIND_INTERFACE: u32 = 3;
const TKIND_DISPATCH: u32 = 4;
const TKIND_COCLASS: u32 = 5;
const DISPID_UNKNOWN: i32 = -1;
const DISPID_VALUE: i32 = 0;
const DISPATCH_METHOD: u16 = 0x0001;
const DISPATCH_PROPERTYGET: u16 = 0x0002;
const DISPATCH_PROPERTYPUT: u16 = 0x0004;
const STATFLAG_NONAME: u32 = 0x0000_0002;
const STGMOVE_MOVE: u32 = 0x0000_0001;
const STGMOVE_COPY: u32 = 0x0000_0002;

// ── The COM interface IIDs the runtime objects answer to ──────────────────

const COM_IID_IUNKNOWN: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_IDISPATCH: [u8; 16] = [
    0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_ITYPEINFO: [u8; 16] = [
    0x01, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_ISTREAM: [u8; 16] = [
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_ISEQUENTIALSTREAM: [u8; 16] = [
    0x30, 0x3a, 0x73, 0x0c, 0x1c, 0x2a, 0xce, 0x11, 0xad, 0xe5, 0x00, 0xaa, 0x00, 0x44, 0x77, 0x3d,
];
const COM_IID_ISTORAGE: [u8; 16] = [
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_IMONIKER: [u8; 16] = [
    0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_IENUMVARIANT: [u8; 16] = [
    0x04, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_IBINDCTX: [u8; 16] = [
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_ICONNECTIONPOINT: [u8; 16] = [
    0x86, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07,
];
const COM_IID_ICONNECTIONPOINTCONTAINER: [u8; 16] = [
    0x84, 0xb2, 0x96, 0xb1, 0xb4, 0xba, 0x1a, 0x10, 0xb6, 0x9c, 0x00, 0xaa, 0x00, 0x34, 0x1d, 0x07,
];
const COM_IID_ITYPELIB: [u8; 16] = [
    0x02, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_IID_ITYPECOMP: [u8; 16] = [
    0x03, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const COM_AUTOMATION_INTERFACE_IID: [u8; 16] = [
    0x02, 0x00, 0xa5, 0xc1, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const COM_AUTOMATION_CLASS_IID: [u8; 16] = [
    0x01, 0x00, 0xa5, 0xc1, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// The runtime's in-process automation/event-source class CLSID.  This is a
/// synthetic-environment class: the runtime's in-process class table models
/// a real IDispatch server with connection points (the behavior is real; the
/// class identity is the runtime's own).
pub const COM_AUTOMATION_SERVER_CLSID: &str = "{C1A50001-0000-4000-8000-000000000001}";

/// The automation server's event dispinterface IID (synthetic for the same
/// reason: the event sink contract it carries is fully implemented).
pub const COM_AUTOMATION_EVENTS_IID: [u8; 16] = [
    0x02, 0x00, 0xa5, 0xc1, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// ── The registered dispatch method tables ─────────────────────────────────

/// The callable kind of one registered automation member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComMemberKind {
    PropertyGet,
    PropertyPut,
    Method,
}

/// One registered automation member: the real per-interface DISPID
/// assignment (`GetIDsOfNames` resolves from these tables).
#[derive(Debug, Clone, Copy)]
struct ComDispatchMember {
    name: &'static str,
    dispid: i32,
    kind: ComMemberKind,
    /// Argument count (for FUNCDESC generation).
    args: u16,
    /// Return VARTYPE (VT_EMPTY = 0 when there is no result).
    returns: u16,
    /// The dual-interface vtable slot this member's method lives at.
    slot: u32,
}

use ComMemberKind::{Method as MemberMethod, PropertyGet as MemberGet, PropertyPut as MemberPut};

/// `ICasa1Automation` — the automation server's dual-interface table.
static CASA1_AUTOMATION_TABLE: &[ComDispatchMember] = &[
    ComDispatchMember {
        name: "Value",
        dispid: 1,
        kind: MemberGet,
        args: 0,
        returns: 3,
        slot: 7,
    },
    ComDispatchMember {
        name: "Value",
        dispid: 1,
        kind: MemberPut,
        args: 1,
        returns: 0,
        slot: 8,
    },
    ComDispatchMember {
        name: "Name",
        dispid: 2,
        kind: MemberGet,
        args: 0,
        returns: 8,
        slot: 9,
    },
    ComDispatchMember {
        name: "Name",
        dispid: 2,
        kind: MemberPut,
        args: 1,
        returns: 0,
        slot: 10,
    },
    ComDispatchMember {
        name: "Count",
        dispid: 3,
        kind: MemberGet,
        args: 0,
        returns: 3,
        slot: 11,
    },
    ComDispatchMember {
        name: "Add",
        dispid: 4,
        kind: MemberMethod,
        args: 2,
        returns: 3,
        slot: 12,
    },
    ComDispatchMember {
        name: "Reset",
        dispid: 5,
        kind: MemberMethod,
        args: 0,
        returns: 0,
        slot: 13,
    },
    ComDispatchMember {
        name: "FireValueChanged",
        dispid: 6,
        kind: MemberMethod,
        args: 1,
        returns: 0,
        slot: 14,
    },
];

/// `ICasa1AutomationEvents` — the connection point's event dispinterface.
static CASA1_AUTOMATION_EVENTS_TABLE: &[ComDispatchMember] = &[
    ComDispatchMember {
        name: "OnValueChanged",
        dispid: 10,
        kind: MemberMethod,
        args: 1,
        returns: 0,
        slot: 0,
    },
    ComDispatchMember {
        name: "OnReset",
        dispid: 11,
        kind: MemberMethod,
        args: 0,
        returns: 0,
        slot: 0,
    },
];

/// `IDispatch` — the base interface table referenced by every automation
/// interface's ITypeInfo (GetRefTypeInfo materializes this real table).
static IDISPATCH_TABLE: &[ComDispatchMember] = &[
    ComDispatchMember {
        name: "GetTypeInfoCount",
        dispid: 1,
        kind: MemberMethod,
        args: 1,
        returns: 3,
        slot: 3,
    },
    ComDispatchMember {
        name: "GetTypeInfo",
        dispid: 2,
        kind: MemberMethod,
        args: 2,
        returns: 13,
        slot: 4,
    },
    ComDispatchMember {
        name: "GetIDsOfNames",
        dispid: 3,
        kind: MemberMethod,
        args: 4,
        returns: 3,
        slot: 5,
    },
    ComDispatchMember {
        name: "Invoke",
        dispid: 4,
        kind: MemberMethod,
        args: 8,
        returns: 3,
        slot: 6,
    },
];

static IUNKNOWN_TABLE: &[ComDispatchMember] = &[
    ComDispatchMember {
        name: "QueryInterface",
        dispid: 0,
        kind: MemberMethod,
        args: 2,
        returns: 3,
        slot: 0,
    },
    ComDispatchMember {
        name: "AddRef",
        dispid: 1,
        kind: MemberMethod,
        args: 0,
        returns: 3,
        slot: 1,
    },
    ComDispatchMember {
        name: "Release",
        dispid: 2,
        kind: MemberMethod,
        args: 0,
        returns: 3,
        slot: 2,
    },
];

fn com_dispatch_table(name: &str) -> Option<&'static [ComDispatchMember]> {
    match name {
        "ICasa1Automation" => Some(CASA1_AUTOMATION_TABLE),
        "ICasa1AutomationEvents" => Some(CASA1_AUTOMATION_EVENTS_TABLE),
        "IDispatch" => Some(IDISPATCH_TABLE),
        "IUnknown" => Some(IUNKNOWN_TABLE),
        _ => None,
    }
}

/// The kind of a registered type-library entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComTypeKind {
    Interface,
    Dispatch,
    DispInterface,
    Class,
}

/// One registered interface/class: the type-library and ITypeInfo
/// implementation-type metadata comes from these tables.
struct ComTypeDescriptor {
    name: &'static str,
    iid: [u8; 16],
    table: &'static str,
    kind: ComTypeKind,
    /// (referenced type name, GetImplTypeFlags value) pairs.
    impls: &'static [(&'static str, u16)],
    dll_name: &'static str,
    dll_entry: &'static str,
    dll_ordinal: u16,
}

/// The typelib GUID exposed by ITypeLib::GetLibAttr.
const COM_AUTOMATION_TYPELIB_IID: [u8; 16] = [
    0x10, 0x00, 0xa5, 0xc1, 0x00, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

static COM_TYPE_DESCRIPTORS: &[ComTypeDescriptor] = &[
    ComTypeDescriptor {
        name: "ICasa1Automation",
        iid: COM_AUTOMATION_INTERFACE_IID,
        table: "ICasa1Automation",
        kind: ComTypeKind::Dispatch,
        impls: &[("IDispatch", 0)],
        dll_name: "casa1.dll",
        dll_entry: "DllGetClassObject",
        dll_ordinal: 1,
    },
    ComTypeDescriptor {
        name: "ICasa1AutomationEvents",
        iid: COM_AUTOMATION_EVENTS_IID,
        table: "ICasa1AutomationEvents",
        kind: ComTypeKind::DispInterface,
        impls: &[("IDispatch", 0)],
        dll_name: "casa1.dll",
        dll_entry: "DllGetClassObject",
        dll_ordinal: 1,
    },
    ComTypeDescriptor {
        name: "IDispatch",
        iid: COM_IID_IDISPATCH,
        table: "IDispatch",
        kind: ComTypeKind::Interface,
        impls: &[("IUnknown", 0)],
        dll_name: "oleaut32.dll",
        dll_entry: "DispInvoke",
        dll_ordinal: 0,
    },
    ComTypeDescriptor {
        name: "IUnknown",
        iid: COM_IID_IUNKNOWN,
        table: "IUnknown",
        kind: ComTypeKind::Interface,
        impls: &[],
        dll_name: "ole32.dll",
        dll_entry: "CoCreateInstance",
        dll_ordinal: 0,
    },
    ComTypeDescriptor {
        name: "Casa1.Automation",
        iid: COM_AUTOMATION_CLASS_IID,
        table: "Casa1.Automation",
        kind: ComTypeKind::Class,
        impls: &[
            (
                "ICasa1Automation",
                IMPLTYPEFLAG_FDEFAULT | IMPLTYPEFLAG_FDEFAULTVTABLE,
            ),
            ("ICasa1AutomationEvents", IMPLTYPEFLAG_FSOURCE),
        ],
        dll_name: "casa1.dll",
        dll_entry: "DllGetClassObject",
        dll_ordinal: 1,
    },
];

const COM_TYPELIB_MARKER: &str = "\u{1}typelib";
const COM_TYPECOMP_MARKER: &str = "\u{1}typecomp";
const COM_CFB_PREFIX: &str = "\u{1}cfb:";
const COM_COMPOSITE_PREFIX: &str = "\u{1}composite:";
const COM_ITEM_PREFIX: &str = "\u{1}item:";

fn com_type_descriptor(table: &str) -> Option<&'static ComTypeDescriptor> {
    COM_TYPE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.table.eq_ignore_ascii_case(table))
}

fn com_type_descriptor_by_name(name: &str) -> Option<&'static ComTypeDescriptor> {
    COM_TYPE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.name.eq_ignore_ascii_case(name))
}

fn com_type_descriptor_index(table: &str) -> Option<u32> {
    COM_TYPE_DESCRIPTORS
        .iter()
        .position(|descriptor| descriptor.table.eq_ignore_ascii_case(table))
        .map(|index| index as u32)
}

/// The first table entry for a DISPID.  Property get and put entries share a
/// DISPID; the invocation flags select the matching entry (a get entry when
/// both exist).
fn com_dispatch_member(table: &str, dispid: i32) -> Option<&'static ComDispatchMember> {
    let members = com_dispatch_table(table)?;
    members
        .iter()
        .find(|member| member.dispid == dispid && member.kind != ComMemberKind::PropertyPut)
        .or_else(|| members.iter().find(|member| member.dispid == dispid))
}

/// The table entry matching an invocation: property puts select the put
/// entry sharing the DISPID, everything else selects the get/method entry.
fn com_dispatch_member_for(
    table: &str,
    dispid: i32,
    flags: u16,
) -> Option<&'static ComDispatchMember> {
    let members = com_dispatch_table(table)?;
    if flags & DISPATCH_PROPERTYPUT != 0 {
        members
            .iter()
            .find(|member| member.dispid == dispid && member.kind == ComMemberKind::PropertyPut)
    } else {
        com_dispatch_member(table, dispid)
    }
}

fn com_dispatch_member_by_name(table: &str, name: &str) -> Option<&'static ComDispatchMember> {
    let members = com_dispatch_table(table)?;
    members
        .iter()
        .find(|member| member.name.eq_ignore_ascii_case(name))
}

fn com_value_as_i4(value: &ComValue) -> i32 {
    match value {
        ComValue::I4(number) => *number,
        ComValue::Bool(flag) => i32::from(*flag),
        ComValue::Double(number) => *number as i32,
        ComValue::Bstr(text) => text.parse::<i32>().unwrap_or(0),
        ComValue::Object(object) => *object as u32 as i32,
        ComValue::Empty => 0,
    }
}

/// The CLSID embedded in an OLE compound document (the header's CLSID
/// field at offset 0x50) — the honest file-based CLSID extraction.
fn ole_embedded_clsid(bytes: &[u8]) -> Option<[u8; 16]> {
    if bytes.len() < 0x60 || bytes[..8] != [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        return None;
    }
    let mut clsid = [0_u8; 16];
    clsid.copy_from_slice(&bytes[0x50..0x60]);
    if clsid.iter().all(|b| *b == 0) {
        return None;
    }
    Some(clsid)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};
    use super::*;

    const OUT: u64 = 0x41_000;
    const BUF: u64 = 0x41_100;
    const STAT: u64 = 0x41_200;
    const COOKIE: u64 = 0x41_300;
    const IID_PTR: u64 = 0x41_400;
    const VARIANT: u64 = 0x41_500;
    const NAME: u64 = 0x41_600;
    const NAMES: u64 = 0x41_800;
    const IDS: u64 = 0x41_900;

    fn guest_ptr(fixture: &Fixture, address: u64) -> u64 {
        read_guest_pointer(&fixture.memory, address, GuestArch::X86).unwrap()
    }

    /// Invoke one vtable slot through the object's real vtable: read the
    /// function pointer, resolve the host thunk the runtime installed and
    /// dispatch it with the x86 stack ABI (exactly what the guest does).
    fn call_slot(fixture: &mut Fixture, object: u64, slot: u64, args: &[u32]) -> u32 {
        let vtable = read_guest_pointer(&fixture.memory, object, GuestArch::X86).unwrap();
        let function =
            read_guest_pointer(&fixture.memory, vtable + slot * 4, GuestArch::X86).unwrap();
        let thunk = fixture
            .runtime
            .host_thunks
            .get(&function)
            .cloned()
            .unwrap_or_else(|| panic!("vtable slot {slot} is not a host thunk"));
        dispatch_x86(fixture, thunk, args) as u32
    }

    fn write_iid(fixture: &mut Fixture, ptr: u64, iid: &[u8; 16]) {
        fixture.memory.map_bytes(ptr, iid);
    }

    fn write_utf16(fixture: &mut Fixture, ptr: u64, text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        fixture.memory.map_bytes(ptr, &bytes);
        bytes
    }

    fn read_variant_i4(fixture: &Fixture, ptr: u64) -> i32 {
        assert_eq!(fixture.memory.read_u16(ptr).unwrap(), 3, "VT_I4");
        fixture.memory.read_u32(ptr + 8).unwrap() as i32
    }

    fn create_server(fixture: &mut Fixture) -> u64 {
        fixture
            .runtime
            .alloc_com_automation_server(&mut fixture.memory, "ICasa1Automation")
            .unwrap()
    }

    // ── Streams ─────────────────────────────────────────────────────────────

    #[test]
    fn stream_vtable_has_real_read_seek_stat_lock_and_clone_semantics() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-stream");
            let stream = fixture
                .runtime
                .alloc_com_stream_object(
                    &mut fixture.memory,
                    b"0123456789".to_vec(),
                    "data.bin",
                    None,
                )
                .unwrap();

            // Read 4 bytes at the initial position.
            fixture.memory.map_bytes(BUF, &[0_u8; 16]);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    3,
                    &[stream as u32, BUF as u32, 4, OUT as u32]
                ),
                0,
                "IStream::Read"
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 4);
            assert_eq!(fixture.memory.read_bytes(BUF, 4).unwrap(), b"0123");

            // Seek to offset 4 (SET).
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    5,
                    &[stream as u32, 4, 0, 0, OUT as u32]
                ),
                0,
                "IStream::Seek"
            );
            assert_eq!(fixture.memory.read_u64(OUT).unwrap(), 4);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    3,
                    &[stream as u32, BUF as u32, 2, OUT as u32]
                ),
                0
            );
            assert_eq!(fixture.memory.read_bytes(BUF, 2).unwrap(), b"45");

            // Write extends the stream in place.
            fixture.memory.map_bytes(BUF, b"XY");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    4,
                    &[stream as u32, BUF as u32, 2, OUT as u32]
                ),
                0,
                "IStream::Write"
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 2);
            assert_eq!(
                fixture
                    .runtime
                    .com_streams
                    .get(&stream)
                    .unwrap()
                    .data
                    .clone(),
                b"012345XY89".to_vec()
            );

            // CopyTo walks the source position into the destination.
            let destination = fixture
                .runtime
                .alloc_com_stream_object(&mut fixture.memory, Vec::new(), "copy", None)
                .unwrap();
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    7,
                    &[
                        stream as u32,
                        destination as u32,
                        5,
                        0,
                        0,
                        OUT as u32,
                        (OUT + 4) as u32,
                    ]
                ),
                0,
                "IStream::CopyTo"
            );
            assert_eq!(
                fixture
                    .runtime
                    .com_streams
                    .get(&destination)
                    .unwrap()
                    .data
                    .clone(),
                b"89".to_vec()
            );

            // Stat reports the real type/size/name.
            fixture.memory.map_bytes(STAT, &[0_u8; 72]);
            assert_eq!(
                call_slot(&mut fixture, stream, 12, &[stream as u32, STAT as u32, 0]),
                0,
                "IStream::Stat"
            );
            assert_eq!(
                fixture.memory.read_u32(STAT + 4).unwrap(),
                2,
                "STGTY_STREAM"
            );
            assert_eq!(fixture.memory.read_u64(STAT + 8).unwrap(), 10);
            let stat_name = guest_ptr(&fixture, STAT);
            assert_eq!(
                read_utf16_string(&fixture.memory, stat_name).unwrap(),
                "data.bin"
            );

            // LockRegion records the region; a duplicate is rejected; Unlock
            // consumes the exact region.
            assert_eq!(
                call_slot(&mut fixture, stream, 10, &[stream as u32, 0, 0, 4, 0, 1]),
                0,
                "IStream::LockRegion"
            );
            assert_eq!(
                call_slot(&mut fixture, stream, 10, &[stream as u32, 0, 0, 4, 0, 1]),
                STG_E_INVALIDFUNCTION
            );
            assert_eq!(
                call_slot(&mut fixture, stream, 11, &[stream as u32, 0, 0, 4, 0, 1]),
                0,
                "IStream::UnlockRegion"
            );
            assert_eq!(
                call_slot(&mut fixture, stream, 11, &[stream as u32, 0, 0, 4, 0, 1]),
                STG_E_INVALIDFUNCTION
            );

            // Clone copies the bytes and the position.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, stream, 13, &[stream as u32, OUT as u32]),
                0,
                "IStream::Clone"
            );
            let clone = guest_ptr(&fixture, OUT);
            assert_ne!(clone, stream);
            let clone_state = fixture.runtime.com_streams.get(&clone).unwrap();
            assert_eq!(clone_state.data, b"012345XY89".to_vec());
            assert_eq!(clone_state.position, 10);

            // The stream answers IStream/ISequentialStream/IUnknown and
            // rejects unrelated interfaces.
            write_iid(&mut fixture, IID_PTR, &COM_IID_ISTREAM);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    0,
                    &[stream as u32, IID_PTR as u32, OUT as u32]
                ),
                0
            );
            assert_eq!(guest_ptr(&fixture, OUT), stream);
        })
    }

    #[test]
    fn stream_file_backing_commits_and_reverts_over_the_real_file() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-stream-file");
            let host_path = fixture._temp.path().join("backing.bin");
            std::fs::write(&host_path, b"disk").unwrap();
            let stream = fixture
                .runtime
                .alloc_com_stream_from_file(&mut fixture.memory, host_path.to_str().unwrap())
                .unwrap();
            assert_eq!(
                fixture
                    .runtime
                    .com_streams
                    .get(&stream)
                    .unwrap()
                    .data
                    .clone(),
                b"disk".to_vec()
            );

            // Seek to the end and append through Write, then Commit.
            assert_eq!(
                call_slot(&mut fixture, stream, 5, &[stream as u32, 0, 0, 2, 0]),
                0
            );
            fixture.memory.map_bytes(BUF, b"-live");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    4,
                    &[stream as u32, BUF as u32, 5, OUT as u32]
                ),
                0
            );
            assert_eq!(
                call_slot(&mut fixture, stream, 8, &[stream as u32, 0]),
                0,
                "IStream::Commit"
            );
            assert_eq!(std::fs::read(&host_path).unwrap(), b"disk-live".to_vec());

            // An out-of-band change is observed by Revert.
            std::fs::write(&host_path, b"external").unwrap();
            assert_eq!(
                call_slot(&mut fixture, stream, 9, &[stream as u32]),
                0,
                "IStream::Revert"
            );
            assert_eq!(
                fixture
                    .runtime
                    .com_streams
                    .get(&stream)
                    .unwrap()
                    .data
                    .clone(),
                b"external".to_vec()
            );
        })
    }

    // ── Storage ─────────────────────────────────────────────────────────────

    #[test]
    fn storage_creates_opens_and_enumerates_streams_over_a_real_directory() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-storage");
            let directory = fixture._temp.path().join("store");
            std::fs::create_dir_all(&directory).unwrap();
            let storage = fixture
                .runtime
                .alloc_com_storage_object(
                    &mut fixture.memory,
                    Some(directory.to_string_lossy().to_string()),
                    "store",
                    0,
                )
                .unwrap();

            // CreateStream + Write + storage Commit writes the real file.
            write_utf16(&mut fixture, NAME, "element.bin");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    storage,
                    3,
                    &[storage as u32, NAME as u32, 0x1002, 0, OUT as u32]
                ),
                0,
                "IStorage::CreateStream"
            );
            let stream = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(BUF, b"payload");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    4,
                    &[stream as u32, BUF as u32, 7, OUT as u32]
                ),
                0
            );
            assert_eq!(
                call_slot(&mut fixture, stream, 8, &[stream as u32, 0]),
                0,
                "IStream::Commit writes the host file"
            );
            assert_eq!(
                std::fs::read(directory.join("element.bin")).unwrap(),
                b"payload".to_vec()
            );

            // OpenStream returns a fresh stream over the committed bytes.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    storage,
                    4,
                    &[storage as u32, NAME as u32, 0, 0x1000, 0, OUT as u32]
                ),
                0,
                "IStorage::OpenStream"
            );
            let reopened = guest_ptr(&fixture, OUT);
            assert_eq!(
                fixture
                    .runtime
                    .com_streams
                    .get(&reopened)
                    .unwrap()
                    .data
                    .clone(),
                b"payload".to_vec()
            );

            // Missing elements answer STG_E_FILENOTFOUND.
            write_utf16(&mut fixture, NAME, "missing.bin");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    storage,
                    4,
                    &[storage as u32, NAME as u32, 0, 0x1000, 0, OUT as u32]
                ),
                STG_E_FILENOTFOUND
            );

            // EnumElements lists the element with its STATSTG.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    storage,
                    11,
                    &[storage as u32, 0, 0, 0, OUT as u32]
                ),
                0,
                "IStorage::EnumElements"
            );
            let enumerator = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(BUF, &[0_u8; 8]);
            let fetched = OUT + 4;
            assert_eq!(
                call_slot(
                    &mut fixture,
                    enumerator,
                    3,
                    &[enumerator as u32, 1, BUF as u32, fetched as u32]
                ),
                0,
                "IEnumSTATSTG::Next"
            );
            assert_eq!(fixture.memory.read_u32(fetched).unwrap(), 1);
            let descriptor = guest_ptr(&fixture, BUF);
            assert_eq!(fixture.memory.read_u32(descriptor + 4).unwrap(), 2);
            assert_eq!(fixture.memory.read_u64(descriptor + 8).unwrap(), 7);
            let element_name = guest_ptr(&fixture, descriptor);
            assert_eq!(
                read_utf16_string(&fixture.memory, element_name).unwrap(),
                "element.bin"
            );

            // DestroyElement removes the real file and the element.
            write_utf16(&mut fixture, NAME, "element.bin");
            assert_eq!(
                call_slot(&mut fixture, storage, 12, &[storage as u32, NAME as u32]),
                0,
                "IStorage::DestroyElement"
            );
            assert!(!directory.join("element.bin").exists());
        })
    }

    // ── Connection points and events ────────────────────────────────────────

    #[test]
    fn connection_points_advise_bookkeeping_enumeration_and_event_firing() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-cp");
            let server = create_server(&mut fixture);
            let sink = fixture
                .runtime
                .alloc_com_sink_object(&mut fixture.memory, "ISink")
                .unwrap();

            // QI(ID_IConnectionPointContainer) on the server hands out the
            // container interface object.
            write_iid(&mut fixture, IID_PTR, &COM_IID_ICONNECTIONPOINTCONTAINER);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    0,
                    &[server as u32, IID_PTR as u32, OUT as u32]
                ),
                0,
                "server QueryInterface(IConnectionPointContainer)"
            );
            let container = guest_ptr(&fixture, OUT);
            assert_ne!(container, 0);

            // FindConnectionPoint(events IID) returns the event point; an
            // unrelated IID is CONNECT_E_NOCONNECTION.
            write_iid(&mut fixture, IID_PTR, &COM_AUTOMATION_EVENTS_IID);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    container,
                    4,
                    &[container as u32, IID_PTR as u32, OUT as u32]
                ),
                0,
                "FindConnectionPoint"
            );
            let point = guest_ptr(&fixture, OUT);
            assert_ne!(point, 0);
            write_iid(&mut fixture, IID_PTR, &COM_IID_IDISPATCH);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    container,
                    4,
                    &[container as u32, IID_PTR as u32, OUT as u32]
                ),
                CONNECT_E_NOCONNECTION
            );

            // The point reports its interface and owner container.
            write_iid(&mut fixture, IID_PTR, &[0_u8; 16]);
            assert_eq!(
                call_slot(&mut fixture, point, 3, &[point as u32, IID_PTR as u32]),
                0
            );
            assert_eq!(
                fixture.memory.read_bytes(IID_PTR, 16).unwrap(),
                COM_AUTOMATION_EVENTS_IID.to_vec()
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, point, 4, &[point as u32, OUT as u32]),
                0
            );
            assert_eq!(guest_ptr(&fixture, OUT), container);

            // Advise the sink; the cookie is recorded.
            fixture.memory.map_bytes(COOKIE, &[0_u8; 4]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    point,
                    5,
                    &[point as u32, sink as u32, COOKIE as u32]
                ),
                0,
                "IConnectionPoint::Advise"
            );
            let cookie = fixture.memory.read_u32(COOKIE).unwrap();
            assert_ne!(cookie, 0);
            assert_eq!(
                fixture
                    .runtime
                    .com_connection_points
                    .get(&point)
                    .unwrap()
                    .sinks,
                vec![(cookie, sink)]
            );

            // EnumConnections enumerates the (sink, cookie) CONNECTDATA.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, point, 7, &[point as u32, OUT as u32]),
                0,
                "EnumConnections"
            );
            let connections = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(BUF, &[0_u8; 16]);
            let fetched = OUT + 4;
            assert_eq!(
                call_slot(
                    &mut fixture,
                    connections,
                    3,
                    &[connections as u32, 1, BUF as u32, fetched as u32]
                ),
                0
            );
            assert_eq!(fixture.memory.read_u32(fetched).unwrap(), 1);
            assert_eq!(guest_ptr(&fixture, BUF), sink);
            assert_eq!(fixture.memory.read_u32(BUF + 4).unwrap(), cookie);

            // EnumConnectionPoints enumerates the point itself.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, container, 3, &[container as u32, OUT as u32]),
                0,
                "EnumConnectionPoints"
            );
            let points = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(BUF, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    points,
                    3,
                    &[points as u32, 1, BUF as u32, fetched as u32]
                ),
                0
            );
            assert_eq!(guest_ptr(&fixture, BUF), point);

            // A server state change (put_Value) fires OnValueChanged into the
            // advised sink through its real IDispatch::Invoke slot.
            fixture
                .runtime
                .write_variant_i4(&mut fixture.memory, VARIANT, 42);
            assert_eq!(
                call_slot(&mut fixture, server, 8, &[server as u32, VARIANT as u32]),
                0,
                "put_Value"
            );
            assert_eq!(
                fixture.runtime.com_sink_invocations,
                vec![(sink, 10, vec![ComValue::I4(42)])]
            );
            let fired = fixture.runtime.com_fired_events.last().unwrap();
            assert_eq!(fired.source, server);
            assert_eq!(fired.dispid, 10);
            assert_eq!(fired.sink, sink);
            assert_eq!(fired.hr, 0);

            // Unadvise removes the sink: the next change fires nothing.
            assert_eq!(
                call_slot(&mut fixture, point, 6, &[point as u32, cookie]),
                0,
                "IConnectionPoint::Unadvise"
            );
            assert_eq!(
                call_slot(&mut fixture, point, 6, &[point as u32, cookie]),
                CONNECT_E_NOCONNECTION
            );
            fixture
                .runtime
                .write_variant_i4(&mut fixture.memory, VARIANT, 43);
            let fired_before = fixture.runtime.com_fired_events.len();
            assert_eq!(
                call_slot(&mut fixture, server, 8, &[server as u32, VARIANT as u32]),
                0
            );
            assert_eq!(fixture.runtime.com_fired_events.len(), fired_before);
        })
    }

    // ── IDispatch / ITypeInfo ───────────────────────────────────────────────

    #[test]
    fn idispatch_assigns_dispids_and_invokes_the_same_state_as_the_vtable() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-dispatch");
            let server = create_server(&mut fixture);

            // GetIDsOfNames resolves the registered table names.
            write_utf16(&mut fixture, NAME, "Value");
            write_utf16(&mut fixture, NAME + 0x40, "Add");
            write_utf16(&mut fixture, NAME + 0x80, "Missing");
            fixture.memory.map_bytes(NAMES, &[0_u8; 16]);
            write_u32(&mut fixture.memory, NAMES, NAME as u32);
            write_u32(&mut fixture.memory, NAMES + 4, (NAME + 0x40) as u32);
            write_u32(&mut fixture.memory, NAMES + 8, (NAME + 0x80) as u32);
            fixture.memory.map_bytes(IDS, &[0_u8; 12]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    5,
                    &[server as u32, 0, NAMES as u32, 3, 0, IDS as u32]
                ),
                DISP_E_UNKNOWNNAME,
                "GetIDsOfNames reports the unknown name"
            );
            assert_eq!(fixture.memory.read_u32(IDS).unwrap(), 1, "Value");
            assert_eq!(fixture.memory.read_u32(IDS + 4).unwrap(), 4, "Add");
            assert_eq!(
                fixture.memory.read_u32(IDS + 8).unwrap(),
                DISPID_UNKNOWN as u32,
                "Missing"
            );
            // The known-name subset succeeds and caches the dynamic name.
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    5,
                    &[server as u32, 0, NAMES as u32, 2, 0, IDS as u32]
                ),
                0
            );
            let cache = &fixture
                .runtime
                .com_servers
                .get(&server)
                .unwrap()
                .dispid_cache;
            assert_eq!(cache.get("Value"), Some(&1));
            assert_eq!(cache.get("Add"), Some(&4));
            assert!(!cache.contains_key("Missing"));

            // GetTypeInfoCount/GetTypeInfo return the table's ITypeInfo.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, server, 3, &[server as u32, OUT as u32]),
                0
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 1);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, server, 4, &[server as u32, 0, OUT as u32]),
                0,
                "GetTypeInfo(0)"
            );
            let type_info = guest_ptr(&fixture, OUT);
            assert_ne!(type_info, 0);
            assert_eq!(
                call_slot(&mut fixture, server, 4, &[server as u32, 1, OUT as u32]),
                TYPE_E_ELEMENTNOTFOUND
            );

            // IDispatch::Invoke property put writes the same state the
            // vtable get_Value reads.
            let (params, result, exception, argument_error) = fixture
                .runtime
                .build_dispatch_invocation(&mut fixture.memory, &[ComValue::I4(7)])
                .unwrap();
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    6,
                    &[
                        server as u32,
                        1,
                        0,
                        0,
                        u64::from(DISPATCH_PROPERTYPUT) as u32,
                        params as u32,
                        result as u32,
                        exception as u32,
                        argument_error as u32,
                    ]
                ),
                0,
                "Invoke(Value, PUT)"
            );
            fixture.memory.map_bytes(VARIANT, &[0_u8; 16]);
            assert_eq!(
                call_slot(&mut fixture, server, 7, &[server as u32, VARIANT as u32]),
                0,
                "vtable get_Value"
            );
            assert_eq!(read_variant_i4(&fixture, VARIANT), 7);

            // A method invocation through Invoke routes to the vtable method
            // state (Add is slot 12); both paths return the same result.
            let (params, result, exception, argument_error) = fixture
                .runtime
                .build_dispatch_invocation(&mut fixture.memory, &[ComValue::I4(3), ComValue::I4(4)])
                .unwrap();
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    6,
                    &[
                        server as u32,
                        4,
                        0,
                        0,
                        u64::from(DISPATCH_METHOD) as u32,
                        params as u32,
                        result as u32,
                        exception as u32,
                        argument_error as u32,
                    ]
                ),
                0,
                "Invoke(Add)"
            );
            assert_eq!(read_variant_i4(&fixture, result), 7);
            fixture.memory.map_bytes(VARIANT, &[0_u8; 16]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    12,
                    &[server as u32, 3, 4, VARIANT as u32]
                ),
                0,
                "vtable Add"
            );
            assert_eq!(read_variant_i4(&fixture, VARIANT), 7);

            // Reset clears the properties and fires OnReset.
            let (params, result, exception, argument_error) = fixture
                .runtime
                .build_dispatch_invocation(&mut fixture.memory, &[])
                .unwrap();
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    6,
                    &[
                        server as u32,
                        5,
                        0,
                        0,
                        u64::from(DISPATCH_METHOD) as u32,
                        params as u32,
                        result as u32,
                        exception as u32,
                        argument_error as u32,
                    ]
                ),
                0,
                "Invoke(Reset)"
            );
            fixture.memory.map_bytes(VARIANT, &[0_u8; 16]);
            assert_eq!(
                call_slot(&mut fixture, server, 11, &[server as u32, VARIANT as u32]),
                0,
                "vtable get_Count"
            );
            assert_eq!(read_variant_i4(&fixture, VARIANT), 0);

            // Unknown members are DISP_E_MEMBERNOTFOUND.
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    6,
                    &[server as u32, 99, 0, 0, 2, 0, 0, 0, 0]
                ),
                DISP_E_MEMBERNOTFOUND
            );

            // ITypeInfo reflects the registered table: GetTypeAttr,
            // GetFuncDesc, GetNames and GetDocumentation.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, type_info, 3, &[type_info as u32, OUT as u32]),
                0,
                "ITypeInfo::GetTypeAttr"
            );
            let attrs = guest_ptr(&fixture, OUT);
            assert_eq!(
                fixture.memory.read_u32(attrs + 40).unwrap(),
                4,
                "TKIND_DISPATCH"
            );
            assert!(fixture.memory.read_u16(attrs + 44).unwrap() > 0, "cFuncs");

            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    5,
                    &[type_info as u32, 6, OUT as u32]
                ),
                0,
                "ITypeInfo::GetFuncDesc(Reset)"
            );
            let func_desc = guest_ptr(&fixture, OUT);
            assert_eq!(fixture.memory.read_u32(func_desc).unwrap(), 5, "memid");

            fixture.memory.map_bytes(NAMES, &[0_u8; 8]);
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    7,
                    &[type_info as u32, 4, NAMES as u32, 2, OUT as u32]
                ),
                0,
                "ITypeInfo::GetNames(Add)"
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 1);
            let add_name = guest_ptr(&fixture, NAMES);
            assert_eq!(read_utf16_string(&fixture.memory, add_name).unwrap(), "Add");

            // ITypeInfo::Invoke with a NULL instance routes to the owner.
            let (params, result, exception, argument_error) = fixture
                .runtime
                .build_dispatch_invocation(&mut fixture.memory, &[ComValue::I4(4), ComValue::I4(7)])
                .unwrap();
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    11,
                    &[
                        type_info as u32,
                        0,
                        4,
                        0,
                        0,
                        u64::from(DISPATCH_METHOD) as u32,
                        params as u32,
                        result as u32,
                        exception as u32,
                        argument_error as u32,
                    ]
                ),
                0,
                "ITypeInfo::Invoke(Add)"
            );
            assert_eq!(read_variant_i4(&fixture, result), 11);
        })
    }

    #[test]
    fn disp_helper_exports_route_into_the_registered_tables() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-disp-exports");
            let server = create_server(&mut fixture);
            write_utf16(&mut fixture, NAME, "Value");
            fixture.memory.map_bytes(NAMES, &[0_u8; 8]);
            write_u32(&mut fixture.memory, NAMES, NAME as u32);
            fixture.memory.map_bytes(IDS, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::OleDispGetIdsOfNames,
                    &[server as u32, NAMES as u32, 1, 0, IDS as u32]
                ),
                0,
                "DispGetIDsOfNames"
            );
            assert_eq!(fixture.memory.read_u32(IDS).unwrap(), 1);

            // DispInvoke with the registered typeinfo routes to the instance.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, server, 4, &[server as u32, 0, OUT as u32]),
                0
            );
            let type_info = guest_ptr(&fixture, OUT);
            let (params, result, exception, argument_error) = fixture
                .runtime
                .build_dispatch_invocation(&mut fixture.memory, &[ComValue::I4(5), ComValue::I4(6)])
                .unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::OleDispInvoke,
                    &[
                        server as u32,
                        type_info as u32,
                        4,
                        u64::from(DISPATCH_METHOD) as u32,
                        params as u32,
                        result as u32,
                        exception as u32,
                        argument_error as u32,
                    ]
                ),
                0,
                "DispInvoke"
            );
            assert_eq!(read_variant_i4(&fixture, result), 11);
        })
    }

    // ── Monikers ────────────────────────────────────────────────────────────

    #[test]
    fn moniker_parses_binds_and_reports_real_state() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-moniker");
            let guest_path = "C:\\payload.bin";
            let host_path = fixture
                .runtime
                .win32
                .ge()
                .host_path_for_windows_path(guest_path)
                .unwrap();
            if let Some(parent) = host_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&host_path, b"moniker-bytes").unwrap();
            let display = format!("file:{guest_path}");
            write_utf16(&mut fixture, NAME, &display);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            fixture.memory.map_bytes(COOKIE, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MkParseDisplayName,
                    &[0, NAME as u32, COOKIE as u32, OUT as u32]
                ),
                0,
                "MkParseDisplayName(file:)"
            );
            let moniker = guest_ptr(&fixture, OUT);
            assert_ne!(moniker, 0);
            assert_eq!(
                fixture.memory.read_u32(COOKIE).unwrap(),
                display.encode_utf16().count() as u32
            );

            // GetDisplayName returns the parsed name as a BSTR.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    moniker,
                    7,
                    &[moniker as u32, 0, 0, OUT as u32]
                ),
                0,
                "GetDisplayName"
            );
            let bstr = guest_ptr(&fixture, OUT);
            assert_eq!(read_utf16_string(&fixture.memory, bstr).unwrap(), display);

            // IsSystemMoniker reports MKSYS_FILEMONIKER; Hash is stable.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, moniker, 9, &[moniker as u32, OUT as u32]),
                0
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 2);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, moniker, 10, &[moniker as u32, OUT as u32]),
                0
            );
            let hash = fixture.memory.read_u32(OUT).unwrap();
            assert_ne!(hash, 0, "a non-empty display name hashes");

            // BindToStorage over IStream yields the real file bytes.
            write_iid(&mut fixture, IID_PTR, &COM_IID_ISTREAM);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    moniker,
                    4,
                    &[moniker as u32, 0, 0, IID_PTR as u32, OUT as u32]
                ),
                0,
                "BindToStorage(IStream)"
            );
            let stream = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(BUF, &[0_u8; 16]);
            let read_out = OUT + 8;
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    3,
                    &[stream as u32, BUF as u32, 13, read_out as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_bytes(BUF, 13).unwrap(),
                b"moniker-bytes".to_vec()
            );

            // Plain files have no object handler: the honest MK_E_NOOBJECT.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    moniker,
                    3,
                    &[moniker as u32, 0, 0, 0, OUT as u32]
                ),
                MK_E_NOOBJECT
            );

            // Reduce/Enum/ComposeWith report the modeled answers.
            assert_eq!(
                call_slot(
                    &mut fixture,
                    moniker,
                    5,
                    &[moniker as u32, 0, 0, 0, OUT as u32]
                ),
                MK_E_REDUCED_TO_SELF
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, moniker, 8, &[moniker as u32, 1, OUT as u32]),
                0
            );
            assert_eq!(guest_ptr(&fixture, OUT), 0);
            // Composing a moniker with itself is rejected (no cycles).
            assert_eq!(
                call_slot(
                    &mut fixture,
                    moniker,
                    6,
                    &[moniker as u32, moniker as u32, 0, OUT as u32]
                ),
                E_INVALIDARG
            );

            // A malformed name is MK_E_SYNTAX and creates no object.
            write_utf16(&mut fixture, NAME, "not a moniker");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MkParseDisplayName,
                    &[0, NAME as u32, COOKIE as u32, OUT as u32]
                ),
                u64::from(MK_E_SYNTAX)
            );
            assert_eq!(guest_ptr(&fixture, OUT), 0);
        })
    }

    #[test]
    fn class_moniker_binds_through_the_class_table() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-class-moniker");
            let display = format!("clsid:{}", COM_AUTOMATION_SERVER_CLSID);
            write_utf16(&mut fixture, NAME, &display);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MkParseDisplayName,
                    &[0, NAME as u32, COOKIE as u32, OUT as u32]
                ),
                0
            );
            let moniker = guest_ptr(&fixture, OUT);
            assert_eq!(
                call_slot(&mut fixture, moniker, 9, &[moniker as u32, OUT as u32]),
                0
            );
            assert_eq!(
                fixture.memory.read_u32(OUT).unwrap(),
                6,
                "MKSYS_CLASSMONIKER"
            );

            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    moniker,
                    3,
                    &[moniker as u32, 0, 0, 0, OUT as u32]
                ),
                0,
                "class moniker BindToObject"
            );
            let server = guest_ptr(&fixture, OUT);
            assert_ne!(server, 0);
            assert!(fixture.runtime.com_servers.contains_key(&server));

            // The bound object is a real IDispatch server.
            write_iid(&mut fixture, IID_PTR, &COM_IID_IDISPATCH);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    server,
                    0,
                    &[server as u32, IID_PTR as u32, OUT as u32]
                ),
                0,
                "bound server QueryInterface(IDispatch)"
            );

            // An unregistered class is REGDB_E_CLASSNOTREG.
            let unknown = "clsid:{11111111-2222-3333-4444-555555555555}";
            write_utf16(&mut fixture, NAME, unknown);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::MkParseDisplayName,
                    &[0, NAME as u32, COOKIE as u32, OUT as u32]
                ),
                0
            );
            let unknown_moniker = guest_ptr(&fixture, OUT);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    unknown_moniker,
                    3,
                    &[unknown_moniker as u32, 0, 0, 0, OUT as u32]
                ),
                REGDB_E_CLASSNOTREG
            );
        })
    }

    // ── ITypeInfo / ITypeLib / ITypeComp depth ─────────────────────────────

    #[test]
    fn type_info_impl_var_dll_address_class_typelib_and_typecomp_are_real() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-typeinfo-depth");
            let server = create_server(&mut fixture);

            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, server, 4, &[server as u32, 0, OUT as u32]),
                0,
                "IDispatch::GetTypeInfo"
            );
            let type_info = guest_ptr(&fixture, OUT);

            // GetRefTypeOfImplType(0) points at IDispatch; GetRefTypeInfo
            // materializes its real ITypeInfo.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    8,
                    &[type_info as u32, 0, OUT as u32]
                ),
                0,
                "GetRefTypeOfImplType(0)"
            );
            let href = fixture.memory.read_u32(OUT).unwrap();
            assert_ne!(href, 0);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    14,
                    &[type_info as u32, href, OUT as u32]
                ),
                0,
                "GetRefTypeInfo(IDispatch)"
            );
            let dispatch_info = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    dispatch_info,
                    3,
                    &[dispatch_info as u32, OUT as u32]
                ),
                0
            );
            let dispatch_attrs = guest_ptr(&fixture, OUT);
            assert_eq!(
                fixture.memory.read_bytes(dispatch_attrs, 16).unwrap(),
                COM_IID_IDISPATCH.to_vec(),
                "referenced ITypeInfo is IDispatch"
            );
            assert_eq!(fixture.memory.read_u32(dispatch_attrs + 40).unwrap(), 3);
            assert_eq!(
                fixture.memory.read_u32(OUT + 8).unwrap_or(0),
                0,
                "no stale output"
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    8,
                    &[type_info as u32, 9, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND,
                "unknown impl index"
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    dispatch_info,
                    14,
                    &[dispatch_info as u32, 999, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND,
                "unknown href"
            );

            // Impl flags: the base IDispatch entry carries no special flags.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    9,
                    &[type_info as u32, 0, OUT as u32]
                ),
                0,
                "GetImplTypeFlags(0)"
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 0);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    9,
                    &[type_info as u32, 3, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND
            );

            // Real VARIANT descriptors from the property table: Value/Count
            // are VT_I4, Name is VT_BSTR.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    6,
                    &[type_info as u32, 0, OUT as u32]
                ),
                0,
                "GetVarDesc(Value)"
            );
            let value_var = guest_ptr(&fixture, OUT);
            assert_eq!(fixture.memory.read_u32(value_var).unwrap(), 1);
            assert_eq!(fixture.memory.read_u16(value_var + 16).unwrap(), 3);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    6,
                    &[type_info as u32, 1, OUT as u32]
                ),
                0,
                "GetVarDesc(Name)"
            );
            let name_var = guest_ptr(&fixture, OUT);
            assert_eq!(fixture.memory.read_u32(name_var).unwrap(), 2);
            assert_eq!(fixture.memory.read_u16(name_var + 16).unwrap(), 8);
            fixture.memory.map_bytes(OUT, &[0u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    6,
                    &[type_info as u32, 99, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND,
                "unknown var index"
            );
            assert_eq!(guest_ptr(&fixture, OUT), 0);

            // GetDllEntry returns the registered DLL/entry/ordinal.
            fixture.memory.map_bytes(OUT, &[0_u8; 16]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    13,
                    &[
                        type_info as u32,
                        1,
                        0,
                        OUT as u32,
                        (OUT + 4) as u32,
                        (OUT + 8) as u32,
                    ]
                ),
                0,
                "GetDllEntry"
            );
            let dll = guest_ptr(&fixture, OUT);
            let entry = guest_ptr(&fixture, OUT + 4);
            assert_eq!(
                read_utf16_string(&fixture.memory, dll).unwrap(),
                "casa1.dll"
            );
            assert_eq!(
                read_utf16_string(&fixture.memory, entry).unwrap(),
                "DllGetClassObject"
            );
            assert_eq!(fixture.memory.read_u16(OUT + 8).unwrap(), 1);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    13,
                    &[type_info as u32, 99, 0, 0, 0, (OUT + 8) as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    13,
                    &[type_info as u32, 1, 1, 0, 0, (OUT + 8) as u32]
                ),
                E_INVALIDARG
            );

            // GetMops: known member, no Mops BSTR.
            fixture.memory.map_bytes(OUT, &[0xff_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    17,
                    &[type_info as u32, 1, OUT as u32]
                ),
                0,
                "GetMops"
            );
            assert_eq!(guest_ptr(&fixture, OUT), 0);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    17,
                    &[type_info as u32, 99, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND
            );

            // AddressOfMember resolves the real dual vtable slot.
            let vtable = read_guest_pointer(&fixture.memory, server, GuestArch::X86).unwrap();
            let get_value =
                read_guest_pointer(&fixture.memory, vtable + 7 * 4, GuestArch::X86).unwrap();
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    15,
                    &[type_info as u32, 1, 2, OUT as u32]
                ),
                0,
                "AddressOfMember(Value, PROPERTYGET)"
            );
            assert_eq!(guest_ptr(&fixture, OUT), get_value);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    15,
                    &[type_info as u32, 99, 2, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    15,
                    &[type_info as u32, 1, 77, OUT as u32]
                ),
                E_INVALIDARG
            );

            // The event dispinterface's real member address resolves through
            // the owner's IDispatch::Invoke slot.
            let events_info = fixture
                .runtime
                .alloc_com_type_info_object(
                    &mut fixture.memory,
                    "ICasa1AutomationEvents",
                    server,
                    1,
                )
                .unwrap();
            let invoke =
                read_guest_pointer(&fixture.memory, vtable + 6 * 4, GuestArch::X86).unwrap();
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    events_info,
                    15,
                    &[events_info as u32, 10, 1, OUT as u32]
                ),
                0,
                "AddressOfMember(event, FUNC)"
            );
            assert_eq!(guest_ptr(&fixture, OUT), invoke);

            // GetContainingTypeLib + the real ITypeLib surface.
            fixture.memory.map_bytes(OUT, &[0_u8; 16]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    18,
                    &[type_info as u32, OUT as u32, (OUT + 8) as u32]
                ),
                0,
                "GetContainingTypeLib"
            );
            let type_lib = guest_ptr(&fixture, OUT);
            assert_ne!(type_lib, 0);
            assert_eq!(fixture.memory.read_u32(OUT + 8).unwrap(), 0);
            write_iid(&mut fixture, IID_PTR, &COM_IID_ITYPELIB);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_lib,
                    0,
                    &[type_lib as u32, IID_PTR as u32, OUT as u32]
                ),
                0,
                "ITypeLib QueryInterface"
            );
            assert_eq!(guest_ptr(&fixture, OUT), type_lib);
            write_iid(&mut fixture, IID_PTR, &COM_IID_ITYPEINFO);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_lib,
                    0,
                    &[type_lib as u32, IID_PTR as u32, OUT as u32]
                ),
                E_NOINTERFACE,
                "ITypeLib is not ITypeInfo"
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, type_lib, 3, &[type_lib as u32, OUT as u32]),
                0
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 5);
            fixture.memory.map_bytes(OUT, &[0_u8; 32]);
            assert_eq!(
                call_slot(&mut fixture, type_lib, 7, &[type_lib as u32, OUT as u32]),
                0,
                "ITypeLib::GetLibAttr"
            );
            let lib_attr = guest_ptr(&fixture, OUT);
            assert_eq!(
                fixture.memory.read_bytes(lib_attr, 16).unwrap(),
                COM_AUTOMATION_TYPELIB_IID.to_vec()
            );
            assert_eq!(fixture.memory.read_u16(lib_attr + 24).unwrap(), 1);
            write_iid(&mut fixture, IID_PTR, &COM_AUTOMATION_INTERFACE_IID);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_lib,
                    6,
                    &[type_lib as u32, IID_PTR as u32, OUT as u32]
                ),
                0,
                "ITypeLib::GetTypeInfoOfGuid"
            );
            let by_guid = guest_ptr(&fixture, OUT);
            assert_ne!(by_guid, 0);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, by_guid, 3, &[by_guid as u32, OUT as u32]),
                0
            );
            let by_guid_attr = guest_ptr(&fixture, OUT);
            assert_eq!(
                fixture.memory.read_bytes(by_guid_attr, 16).unwrap(),
                COM_AUTOMATION_INTERFACE_IID.to_vec()
            );
            write_iid(&mut fixture, IID_PTR, &[0u8; 16]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_lib,
                    6,
                    &[type_lib as u32, IID_PTR as u32, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND,
                "unknown typelib GUID"
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, type_lib, 4, &[type_lib as u32, 4, OUT as u32]),
                0,
                "ITypeLib::GetTypeInfo(coclass)"
            );
            let class_info = guest_ptr(&fixture, OUT);
            assert_ne!(class_info, 0);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    3,
                    &[class_info as u32, OUT as u32]
                ),
                0
            );
            let class_attrs = guest_ptr(&fixture, OUT);
            assert_eq!(fixture.memory.read_u32(class_attrs + 40).unwrap(), 5);
            assert_eq!(fixture.memory.read_u16(class_attrs + 48).unwrap(), 2);

            // Coclass impl types: default dual interface + source dispinterface.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    9,
                    &[class_info as u32, 0, OUT as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_u32(OUT).unwrap(),
                u32::from(IMPLTYPEFLAG_FDEFAULT | IMPLTYPEFLAG_FDEFAULTVTABLE)
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    9,
                    &[class_info as u32, 1, OUT as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_u32(OUT).unwrap(),
                u32::from(IMPLTYPEFLAG_FSOURCE)
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    9,
                    &[class_info as u32, 2, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    8,
                    &[class_info as u32, 1, OUT as u32]
                ),
                0
            );
            let events_href = fixture.memory.read_u32(OUT).unwrap();
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    14,
                    &[class_info as u32, events_href, OUT as u32]
                ),
                0,
                "coclass GetRefTypeInfo(events)"
            );
            let events_from_class = guest_ptr(&fixture, OUT);
            assert_ne!(events_from_class, 0);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    8,
                    &[class_info as u32, 5, OUT as u32]
                ),
                TYPE_E_ELEMENTNOTFOUND
            );

            // CreateInstance creates the real automation server via the
            // class table; aggregation and wrong type kinds are rejected.
            write_iid(&mut fixture, IID_PTR, &COM_IID_IDISPATCH);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    16,
                    &[class_info as u32, 0, IID_PTR as u32, OUT as u32]
                ),
                0,
                "ITypeInfo::CreateInstance"
            );
            let created = guest_ptr(&fixture, OUT);
            assert_ne!(created, 0);
            assert!(fixture.runtime.com_servers.contains_key(&created));
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    16,
                    &[class_info as u32, 0x1234, IID_PTR as u32, OUT as u32]
                ),
                CLASS_E_NOAGGREGATION
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_info,
                    16,
                    &[type_info as u32, 0, IID_PTR as u32, OUT as u32]
                ),
                TYPE_E_WRONGTYPEKIND
            );

            // ITypeComp::Bind resolves both type names and member names.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_info,
                    4,
                    &[class_info as u32, OUT as u32]
                ),
                0,
                "ITypeInfo::GetTypeComp"
            );
            let type_comp = guest_ptr(&fixture, OUT);
            assert_ne!(type_comp, 0);
            write_iid(&mut fixture, IID_PTR, &COM_IID_ITYPECOMP);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_comp,
                    0,
                    &[type_comp as u32, IID_PTR as u32, OUT as u32]
                ),
                0,
                "ITypeComp QueryInterface"
            );
            assert_eq!(guest_ptr(&fixture, OUT), type_comp);
            write_utf16(&mut fixture, NAME, "Value");
            fixture.memory.map_bytes(OUT, &[0_u8; 16]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_comp,
                    3,
                    &[
                        type_comp as u32,
                        NAME as u32,
                        0,
                        0,
                        OUT as u32,
                        (OUT + 4) as u32,
                    ]
                ),
                0,
                "ITypeComp::Bind(member)"
            );
            let member_info = guest_ptr(&fixture, OUT);
            let member_desc = guest_ptr(&fixture, OUT + 4);
            assert_ne!(member_info, 0);
            assert_ne!(member_desc, 0);
            assert_eq!(fixture.memory.read_u32(member_desc).unwrap(), 1);
            write_utf16(&mut fixture, NAME, "ICasa1Automation");
            fixture.memory.map_bytes(OUT, &[0_u8; 16]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_comp,
                    4,
                    &[type_comp as u32, NAME as u32, 0, OUT as u32]
                ),
                0,
                "ITypeComp::BindType"
            );
            let bound_type = guest_ptr(&fixture, OUT);
            assert_ne!(bound_type, 0);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    bound_type,
                    3,
                    &[bound_type as u32, OUT as u32]
                ),
                0
            );
            let bound_attr = guest_ptr(&fixture, OUT);
            assert_eq!(
                fixture.memory.read_bytes(bound_attr, 16).unwrap(),
                COM_AUTOMATION_INTERFACE_IID.to_vec()
            );
            write_utf16(&mut fixture, NAME, "NoSuchMember");
            fixture.memory.map_bytes(OUT, &[0_u8; 16]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    type_comp,
                    3,
                    &[
                        type_comp as u32,
                        NAME as u32,
                        0,
                        0,
                        OUT as u32,
                        (OUT + 4) as u32,
                    ]
                ),
                TYPE_E_ELEMENTNOTFOUND
            );
            assert_eq!(guest_ptr(&fixture, OUT), 0);
            assert_eq!(guest_ptr(&fixture, OUT + 4), 0);
        })
    }

    // ── Composite monikers ─────────────────────────────────────────────────

    fn parse_moniker(fixture: &mut Fixture, text: &str) -> u64 {
        write_utf16(fixture, NAME, text);
        fixture.memory.map_bytes(OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::MkParseDisplayName,
                &[0, NAME as u32, COOKIE as u32, OUT as u32]
            ),
            0,
            "MkParseDisplayName({text})"
        );
        guest_ptr(fixture, OUT)
    }

    fn compose_monikers(fixture: &mut Fixture, left: u64, right: u64) -> u64 {
        fixture.memory.map_bytes(OUT, &[0_u8; 8]);
        assert_eq!(
            call_slot(
                fixture,
                left,
                6,
                &[left as u32, right as u32, 0, OUT as u32]
            ),
            0,
            "IMoniker::ComposeWith"
        );
        guest_ptr(fixture, OUT)
    }

    #[test]
    fn composite_monikers_compose_enum_reduce_and_bind_real_components() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-composite-moniker");
            let guest_dir = "C:\\moniker-dir";
            let host_dir = fixture
                .runtime
                .win32
                .ge()
                .host_path_for_windows_path(guest_dir)
                .unwrap();
            std::fs::create_dir_all(&host_dir).unwrap();
            std::fs::write(host_dir.join("element.bin"), b"item-bytes").unwrap();

            let file_moniker = parse_moniker(&mut fixture, &format!("file:{guest_dir}"));
            let item_moniker = parse_moniker(&mut fixture, "item:element.bin");
            let composite = compose_monikers(&mut fixture, file_moniker, item_moniker);
            assert_ne!(composite, 0);

            // Display name joins the components; the composite reports
            // MKSYS_GENERICCOMPOSITE.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    composite,
                    7,
                    &[composite as u32, 0, 0, OUT as u32]
                ),
                0,
                "GetDisplayName(composite)"
            );
            let bstr = guest_ptr(&fixture, OUT);
            assert_eq!(
                read_utf16_string(&fixture.memory, bstr).unwrap(),
                format!("file:{guest_dir}!item:element.bin")
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(&mut fixture, composite, 9, &[composite as u32, OUT as u32]),
                0
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 1);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    item_moniker,
                    9,
                    &[item_moniker as u32, OUT as u32]
                ),
                0
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 4);

            // Enum(fForward=TRUE) walks the real chain in order.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    composite,
                    8,
                    &[composite as u32, 1, OUT as u32]
                ),
                0,
                "IMoniker::Enum"
            );
            let enumerator = guest_ptr(&fixture, OUT);
            assert_ne!(enumerator, 0);
            fixture.memory.map_bytes(BUF, &[0_u8; 8]);
            let fetched = OUT + 0x20;
            assert_eq!(
                call_slot(
                    &mut fixture,
                    enumerator,
                    3,
                    &[enumerator as u32, 2, BUF as u32, fetched as u32]
                ),
                0,
                "IEnumMoniker::Next"
            );
            assert_eq!(fixture.memory.read_u32(fetched).unwrap(), 2);
            assert_eq!(guest_ptr(&fixture, BUF), file_moniker);
            assert_eq!(guest_ptr(&fixture, BUF + 4), item_moniker);

            // BindToStorage resolves the file (directory-backed storage) then
            // delegates the item to the element stream.
            write_iid(&mut fixture, IID_PTR, &COM_IID_ISTORAGE);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    composite,
                    4,
                    &[composite as u32, 0, 0, IID_PTR as u32, OUT as u32]
                ),
                0,
                "composite BindToStorage"
            );
            let stream = guest_ptr(&fixture, OUT);
            assert_ne!(stream, 0);
            fixture.memory.map_bytes(BUF, &[0_u8; 16]);
            let read_out = OUT + 0x28;
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    3,
                    &[stream as u32, BUF as u32, 10, read_out as u32]
                ),
                0,
                "item stream Read"
            );
            assert_eq!(
                fixture.memory.read_bytes(BUF, 10).unwrap(),
                b"item-bytes".to_vec()
            );

            // BindToObject on file+item yields the item container storage.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    composite,
                    3,
                    &[composite as u32, 0, 0, 0, OUT as u32]
                ),
                0,
                "file+item BindToObject"
            );
            let storage = guest_ptr(&fixture, OUT);
            assert_ne!(storage, 0);
            assert!(fixture.runtime.com_storages.contains_key(&storage));

            // A missing item fails with MK_E_NOOBJECT.
            let missing = parse_moniker(&mut fixture, "item:absent.bin");
            let bad_composite = compose_monikers(&mut fixture, file_moniker, missing);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    bad_composite,
                    4,
                    &[bad_composite as u32, 0, 0, IID_PTR as u32, OUT as u32]
                ),
                MK_E_NOOBJECT,
                "missing item"
            );

            // class+item: the class moniker creates the server, the item
            // validates a registered member.
            let class_moniker = parse_moniker(
                &mut fixture,
                &format!("clsid:{}", COM_AUTOMATION_SERVER_CLSID),
            );
            let value_item = parse_moniker(&mut fixture, "item:Value");
            let class_composite = compose_monikers(&mut fixture, class_moniker, value_item);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    class_composite,
                    3,
                    &[class_composite as u32, 0, 0, 0, OUT as u32]
                ),
                0,
                "class+item BindToObject"
            );
            let bound_server = guest_ptr(&fixture, OUT);
            assert!(fixture.runtime.com_servers.contains_key(&bound_server));
            let missing_item = parse_moniker(&mut fixture, "item:Missing");
            let bad_class = compose_monikers(&mut fixture, class_moniker, missing_item);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    bad_class,
                    3,
                    &[bad_class as u32, 0, 0, 0, OUT as u32]
                ),
                MK_E_NOOBJECT,
                "class+unknown item"
            );

            // Reduce: a multi-component chain reduces to itself; a one
            // component composite reduces to the component.
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    composite,
                    5,
                    &[composite as u32, 0, 0, 0, OUT as u32]
                ),
                MK_E_REDUCED_TO_SELF
            );
            assert_eq!(guest_ptr(&fixture, OUT), 0);
            let single = fixture
                .runtime
                .alloc_com_moniker_object(
                    &mut fixture.memory,
                    crate::runtime::state::ComMonikerState {
                        kind: crate::runtime::state::ComMonikerKind::File,
                        display_name: "single".to_string(),
                        payload: format!("{COM_COMPOSITE_PREFIX}{file_moniker}"),
                        host_path: None,
                    },
                )
                .unwrap();
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    single,
                    5,
                    &[single as u32, 0, 0, 0, OUT as u32]
                ),
                0,
                "Reduce(single-component composite)"
            );
            assert_eq!(guest_ptr(&fixture, OUT), file_moniker);
        })
    }

    // ── Compound-file storage ──────────────────────────────────────────────

    #[test]
    fn storage_round_trips_through_a_real_cfb_and_rejects_malformed_files() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-cfb-storage");
            let path = fixture._temp.path().join("roundtrip.cfb");
            let path_text = path.to_string_lossy().to_string();
            let storage = match fixture
                .runtime
                .alloc_com_compound_storage(&mut fixture.memory, &path_text, 0, true)
                .unwrap()
            {
                Ok(storage) => storage,
                Err(hr) => panic!("create storage failed: {hr:#x}"),
            };

            // CreateStream + Write + storage Commit writes a real CFB.
            write_utf16(&mut fixture, NAME, "element.bin");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    storage,
                    3,
                    &[storage as u32, NAME as u32, 0x1002, 0, OUT as u32]
                ),
                0,
                "IStorage::CreateStream"
            );
            let stream = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(BUF, b"payload");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    4,
                    &[stream as u32, BUF as u32, 7, (OUT + 4) as u32]
                ),
                0
            );
            assert_eq!(
                call_slot(&mut fixture, storage, 9, &[storage as u32, 0]),
                0,
                "IStorage::Commit(compound)"
            );
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(
                bytes.get(..8).unwrap(),
                &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
                "real OLE compound-file header"
            );
            assert!(bytes.len() >= 512);

            // Reopen from disk: streams and their bytes are enumerated.
            let reopened = match fixture
                .runtime
                .alloc_com_compound_storage(&mut fixture.memory, &path_text, 0, false)
                .unwrap()
            {
                Ok(storage) => storage,
                Err(hr) => panic!("reopen failed: {hr:#x}"),
            };
            assert_ne!(reopened, storage);
            assert_eq!(
                fixture
                    .runtime
                    .com_storages
                    .get(&reopened)
                    .unwrap()
                    .streams
                    .get("element.bin")
                    .cloned(),
                Some(b"payload".to_vec())
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    11,
                    &[reopened as u32, 0, 0, 0, OUT as u32]
                ),
                0,
                "IStorage::EnumElements(reopened)"
            );
            let enumerator = guest_ptr(&fixture, OUT);
            fixture.memory.map_bytes(BUF, &[0_u8; 8]);
            let fetched = OUT + 0x10;
            assert_eq!(
                call_slot(
                    &mut fixture,
                    enumerator,
                    3,
                    &[enumerator as u32, 1, BUF as u32, fetched as u32]
                ),
                0,
                "IEnumSTATSTG::Next(reopened)"
            );
            assert_eq!(fixture.memory.read_u32(fetched).unwrap(), 1);
            let descriptor = guest_ptr(&fixture, BUF);
            assert_eq!(fixture.memory.read_u32(descriptor + 4).unwrap(), 2);
            assert_eq!(fixture.memory.read_u64(descriptor + 8).unwrap(), 7);
            let element_name = guest_ptr(&fixture, descriptor);
            assert_eq!(
                read_utf16_string(&fixture.memory, element_name).unwrap(),
                "element.bin"
            );
            write_utf16(&mut fixture, NAME, "element.bin");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    4,
                    &[reopened as u32, NAME as u32, 0, 0x1000, 0, OUT as u32]
                ),
                0,
                "OpenStream(reopened)"
            );
            let reopened_stream = guest_ptr(&fixture, OUT);
            assert_eq!(
                fixture
                    .runtime
                    .com_streams
                    .get(&reopened_stream)
                    .unwrap()
                    .data
                    .clone(),
                b"payload".to_vec()
            );
            // A rewrite through an opened stream persists on storage Commit.
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened_stream,
                    5,
                    &[reopened_stream as u32, 0, 0, 0, OUT as u32]
                ),
                0,
                "IStream::Seek"
            );
            fixture.memory.map_bytes(BUF, b"PAYLOAD");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened_stream,
                    4,
                    &[reopened_stream as u32, BUF as u32, 7, (OUT + 4) as u32]
                ),
                0,
                "IStream::Write(opened compound stream)"
            );
            assert_eq!(
                call_slot(&mut fixture, reopened, 9, &[reopened as u32, 0]),
                0,
                "IStorage::Commit after stream rewrite"
            );
            let after_rewrite = match fixture
                .runtime
                .alloc_com_compound_storage(&mut fixture.memory, &path_text, 0, false)
                .unwrap()
            {
                Ok(storage) => storage,
                Err(hr) => panic!("reopen after rewrite failed: {hr:#x}"),
            };
            assert_eq!(
                fixture
                    .runtime
                    .com_storages
                    .get(&after_rewrite)
                    .unwrap()
                    .streams
                    .get("element.bin")
                    .cloned(),
                Some(b"PAYLOAD".to_vec())
            );

            write_utf16(&mut fixture, NAME, "absent.bin");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    4,
                    &[reopened as u32, NAME as u32, 0, 0x1000, 0, OUT as u32]
                ),
                STG_E_FILENOTFOUND
            );

            // A malformed file discovered by Revert is the real
            // STG_E_INVALIDHEADER (and does not corrupt the open state).
            std::fs::write(&path, b"corrupted").unwrap();
            assert_eq!(
                call_slot(&mut fixture, reopened, 10, &[reopened as u32]),
                STG_E_INVALIDHEADER,
                "IStorage::Revert(malformed)"
            );
            assert_eq!(
                fixture
                    .runtime
                    .com_storages
                    .get(&reopened)
                    .unwrap()
                    .streams
                    .get("element.bin")
                    .cloned(),
                Some(b"PAYLOAD".to_vec())
            );
            std::fs::write(
                &path,
                crate::runtime::dispatch::msi::write_compound_file(&[(
                    "element.bin".to_string(),
                    b"payload".to_vec(),
                )]),
            )
            .unwrap();

            // Nested storages are real directory entries in the CFB writer.
            write_utf16(&mut fixture, NAME, "nested");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    5,
                    &[reopened as u32, NAME as u32, 0, 0, OUT as u32]
                ),
                0,
                "IStorage::CreateStorage(nested)"
            );
            assert_ne!(guest_ptr(&fixture, OUT), 0);

            // Malformed and absent files answer the real HRESULTs.
            let malformed_path = fixture._temp.path().join("malformed.cfb");
            std::fs::write(&malformed_path, b"not a compound file").unwrap();
            assert_eq!(
                fixture
                    .runtime
                    .alloc_com_compound_storage(
                        &mut fixture.memory,
                        &malformed_path.to_string_lossy(),
                        0,
                        false
                    )
                    .unwrap(),
                Err(STG_E_INVALIDHEADER)
            );
            let absent_path = fixture._temp.path().join("absent.cfb");
            assert_eq!(
                fixture
                    .runtime
                    .alloc_com_compound_storage(
                        &mut fixture.memory,
                        &absent_path.to_string_lossy(),
                        0,
                        false
                    )
                    .unwrap(),
                Err(STG_E_FILENOTFOUND)
            );

            // The directory backend remains the fallback for a directory.
            let directory = fixture._temp.path().join("directory-store");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("legacy.bin"), b"legacy").unwrap();
            let directory_storage = fixture
                .runtime
                .alloc_com_storage_object(
                    &mut fixture.memory,
                    Some(directory.to_string_lossy().to_string()),
                    "directory-store",
                    0,
                )
                .unwrap();
            assert_eq!(
                fixture
                    .runtime
                    .com_storages
                    .get(&directory_storage)
                    .unwrap()
                    .streams
                    .get("legacy.bin")
                    .cloned(),
                Some(b"legacy".to_vec())
            );
        })
    }

    // ── Nested compound storages ───────────────────────────────────────────

    const NESTED_ROOT_CLSID: [u8; 16] = [
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19,
    ];
    const NESTED_SUB_CLSID: [u8; 16] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30,
    ];

    fn cfb_create_storage(fixture: &mut Fixture, parent: u64, name: &str) -> u64 {
        write_utf16(fixture, NAME, name);
        fixture.memory.map_bytes(OUT, &[0_u8; 8]);
        assert_eq!(
            call_slot(
                fixture,
                parent,
                5,
                &[parent as u32, NAME as u32, 0, 0, OUT as u32]
            ),
            0,
            "IStorage::CreateStorage({name})"
        );
        guest_ptr(fixture, OUT)
    }

    fn cfb_open_storage_hr(fixture: &mut Fixture, parent: u64, name: &str) -> u32 {
        write_utf16(fixture, NAME, name);
        fixture.memory.map_bytes(OUT, &[0_u8; 8]);
        call_slot(
            fixture,
            parent,
            6,
            &[parent as u32, NAME as u32, 0, 0, 0, OUT as u32],
        )
    }

    fn cfb_open_storage(fixture: &mut Fixture, parent: u64, name: &str) -> u64 {
        assert_eq!(
            cfb_open_storage_hr(fixture, parent, name),
            0,
            "IStorage::OpenStorage({name})"
        );
        guest_ptr(fixture, OUT)
    }

    fn cfb_create_stream(fixture: &mut Fixture, parent: u64, name: &str, data: &[u8]) -> u64 {
        write_utf16(fixture, NAME, name);
        fixture.memory.map_bytes(OUT, &[0_u8; 8]);
        assert_eq!(
            call_slot(
                fixture,
                parent,
                3,
                &[parent as u32, NAME as u32, 0x1002, 0, OUT as u32]
            ),
            0,
            "IStorage::CreateStream({name})"
        );
        let stream = guest_ptr(fixture, OUT);
        fixture.memory.map_bytes(BUF, data);
        let written = OUT + 0x40;
        assert_eq!(
            call_slot(
                fixture,
                stream,
                4,
                &[stream as u32, BUF as u32, data.len() as u32, written as u32]
            ),
            0,
            "IStream::Write({name})"
        );
        assert_eq!(
            fixture.memory.read_u32(written).unwrap() as usize,
            data.len()
        );
        stream
    }

    fn cfb_open_stream_hr(fixture: &mut Fixture, parent: u64, name: &str) -> u32 {
        write_utf16(fixture, NAME, name);
        fixture.memory.map_bytes(OUT, &[0_u8; 8]);
        call_slot(
            fixture,
            parent,
            4,
            &[parent as u32, NAME as u32, 0, 0, 0, OUT as u32],
        )
    }

    fn cfb_read_stream(fixture: &mut Fixture, stream: u64, expected: &[u8]) {
        fixture.memory.map_bytes(BUF, &[0_u8; 128]);
        let read_out = OUT + 0x48;
        assert_eq!(
            call_slot(
                fixture,
                stream,
                3,
                &[
                    stream as u32,
                    BUF as u32,
                    expected.len() as u32,
                    read_out as u32
                ]
            ),
            0,
            "IStream::Read"
        );
        assert_eq!(
            fixture.memory.read_u32(read_out).unwrap() as usize,
            expected.len()
        );
        assert_eq!(
            fixture.memory.read_bytes(BUF, expected.len()).unwrap(),
            expected.to_vec()
        );
    }

    fn cfb_commit(fixture: &mut Fixture, storage: u64) {
        assert_eq!(
            call_slot(fixture, storage, 9, &[storage as u32, 0]),
            0,
            "IStorage::Commit"
        );
    }

    fn cfb_enum_elements(fixture: &mut Fixture, storage: u64) -> Vec<(String, u32, [u8; 16])> {
        fixture.memory.map_bytes(OUT, &[0_u8; 8]);
        assert_eq!(
            call_slot(fixture, storage, 11, &[storage as u32, 0, 0, 0, OUT as u32]),
            0,
            "IStorage::EnumElements"
        );
        let enumerator = guest_ptr(fixture, OUT);
        fixture.memory.map_bytes(BUF, &[0_u8; 32 * 4]);
        let fetched = OUT + 0x40;
        let hr = call_slot(
            fixture,
            enumerator,
            3,
            &[enumerator as u32, 32, BUF as u32, fetched as u32],
        );
        assert!(hr == 0 || hr == S_FALSE, "IEnumSTATSTG::Next {hr:#x}");
        let count = fixture.memory.read_u32(fetched).unwrap();
        let mut elements = Vec::new();
        for index in 0..count as u64 {
            let descriptor = guest_ptr(fixture, BUF + index * 4);
            let name_ptr = guest_ptr(fixture, descriptor);
            let name = read_utf16_string(&fixture.memory, name_ptr).unwrap();
            let kind = fixture.memory.read_u32(descriptor + 4).unwrap();
            let mut clsid = [0_u8; 16];
            clsid.copy_from_slice(&fixture.memory.read_bytes(descriptor + 48, 16).unwrap());
            elements.push((name, kind, clsid));
        }
        elements
    }

    /// root/alpha.bin
    /// root/Storage/outer.bin
    /// root/Storage/Sub/{beta.bin,gamma.bin}
    fn build_nested_compound(
        fixture: &mut Fixture,
        file_name: &str,
    ) -> (std::path::PathBuf, String, u64) {
        let path = fixture._temp.path().join(file_name);
        let path_text = path.to_string_lossy().to_string();
        let root = match fixture
            .runtime
            .alloc_com_compound_storage(&mut fixture.memory, &path_text, 0, true)
            .unwrap()
        {
            Ok(storage) => storage,
            Err(hr) => panic!("create compound storage failed: {hr:#x}"),
        };
        fixture.memory.map_bytes(OUT + 0x80, &NESTED_ROOT_CLSID);
        assert_eq!(
            call_slot(fixture, root, 15, &[root as u32, (OUT + 0x80) as u32]),
            0,
            "IStorage::SetClass(root)"
        );
        let storage = cfb_create_storage(fixture, root, "Storage");
        let sub = cfb_create_storage(fixture, storage, "Sub");
        fixture.memory.map_bytes(OUT + 0x80, &NESTED_SUB_CLSID);
        assert_eq!(
            call_slot(fixture, sub, 15, &[sub as u32, (OUT + 0x80) as u32]),
            0,
            "IStorage::SetClass(Sub)"
        );
        cfb_create_stream(fixture, root, "alpha.bin", b"alpha-bytes");
        cfb_create_stream(fixture, storage, "outer.bin", b"outer-bytes");
        cfb_create_stream(fixture, sub, "beta.bin", b"beta-bytes");
        cfb_create_stream(fixture, sub, "gamma.bin", b"gamma-bytes");
        (path, path_text, root)
    }

    fn reopen_compound(fixture: &mut Fixture, path_text: &str) -> u64 {
        match fixture
            .runtime
            .alloc_com_compound_storage(&mut fixture.memory, path_text, 0, false)
            .unwrap()
        {
            Ok(storage) => storage,
            Err(hr) => panic!("reopen compound storage failed: {hr:#x}"),
        }
    }

    #[test]
    fn nested_storage_tree_round_trips_and_enumerates() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-cfb-nested-tree");
            let (path, path_text, root) = build_nested_compound(&mut fixture, "nested-tree.cfb");
            cfb_commit(&mut fixture, root);

            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(
                bytes.get(..8).unwrap(),
                &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
                "real OLE compound-file header"
            );
            let compound =
                crate::runtime::dispatch::msi::CompoundFile::parse(bytes).expect("parse tree");
            assert_eq!(
                compound.stream_at("Root/Storage/Sub/beta.bin"),
                Some(b"beta-bytes".to_vec()),
                "nested stream resolved by path"
            );
            assert_eq!(
                compound.stream_at("Root/Storage/Sub/gamma.bin"),
                Some(b"gamma-bytes".to_vec())
            );
            assert_eq!(
                compound.stream_at("Root/Storage/outer.bin"),
                Some(b"outer-bytes".to_vec())
            );
            assert_eq!(
                compound.stream_at("Root/alpha.bin"),
                Some(b"alpha-bytes".to_vec())
            );
            let root_entry = compound.root_entry().expect("root entry");
            assert_eq!(root_entry.kind, 5);
            assert_eq!(root_entry.clsid, NESTED_ROOT_CLSID);
            let sub_entry = compound
                .entry_at("Root/Storage/Sub")
                .expect("nested storage entry");
            assert_eq!(sub_entry.kind, 1);
            assert_eq!(sub_entry.clsid, NESTED_SUB_CLSID);
            assert_ne!(sub_entry.created, 0);
            assert_ne!(sub_entry.modified, 0);
            let storage_children = compound.children("Root/Storage").unwrap();
            assert_eq!(storage_children.len(), 2);
            assert!(
                storage_children
                    .iter()
                    .any(|entry| { entry.decoded_name() == "Sub" && entry.kind == 1 })
            );
            assert!(
                storage_children
                    .iter()
                    .any(|entry| { entry.decoded_name() == "outer.bin" && entry.kind == 2 })
            );

            let reopened = reopen_compound(&mut fixture, &path_text);
            let storage = cfb_open_storage(&mut fixture, reopened, "Storage");
            let sub = cfb_open_storage(&mut fixture, storage, "Sub");

            assert_eq!(
                cfb_open_stream_hr(&mut fixture, sub, "beta.bin"),
                0,
                "OpenStream(nested)"
            );
            let beta = guest_ptr(&fixture, OUT);
            cfb_read_stream(&mut fixture, beta, b"beta-bytes");

            assert_eq!(
                cfb_open_stream_hr(&mut fixture, sub, "absent.bin"),
                STG_E_FILENOTFOUND
            );
            assert_eq!(
                cfb_open_storage_hr(&mut fixture, reopened, "Missing"),
                STG_E_FILENOTFOUND
            );
            assert_eq!(
                cfb_open_storage_hr(&mut fixture, storage, "Sub"),
                0,
                "reopening a live nested storage"
            );

            let root_elements = cfb_enum_elements(&mut fixture, reopened);
            assert_eq!(root_elements.len(), 2);
            assert!(root_elements.iter().any(|(name, kind, clsid)| {
                name == "Storage" && *kind == 1 && clsid.iter().all(|byte| *byte == 0)
            }));
            assert!(
                root_elements
                    .iter()
                    .any(|(name, kind, _)| { name == "alpha.bin" && *kind == 2 })
            );
            let storage_elements = cfb_enum_elements(&mut fixture, storage);
            assert_eq!(storage_elements.len(), 2);
            assert!(storage_elements.iter().any(|(name, kind, clsid)| {
                name == "Sub" && *kind == 1 && *clsid == NESTED_SUB_CLSID
            }));
            assert!(
                storage_elements
                    .iter()
                    .any(|(name, kind, _)| { name == "outer.bin" && *kind == 2 })
            );
            let sub_elements = cfb_enum_elements(&mut fixture, sub);
            assert_eq!(sub_elements.len(), 2);
            assert!(
                sub_elements
                    .iter()
                    .any(|(name, kind, _)| { name == "beta.bin" && *kind == 2 })
            );
            assert!(
                sub_elements
                    .iter()
                    .any(|(name, kind, _)| { name == "gamma.bin" && *kind == 2 })
            );

            // The storage CLSID round-trips through Stat after reopening.
            fixture.memory.map_bytes(STAT, &[0_u8; 72]);
            assert_eq!(
                call_slot(&mut fixture, sub, 17, &[sub as u32, STAT as u32, 0]),
                0,
                "IStorage::Stat(sub)"
            );
            assert_eq!(fixture.memory.read_u32(STAT + 4).unwrap(), 1);
            assert_eq!(
                fixture.memory.read_bytes(STAT + 48, 16).unwrap(),
                NESTED_SUB_CLSID.to_vec()
            );
            fixture.memory.map_bytes(STAT, &[0_u8; 72]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    17,
                    &[reopened as u32, STAT as u32, 0]
                ),
                0,
                "IStorage::Stat(root)"
            );
            assert_eq!(
                fixture.memory.read_bytes(STAT + 48, 16).unwrap(),
                NESTED_ROOT_CLSID.to_vec()
            );

            // Nested IStream writes honor a real seek offset, and a Commit
            // issued through the nested storage rewrites the whole file.
            assert_eq!(
                call_slot(
                    &mut fixture,
                    beta,
                    5,
                    &[beta as u32, 5, 0, 0, (OUT + 0x40) as u32]
                ),
                0,
                "IStream::Seek(nested, 5)"
            );
            fixture.memory.map_bytes(BUF, b"BYTES");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    beta,
                    4,
                    &[beta as u32, BUF as u32, 5, (OUT + 0x44) as u32]
                ),
                0,
                "IStream::Write(nested at offset 5)"
            );
            cfb_commit(&mut fixture, sub);
            let after_offset_write = reopen_compound(&mut fixture, &path_text);
            let storage_after = cfb_open_storage(&mut fixture, after_offset_write, "Storage");
            let sub_after = cfb_open_storage(&mut fixture, storage_after, "Sub");
            assert_eq!(cfb_open_stream_hr(&mut fixture, sub_after, "beta.bin"), 0);
            let beta_after = guest_ptr(&fixture, OUT);
            cfb_read_stream(&mut fixture, beta_after, b"beta-BYTES");
        })
    }

    #[test]
    fn nested_storage_destroy_copy_and_error_paths_persist() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-cfb-nested-copy");
            let (path, path_text, root) = build_nested_compound(&mut fixture, "nested-copy.cfb");
            cfb_commit(&mut fixture, root);

            let reopened = reopen_compound(&mut fixture, &path_text);
            assert_eq!(
                cfb_open_storage_hr(&mut fixture, reopened, "Missing"),
                STG_E_FILENOTFOUND
            );

            write_utf16(&mut fixture, NAME, "Storage");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    5,
                    &[reopened as u32, NAME as u32, 0, 0, OUT as u32]
                ),
                STG_E_FILEALREADYEXISTS,
                "CreateStorage collision"
            );
            write_utf16(&mut fixture, NAME, "alpha.bin");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    3,
                    &[reopened as u32, NAME as u32, 0x1002, 0, OUT as u32]
                ),
                STG_E_FILEALREADYEXISTS,
                "CreateStream collision"
            );
            write_utf16(&mut fixture, NAME, "Storage");
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                call_slot(
                    &mut fixture,
                    reopened,
                    3,
                    &[reopened as u32, NAME as u32, 0x1002, 0, OUT as u32]
                ),
                STG_E_FILEALREADYEXISTS,
                "CreateStream over a storage"
            );

            let source_storage = cfb_open_storage(&mut fixture, reopened, "Storage");
            let copy = cfb_create_storage(&mut fixture, reopened, "Copy");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    source_storage,
                    7,
                    &[source_storage as u32, 0, 0, 0, copy as u32]
                ),
                0,
                "IStorage::CopyTo"
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    source_storage,
                    7,
                    &[source_storage as u32, 0, 0, 0, copy as u32]
                ),
                STG_E_FILEALREADYEXISTS,
                "CopyTo collision"
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    source_storage,
                    7,
                    &[source_storage as u32, 0, 0, 0, source_storage as u32]
                ),
                STG_E_ACCESSDENIED,
                "CopyTo onto itself"
            );
            cfb_commit(&mut fixture, reopened);

            let reopened_copy = reopen_compound(&mut fixture, &path_text);
            let copy_storage = cfb_open_storage(&mut fixture, reopened_copy, "Copy");
            let copied_sub = cfb_open_storage(&mut fixture, copy_storage, "Sub");
            assert_eq!(cfb_open_stream_hr(&mut fixture, copied_sub, "beta.bin"), 0);
            let copied_beta = guest_ptr(&fixture, OUT);
            cfb_read_stream(&mut fixture, copied_beta, b"beta-bytes");
            assert_eq!(
                cfb_open_stream_hr(&mut fixture, copy_storage, "outer.bin"),
                0
            );
            let copied_outer = guest_ptr(&fixture, OUT);
            cfb_read_stream(&mut fixture, copied_outer, b"outer-bytes");

            // Destroy one stream and one whole storage subtree; both survive
            // a commit/reopen round trip.
            write_utf16(&mut fixture, NAME, "beta.bin");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    copied_sub,
                    12,
                    &[copied_sub as u32, NAME as u32]
                ),
                0,
                "DestroyElement(stream)"
            );
            assert_eq!(
                call_slot(
                    &mut fixture,
                    copied_sub,
                    12,
                    &[copied_sub as u32, NAME as u32]
                ),
                STG_E_FILENOTFOUND,
                "DestroyElement(missing stream)"
            );
            assert_eq!(
                cfb_open_stream_hr(&mut fixture, copied_sub, "beta.bin"),
                STG_E_FILENOTFOUND
            );
            write_utf16(&mut fixture, NAME, "Missing");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    copy_storage,
                    12,
                    &[copy_storage as u32, NAME as u32]
                ),
                STG_E_FILENOTFOUND,
                "DestroyElement(missing element)"
            );
            cfb_commit(&mut fixture, reopened_copy);

            let bytes = std::fs::read(&path).unwrap();
            let compound =
                crate::runtime::dispatch::msi::CompoundFile::parse(bytes).expect("parse tree");
            assert_eq!(compound.stream_at("Root/Copy/Sub/beta.bin"), None);
            assert_eq!(
                compound.stream_at("Root/Copy/Sub/gamma.bin"),
                Some(b"gamma-bytes".to_vec())
            );
            assert_eq!(
                compound.stream_at("Root/Copy/outer.bin"),
                Some(b"outer-bytes".to_vec())
            );
            assert_eq!(
                compound.stream_at("Root/Storage/Sub/beta.bin"),
                Some(b"beta-bytes".to_vec()),
                "destroying a copied stream leaves the source intact"
            );

            write_utf16(&mut fixture, NAME, "Sub");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    copy_storage,
                    12,
                    &[copy_storage as u32, NAME as u32]
                ),
                0,
                "DestroyElement(storage subtree)"
            );
            assert_eq!(
                cfb_open_storage_hr(&mut fixture, copy_storage, "Sub"),
                STG_E_FILENOTFOUND
            );
            cfb_commit(&mut fixture, reopened_copy);
            let bytes = std::fs::read(&path).unwrap();
            let compound =
                crate::runtime::dispatch::msi::CompoundFile::parse(bytes).expect("parse tree");
            assert!(compound.entry_at("Root/Copy/Sub").is_none());
            assert!(compound.entry_at("Root/Copy/Sub/gamma.bin").is_none());
            assert_eq!(
                compound.stream_at("Root/Copy/outer.bin"),
                Some(b"outer-bytes".to_vec())
            );
            assert_eq!(
                compound.stream_at("Root/Storage/Sub/gamma.bin"),
                Some(b"gamma-bytes".to_vec()),
                "destroying a copied storage leaves the source intact"
            );
        })
    }

    #[test]
    fn nested_storage_revert_discards_changes_and_rejects_malformed_directories() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-cfb-nested-revert");
            let (path, path_text, root) = build_nested_compound(&mut fixture, "nested-revert.cfb");
            cfb_commit(&mut fixture, root);

            let reopened = reopen_compound(&mut fixture, &path_text);
            let storage = cfb_open_storage(&mut fixture, reopened, "Storage");
            let sub = cfb_open_storage(&mut fixture, storage, "Sub");
            assert_eq!(cfb_open_stream_hr(&mut fixture, sub, "beta.bin"), 0);
            let beta = guest_ptr(&fixture, OUT);
            assert_eq!(
                call_slot(&mut fixture, beta, 5, &[beta as u32, 0, 0, 0, OUT as u32]),
                0,
                "IStream::Seek(0)"
            );
            fixture.memory.map_bytes(BUF, b"CORRUPTED!");
            assert_eq!(
                call_slot(
                    &mut fixture,
                    beta,
                    4,
                    &[beta as u32, BUF as u32, 10, (OUT + 4) as u32]
                ),
                0,
                "IStream::Write(before revert)"
            );
            assert_eq!(
                call_slot(&mut fixture, reopened, 10, &[reopened as u32]),
                0,
                "IStorage::Revert(root)"
            );
            // The already-open nested objects observe the reverted tree.
            assert_eq!(cfb_open_stream_hr(&mut fixture, sub, "beta.bin"), 0);
            let reverted_beta = guest_ptr(&fixture, OUT);
            cfb_read_stream(&mut fixture, reverted_beta, b"beta-bytes");
            let storage = cfb_open_storage(&mut fixture, reopened, "Storage");
            let sub = cfb_open_storage(&mut fixture, storage, "Sub");
            assert_eq!(cfb_open_stream_hr(&mut fixture, sub, "beta.bin"), 0);
            let beta = guest_ptr(&fixture, OUT);
            cfb_read_stream(&mut fixture, beta, b"beta-bytes");
            let bytes = std::fs::read(&path).unwrap();
            let compound =
                crate::runtime::dispatch::msi::CompoundFile::parse(bytes).expect("parse tree");
            assert_eq!(
                compound.stream_at("Root/Storage/Sub/beta.bin"),
                Some(b"beta-bytes".to_vec()),
                "Revert discards uncommitted nested writes"
            );

            // Malformed directory trees: cyclic sibling, absent pointer,
            // missing root, and a root child cycle.
            let base = crate::runtime::dispatch::msi::write_compound_file(&[(
                "payload".to_string(),
                b"data".to_vec(),
            )]);
            let dir_start = u32::from_le_bytes(base[0x2C..0x30].try_into().unwrap()) as usize;
            let dir_offset = (dir_start + 1) * 512;
            let second = dir_offset + 128;

            let mut cyclic = base.clone();
            cyclic[second + 0x48..second + 0x4C].copy_from_slice(&1u32.to_le_bytes());
            assert!(
                crate::runtime::dispatch::msi::CompoundFile::parse(cyclic.clone()).is_err(),
                "cyclic sibling chain rejected"
            );
            let cyclic_path = fixture._temp.path().join("cyclic.cfb");
            std::fs::write(&cyclic_path, &cyclic).unwrap();
            assert_eq!(
                fixture
                    .runtime
                    .alloc_com_compound_storage(
                        &mut fixture.memory,
                        &cyclic_path.to_string_lossy(),
                        0,
                        false
                    )
                    .unwrap(),
                Err(STG_E_INVALIDHEADER)
            );

            let mut absent = base.clone();
            absent[second + 0x4C..second + 0x50].copy_from_slice(&999u32.to_le_bytes());
            assert!(
                crate::runtime::dispatch::msi::CompoundFile::parse(absent).is_err(),
                "absent child pointer rejected"
            );

            let mut rootless = base.clone();
            rootless[dir_offset + 0x42] = 0;
            assert!(
                crate::runtime::dispatch::msi::CompoundFile::parse(rootless).is_err(),
                "missing root entry rejected"
            );

            let mut root_cycle = base.clone();
            root_cycle[dir_offset + 0x4C..dir_offset + 0x50].copy_from_slice(&0u32.to_le_bytes());
            assert!(
                crate::runtime::dispatch::msi::CompoundFile::parse(root_cycle).is_err(),
                "root child cycle rejected"
            );
        })
    }

    // ── Marshal stream ──────────────────────────────────────────────────────

    #[test]
    fn marshal_stream_is_a_real_istream_and_resolves_the_record() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("com-marshal");
            let server = create_server(&mut fixture);
            write_iid(&mut fixture, IID_PTR, &COM_IID_IDISPATCH);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CoMarshalInterThreadInterfaceInStream,
                    &[IID_PTR as u32, server as u32, OUT as u32]
                ),
                0
            );
            let stream = guest_ptr(&fixture, OUT);
            assert_ne!(stream, 0);

            // The payload is readable through the real IStream vtable.
            fixture.memory.map_bytes(BUF, &[0_u8; 8]);
            let read_out = OUT + 0x10;
            assert_eq!(
                call_slot(
                    &mut fixture,
                    stream,
                    3,
                    &[stream as u32, BUF as u32, 8, read_out as u32]
                ),
                0
            );
            assert_eq!(fixture.memory.read_u32(read_out).unwrap(), 8);

            // The resolver consumes and releases the stream.
            write_iid(&mut fixture, IID_PTR, &COM_IID_IDISPATCH);
            fixture.memory.map_bytes(OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CoGetInterfaceAndReleaseStream,
                    &[stream as u32, IID_PTR as u32, OUT as u32]
                ),
                0
            );
            assert_eq!(guest_ptr(&fixture, OUT), server);
            assert!(!fixture.runtime.guest_objects.contains_key(&stream));
            assert!(!fixture.runtime.com_streams.contains_key(&stream));
        })
    }
}
