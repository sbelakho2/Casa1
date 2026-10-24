//! WASAPI (IAudioClient / IAudioRenderClient / IAudioService) dispatch
//! handlers, moved out of the runtime monolith.  Per-endpoint state lives in
//! `crate::audio_activation`; these methods marshal guest arguments and route
//! the ready-event signal through the runtime's guest event machinery.

use super::super::*;

impl PeHostRuntime {
    // ── IAudioClient / IAudioRenderClient dispatch ──────────────────────────
    //
    // The methods below implement the real WASAPI method surface of an audio
    // endpoint activated by `ActivateAudioInterfaceAsync`.  The per-endpoint
    // state (parsed format, real buffer geometry, playback clock, service
    // objects) lives in `crate::audio_activation`; these handlers marshal the
    // guest arguments, touch guest memory, and route the ready-event signal
    // through the runtime's real guest event machinery.

    /// `IActivateAudioInterfaceAsyncOperation::QueryInterface(riid, ppv)`.
    pub(crate) fn dispatch_audio_activation_operation_query_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_E_NOINTERFACE, ACTIVATION_S_OK, AUDCLNT_E_POINTER,
            activation_operation_supports_riid,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if riid_ptr == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let riid = match memory.read_bytes(riid_ptr, 16) {
            Ok(bytes) => <[u8; 16]>::try_from(bytes.as_slice()).unwrap_or([0_u8; 16]),
            Err(_) => {
                state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
                self.last_error = 0;
                return Ok(());
            }
        };
        if activation_operation_supports_riid(&riid) {
            self.add_ref_guest_object(object)?;
            if out != 0 {
                write_guest_pointer(memory, out, object, self.guest_arch)?;
            }
            state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
        } else {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch)?;
            }
            state.set(Register::Rax, u64::from(ACTIVATION_E_NOINTERFACE));
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IActivateAudioInterfaceAsyncOperation::GetActivateResult(activateResult,
    /// activatedInterface)`.
    pub(crate) fn dispatch_audio_activation_operation_get_activate_result(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_S_OK, AUDCLNT_E_POINTER, operation_get_activate_result,
        };
        let operation = guest_call_arg(state, memory, 0)?;
        let result_out = guest_call_arg(state, memory, 1)?;
        let interface_out = guest_call_arg(state, memory, 2)?;
        if result_out == 0 || interface_out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        match operation_get_activate_result(self.guest_pid, operation) {
            Ok((result_hr, interface_object)) => {
                if interface_object != 0 {
                    self.add_ref_guest_object(interface_object)?;
                }
                write_u32(memory, result_out, result_hr);
                write_guest_pointer(memory, interface_out, interface_object, self.guest_arch)?;
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
            }
            Err(hr) => state.set(Register::Rax, u64::from(hr)),
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient::QueryInterface(riid, ppv)`.
    pub(crate) fn dispatch_audio_client_query_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_E_NOINTERFACE, ACTIVATION_S_OK, AUDCLNT_E_POINTER, IID_IAUDIO_CLIENT,
            IID_IAUDIO_CLIENT_2, IID_IAUDIO_CLIENT_3, IID_IUNKNOWN,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if riid_ptr == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let riid = match memory.read_bytes(riid_ptr, 16) {
            Ok(bytes) => <[u8; 16]>::try_from(bytes.as_slice()).unwrap_or([0_u8; 16]),
            Err(_) => {
                state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
                self.last_error = 0;
                return Ok(());
            }
        };
        let supported = riid == IID_IUNKNOWN
            || riid == IID_IAUDIO_CLIENT
            || riid == IID_IAUDIO_CLIENT_2
            || riid == IID_IAUDIO_CLIENT_3;
        if supported {
            self.add_ref_guest_object(object)?;
            if out != 0 {
                write_guest_pointer(memory, out, object, self.guest_arch)?;
            }
            state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
        } else {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch)?;
            }
            state.set(Register::Rax, u64::from(ACTIVATION_E_NOINTERFACE));
        }
        self.last_error = 0;
        Ok(())
    }

    /// Read a guest `WAVEFORMATEX`/`WAVEFORMATEXTENSIBLE` pointer and parse
    /// it for real (extending to the 40-byte form when the tag says so).
    pub(crate) fn read_guest_wave_format(
        &self,
        memory: &MemoryImage,
        format_ptr: u64,
    ) -> Result<crate::audio_activation::AudioClientFormat, u32> {
        use crate::audio_activation::{
            AUDCLNT_E_POINTER, WAVE_FORMAT_EXTENSIBLE, parse_wave_format,
        };
        if format_ptr == 0 {
            return Err(AUDCLNT_E_POINTER);
        }
        let mut bytes = memory
            .read_bytes(format_ptr, 18)
            .map_err(|_| AUDCLNT_E_POINTER)?;
        if bytes.len() >= 2 && u16::from_le_bytes([bytes[0], bytes[1]]) == WAVE_FORMAT_EXTENSIBLE {
            // Fall back to the short read when the guest only mapped the
            // base structure; the parser then rejects it for real.
            if let Ok(extended) = memory.read_bytes(format_ptr, 40) {
                bytes = extended;
            }
        }
        parse_wave_format(&bytes)
    }

    /// Allocate the real guest render buffer for an initialization plan and
    /// commit the successful `Initialize`.
    pub(crate) fn commit_audio_client_initialize(
        &mut self,
        memory: &mut MemoryImage,
        object: u64,
        plan: &crate::audio_activation::AudioInitializePlan,
        format: &crate::audio_activation::AudioClientFormat,
    ) -> AppResult<u32> {
        let buffer_bytes = (plan.buffer_frames as u64)
            .saturating_mul(plan.block_align as u64)
            .max(1);
        let buffer_address = self.alloc_zeroed(memory, buffer_bytes as usize, 16)?;
        Ok(crate::audio_activation::commit_initialize(
            self.guest_pid,
            object,
            plan,
            format,
            buffer_address,
            buffer_bytes,
        ))
    }

    /// `IAudioClient::Initialize(share_mode, stream_flags, buffer_duration,
    /// periodicity, format, session_guid)`.
    pub(crate) fn dispatch_audio_client_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{AUDCLNT_E_POINTER, plan_initialize};
        let object = guest_call_arg(state, memory, 0)?;
        let share_mode = guest_call_arg_u32(state, memory, 1)?;
        let stream_flags = guest_call_arg_u32(state, memory, 2)?;
        let duration_hns = guest_call_arg(state, memory, 3)? as i64;
        let periodicity_hns = guest_call_arg(state, memory, 4)? as i64;
        let format_ptr = guest_call_arg(state, memory, 5)?;
        let _session_guid = guest_call_arg(state, memory, 6)?;
        let fail = |state: &mut CpuState, hr: u32| {
            state.set(Register::Rax, u64::from(hr));
        };
        if format_ptr == 0 {
            fail(state, AUDCLNT_E_POINTER);
            self.last_error = 0;
            return Ok(());
        }
        let format = match self.read_guest_wave_format(memory, format_ptr) {
            Ok(format) => format,
            Err(hr) => {
                fail(state, hr);
                self.last_error = 0;
                return Ok(());
            }
        };
        let plan = match plan_initialize(
            self.guest_pid,
            object,
            share_mode,
            stream_flags,
            duration_hns,
            periodicity_hns,
            &format,
        ) {
            Ok(plan) => plan,
            Err(hr) => {
                fail(state, hr);
                self.last_error = 0;
                return Ok(());
            }
        };
        let hr = self.commit_audio_client_initialize(memory, object, &plan, &format)?;
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        self.push_trace(
            "audio",
            "IAudioClient::Initialize",
            BTreeMap::from([
                ("share_mode".to_string(), json!(share_mode)),
                ("stream_flags".to_string(), json!(stream_flags)),
                ("buffer_frames".to_string(), json!(plan.buffer_frames)),
                ("channels".to_string(), json!(format.channels)),
                ("sample_rate".to_string(), json!(format.sample_rate)),
                ("bits_per_sample".to_string(), json!(format.bits_per_sample)),
            ]),
            json!(hr),
        );
        Ok(())
    }

    /// `IAudioClient::GetBufferSize(pNumBufferFrames)`.
    pub(crate) fn dispatch_audio_client_get_buffer_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{ACTIVATION_S_OK, AUDCLNT_E_POINTER, get_buffer_size};
        let object = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
        } else {
            match get_buffer_size(self.guest_pid, object) {
                Ok(frames) => {
                    write_u32(memory, out, frames);
                    state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
                }
                Err(hr) => state.set(Register::Rax, u64::from(hr)),
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient::GetStreamLatency(phnsLatency)`.
    pub(crate) fn dispatch_audio_client_get_stream_latency(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{ACTIVATION_S_OK, AUDCLNT_E_POINTER, get_stream_latency};
        let object = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
        } else {
            match get_stream_latency(self.guest_pid, object) {
                Ok(latency_hns) => {
                    write_u64(memory, out, latency_hns);
                    state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
                }
                Err(hr) => state.set(Register::Rax, u64::from(hr)),
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient::GetCurrentPadding(pNumPaddingFrames)`.
    pub(crate) fn dispatch_audio_client_get_current_padding(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{ACTIVATION_S_OK, AUDCLNT_E_POINTER, get_current_padding};
        let object = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
        } else {
            match get_current_padding(self.guest_pid, object) {
                Ok(padding) => {
                    write_u32(memory, out, padding);
                    state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
                }
                Err(hr) => state.set(Register::Rax, u64::from(hr)),
            }
        }
        // The guest observed the buffer state; if the drain freed space the
        // ready event is raised through the real event machinery.
        self.signal_audio_ready_event(object);
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient::IsFormatSupported(share_mode, format, ppClosestMatch)`.
    pub(crate) fn dispatch_audio_client_is_format_supported(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            AUDCLNT_E_DEVICE_INVALIDATED, AUDCLNT_E_POINTER, AUDCLNT_S_FALSE,
            WAVE_FORMAT_EXTENSIBLE, audio_format_support, device_of, mix_format_for_device,
            parse_wave_format, wave_format_bytes,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let share_mode = guest_call_arg_u32(state, memory, 1)?;
        let format_ptr = guest_call_arg(state, memory, 2)?;
        let closest_out = guest_call_arg(state, memory, 3)?;
        if share_mode > crate::audio_activation::AUDCLNT_SHAREMODE_EXCLUSIVE {
            state.set(
                Register::Rax,
                u64::from(crate::audio_activation::AUDCLNT_E_INVALIDARG),
            );
            self.last_error = 0;
            return Ok(());
        }
        if format_ptr == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let mut bytes = match memory.read_bytes(format_ptr, 18) {
            Ok(bytes) => bytes,
            Err(_) => {
                state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
                self.last_error = 0;
                return Ok(());
            }
        };
        if bytes.len() >= 2 && u16::from_le_bytes([bytes[0], bytes[1]]) == WAVE_FORMAT_EXTENSIBLE {
            if let Ok(extended) = memory.read_bytes(format_ptr, 40) {
                bytes = extended;
            }
        }
        let format = match parse_wave_format(&bytes) {
            Ok(format) => format,
            Err(hr) => {
                state.set(Register::Rax, u64::from(hr));
                self.last_error = 0;
                return Ok(());
            }
        };
        let Some(device) = device_of(self.guest_pid, object) else {
            state.set(Register::Rax, u64::from(AUDCLNT_E_DEVICE_INVALIDATED));
            self.last_error = 0;
            return Ok(());
        };
        let hr = audio_format_support(&device, &format, share_mode);
        if closest_out != 0 {
            if hr == AUDCLNT_S_FALSE {
                // The engine would convert; the real closest match is the
                // device's own mix format.
                let mix = mix_format_for_device(&device);
                let mix_bytes = wave_format_bytes(&mix);
                let address = self.alloc_zeroed(memory, mix_bytes.len(), 16)?;
                memory.map_bytes(address, &mix_bytes);
                write_guest_pointer(memory, closest_out, address, self.guest_arch)?;
            } else {
                write_guest_pointer(memory, closest_out, 0, self.guest_arch)?;
            }
        }
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient::GetMixFormat(ppDeviceFormat)`.
    pub(crate) fn dispatch_audio_client_get_mix_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_S_OK, AUDCLNT_E_DEVICE_INVALIDATED, AUDCLNT_E_POINTER, device_of,
            mix_format_for_device, wave_format_bytes,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let Some(device) = device_of(self.guest_pid, object) else {
            state.set(Register::Rax, u64::from(AUDCLNT_E_DEVICE_INVALIDATED));
            self.last_error = 0;
            return Ok(());
        };
        let format = mix_format_for_device(&device);
        let bytes = wave_format_bytes(&format);
        let address = self.alloc_zeroed(memory, bytes.len(), 16)?;
        memory.map_bytes(address, &bytes);
        write_guest_pointer(memory, out, address, self.guest_arch)?;
        state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
        self.last_error = 0;
        self.push_trace(
            "audio",
            "IAudioClient::GetMixFormat",
            BTreeMap::from([
                ("channels".to_string(), json!(format.channels)),
                ("sample_rate".to_string(), json!(format.sample_rate)),
            ]),
            json!(ACTIVATION_S_OK),
        );
        Ok(())
    }

    /// `IAudioClient::GetDevicePeriod(phnsDefault, phnsMinimum)`.
    pub(crate) fn dispatch_audio_client_get_device_period(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{ACTIVATION_S_OK, AUDCLNT_E_POINTER, get_device_period};
        let object = guest_call_arg(state, memory, 0)?;
        let default_out = guest_call_arg(state, memory, 1)?;
        let minimum_out = guest_call_arg(state, memory, 2)?;
        if default_out == 0 && minimum_out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
        } else {
            match get_device_period(self.guest_pid, object) {
                Ok((default_hns, minimum_hns)) => {
                    if default_out != 0 {
                        write_u64(memory, default_out, default_hns);
                    }
                    if minimum_out != 0 {
                        write_u64(memory, minimum_out, minimum_hns);
                    }
                    state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
                }
                Err(hr) => state.set(Register::Rax, u64::from(hr)),
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient::Start()`.
    pub(crate) fn dispatch_audio_client_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let hr = crate::audio_activation::start(self.guest_pid, object);
        self.signal_audio_ready_event(object);
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        self.push_trace("audio", "IAudioClient::Start", BTreeMap::new(), json!(hr));
        Ok(())
    }

    /// `IAudioClient::Stop()`.
    pub(crate) fn dispatch_audio_client_stop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let hr = crate::audio_activation::stop(self.guest_pid, object);
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        self.push_trace("audio", "IAudioClient::Stop", BTreeMap::new(), json!(hr));
        Ok(())
    }

    /// `IAudioClient::Reset()`.
    pub(crate) fn dispatch_audio_client_reset(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let hr = crate::audio_activation::reset(self.guest_pid, object);
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        self.push_trace("audio", "IAudioClient::Reset", BTreeMap::new(), json!(hr));
        Ok(())
    }

    /// `IAudioClient::SetEventHandle(eventHandle)`.
    pub(crate) fn dispatch_audio_client_set_event_handle(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let handle = guest_call_arg(state, memory, 1)?;
        let hr = crate::audio_activation::set_event_handle(self.guest_pid, object, handle);
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        self.push_trace(
            "audio",
            "IAudioClient::SetEventHandle",
            BTreeMap::from([("handle".to_string(), json!(format!("{handle:#x}")))]),
            json!(hr),
        );
        Ok(())
    }

    /// `IAudioClient::GetService(riid, ppv)` — real service objects.
    pub(crate) fn dispatch_audio_client_get_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_E_NOINTERFACE, ACTIVATION_S_OK, AUDCLNT_E_POINTER, IID_IUNKNOWN,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 || riid_ptr == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let riid = match memory.read_bytes(riid_ptr, 16) {
            Ok(bytes) => <[u8; 16]>::try_from(bytes.as_slice()).unwrap_or([0_u8; 16]),
            Err(_) => {
                state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
                self.last_error = 0;
                return Ok(());
            }
        };
        let hr = if riid == IID_IUNKNOWN {
            self.add_ref_guest_object(object)?;
            write_guest_pointer(memory, out, object, self.guest_arch)?;
            ACTIVATION_S_OK
        } else if let Some(kind) = crate::audio_activation::audio_service_kind_for_riid(&riid) {
            let direction = crate::audio_activation::client_direction(self.guest_pid, object);
            let Some(direction) = direction else {
                write_guest_pointer(memory, out, 0, self.guest_arch)?;
                state.set(
                    Register::Rax,
                    u64::from(crate::audio_activation::AUDCLNT_E_DEVICE_INVALIDATED),
                );
                self.last_error = 0;
                return Ok(());
            };
            if !crate::audio_activation::service_supported_for_direction(direction, kind) {
                write_guest_pointer(memory, out, 0, self.guest_arch)?;
                state.set(
                    Register::Rax,
                    u64::from(crate::audio_activation::AUDCLNT_E_WRONG_ENDPOINT_TYPE),
                );
                self.last_error = 0;
                return Ok(());
            }
            let cached = crate::audio_activation::service_for(self.guest_pid, object, kind)
                .filter(|service| self.guest_objects.contains_key(service));
            let service = match cached {
                Some(service) => {
                    self.add_ref_guest_object(service)?;
                    service
                }
                None => {
                    let vtable = self.alloc_guest_vtable(
                        memory,
                        crate::audio_activation::audio_service_methods(kind),
                    )?;
                    let service =
                        self.alloc_guest_object(memory, GuestObjectKind::DirectSound8, vtable)?;
                    crate::audio_activation::bind_service(self.guest_pid, object, service, kind);
                    service
                }
            };
            write_guest_pointer(memory, out, service, self.guest_arch)?;
            ACTIVATION_S_OK
        } else {
            write_guest_pointer(memory, out, 0, self.guest_arch)?;
            ACTIVATION_E_NOINTERFACE
        };
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        let service_name = crate::audio_activation::audio_service_kind_for_riid(&riid)
            .map(crate::audio_activation::audio_service_name);
        self.push_trace(
            "audio",
            "IAudioClient::GetService",
            BTreeMap::from([
                (
                    "riid".to_string(),
                    json!(crate::audio_activation::activation_riid_name(&riid)),
                ),
                ("service".to_string(), json!(service_name)),
            ]),
            json!(hr),
        );
        Ok(())
    }

    /// `IAudioRenderClient::QueryInterface(riid, ppv)`.
    pub(crate) fn dispatch_audio_render_client_query_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_E_NOINTERFACE, ACTIVATION_S_OK, AUDCLNT_E_POINTER, IID_IAUDIO_RENDER_CLIENT,
            IID_IUNKNOWN,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let riid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if riid_ptr == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let riid = match memory.read_bytes(riid_ptr, 16) {
            Ok(bytes) => <[u8; 16]>::try_from(bytes.as_slice()).unwrap_or([0_u8; 16]),
            Err(_) => {
                state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
                self.last_error = 0;
                return Ok(());
            }
        };
        let hr = if riid == IID_IUNKNOWN || riid == IID_IAUDIO_RENDER_CLIENT {
            self.add_ref_guest_object(object)?;
            if out != 0 {
                write_guest_pointer(memory, out, object, self.guest_arch)?;
            }
            ACTIVATION_S_OK
        } else {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch)?;
            }
            ACTIVATION_E_NOINTERFACE
        };
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioRenderClient::GetBuffer(NumFramesRequested, ppData)`.
    pub(crate) fn dispatch_audio_render_client_get_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{ACTIVATION_S_OK, AUDCLNT_E_POINTER, render_get_buffer};
        let service = guest_call_arg(state, memory, 0)?;
        let frames_requested = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        match render_get_buffer(self.guest_pid, service, frames_requested) {
            Ok((address, _frames)) => {
                write_guest_pointer(memory, out, address, self.guest_arch)?;
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
            }
            Err(hr) => {
                write_guest_pointer(memory, out, 0, self.guest_arch)?;
                state.set(Register::Rax, u64::from(hr));
            }
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioRenderClient::ReleaseBuffer(NumFramesWritten, dwFlags)`.
    pub(crate) fn dispatch_audio_render_client_release_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_S_OK, push_real_render_samples, render_release_buffer,
        };
        let service = guest_call_arg(state, memory, 0)?;
        let frames_written = guest_call_arg_u32(state, memory, 1)?;
        let flags = guest_call_arg_u32(state, memory, 2)?;
        match render_release_buffer(self.guest_pid, service, frames_written, flags) {
            Ok(release) => {
                let channels = release.channels.max(1) as usize;
                let sample_count = release.frames as usize * channels;
                let samples = if release.silent {
                    vec![0.0f32; sample_count]
                } else {
                    let byte_len = release.frames as usize * release.block_align.max(1) as usize;
                    match memory.read_bytes(release.buffer_address, byte_len) {
                        Ok(bytes) => crate::real_audio::pcm_bytes_to_float(
                            &bytes,
                            release.wave_format_tag,
                            release.bits_per_sample,
                            release.channels,
                        ),
                        Err(_) => Vec::new(),
                    }
                };
                if !samples.is_empty() {
                    if let Some(device_id) = release.real_device_id {
                        push_real_render_samples(
                            device_id,
                            &samples,
                            release.channels,
                            release.sample_rate,
                        );
                    }
                    // The client-side render queue feeds loopback capture even
                    // when the host output stream could not be opened.
                    if let Some(device) =
                        crate::audio_activation::device_of(self.guest_pid, release.endpoint)
                    {
                        crate::audio_activation::push_loopback_render_samples(
                            self.guest_pid,
                            &device.key,
                            &samples,
                            release.channels,
                            release.sample_rate,
                        );
                    }
                }
                self.signal_audio_ready_event(release.endpoint);
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
            }
            Err(hr) => state.set(Register::Rax, u64::from(hr)),
        }
        self.last_error = 0;
        Ok(())
    }

    /// Dispatch the service interfaces returned by
    /// `IAudioClient::GetService` / activation — IAudioClock,
    /// ISimpleAudioVolume, IAudioStreamVolume, IAudioSessionControl(2) and
    /// IAudioCaptureClient.  All state is real and lives in
    /// `crate::audio_activation`; this layer only reads guest arguments,
    /// calls the state operation and writes real results back.
    pub(crate) fn dispatch_audio_service_method(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_E_NOINTERFACE, ACTIVATION_S_OK, AUDCLNT_E_INVALIDARG, AUDCLNT_E_POINTER,
            AUDCLNT_S_FALSE, AUDCLNT_S_OK, audio_service_supports_riid, capture_get_buffer,
            capture_next_packet_size, capture_release_buffer, clock_frequency, clock_position,
            clock_state, get_all_volumes, get_channel_volume, get_display_name, get_grouping_param,
            get_icon_path, get_master_volume, get_mute, is_system_sounds_session,
            register_session_notification, service_kind, session_identifier,
            session_instance_identifier, session_process_id, session_state, set_all_volumes,
            set_channel_volume, set_display_name, set_ducking_preference, set_grouping_param,
            set_icon_path, set_master_volume, set_mute, stream_volume_channel_count,
            unregister_session_notification,
        };
        let pid = self.guest_pid;
        let this = guest_call_arg(state, memory, 0)?;
        let hr: u32 = match thunk {
            HostThunk::AudioServiceQueryInterface => {
                let riid_ptr = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    let riid: Option<[u8; 16]> = memory
                        .read_bytes(riid_ptr, 16)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok());
                    match (riid, service_kind(pid, this)) {
                        (Some(riid), Some(kind)) if audio_service_supports_riid(kind, &riid) => {
                            let _ = write_guest_pointer(memory, out, this, self.guest_arch);
                            AUDCLNT_S_OK
                        }
                        _ => {
                            let _ = write_guest_pointer(memory, out, 0, self.guest_arch);
                            ACTIVATION_E_NOINTERFACE
                        }
                    }
                }
            }
            HostThunk::AudioClockGetFrequency => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match clock_frequency(pid, this) {
                        Ok(frequency) => {
                            write_u64(memory, out, frequency as u64);
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioClockGetPosition => {
                let position_out = guest_call_arg(state, memory, 1)?;
                let qpc_out = guest_call_arg(state, memory, 2)?;
                if position_out == 0 || qpc_out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match clock_position(pid, this) {
                        Ok((position, qpc)) => {
                            write_u64(memory, position_out, position);
                            write_u64(memory, qpc_out, qpc);
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioClockGetState => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match clock_state(pid, this) {
                        Ok(value) => {
                            write_u32(memory, out, value);
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSimpleVolumeSetMasterVolume => {
                let level = f32::from_bits(guest_call_arg_u32(state, memory, 1)?);
                let event_context = guest_call_arg(state, memory, 2)?;
                set_master_volume(pid, this, level, event_context)
            }
            HostThunk::AudioSimpleVolumeGetMasterVolume => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match get_master_volume(pid, this) {
                        Ok(level) => {
                            write_u32(memory, out, level.to_bits());
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSimpleVolumeSetMute => {
                let muted = guest_call_arg_u32(state, memory, 1)? != 0;
                let event_context = guest_call_arg(state, memory, 2)?;
                set_mute(pid, this, muted, event_context)
            }
            HostThunk::AudioSimpleVolumeGetMute => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match get_mute(pid, this) {
                        Ok(muted) => {
                            write_u32(memory, out, u32::from(muted));
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioStreamVolumeGetChannelCount => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match stream_volume_channel_count(pid, this) {
                        Ok(count) => {
                            write_u32(memory, out, count);
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioStreamVolumeSetChannelVolume => {
                let index = guest_call_arg_u32(state, memory, 1)?;
                let level = f32::from_bits(guest_call_arg_u32(state, memory, 2)?);
                let event_context = guest_call_arg(state, memory, 3)?;
                set_channel_volume(pid, this, index, level, event_context)
            }
            HostThunk::AudioStreamVolumeGetChannelVolume => {
                let index = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match get_channel_volume(pid, this, index) {
                        Ok(level) => {
                            write_u32(memory, out, level.to_bits());
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioStreamVolumeSetAllVolumes => {
                let count = guest_call_arg_u32(state, memory, 1)?;
                let volumes_ptr = guest_call_arg(state, memory, 2)?;
                let event_context = guest_call_arg(state, memory, 3)?;
                if volumes_ptr == 0 || count == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    let mut volumes = Vec::with_capacity(count as usize);
                    let mut ok = true;
                    for index in 0..count as u64 {
                        match read_u32(memory, volumes_ptr + index * 4) {
                            Ok(bits) => volumes.push(f32::from_bits(bits)),
                            Err(_) => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok {
                        set_all_volumes(pid, this, volumes, event_context)
                    } else {
                        AUDCLNT_E_POINTER
                    }
                }
            }
            HostThunk::AudioStreamVolumeGetAllVolumes => {
                let count = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match get_all_volumes(pid, this) {
                        Ok(volumes) => {
                            if count < volumes.len() as u32 {
                                AUDCLNT_E_INVALIDARG
                            } else {
                                for (index, level) in volumes.iter().enumerate() {
                                    write_u32(memory, out + index as u64 * 4, level.to_bits());
                                }
                                ACTIVATION_S_OK
                            }
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControlGetState => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match session_state(pid, this) {
                        Ok(value) => {
                            write_u32(memory, out, value);
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControlSetDisplayName => {
                let name_ptr = guest_call_arg(state, memory, 1)?;
                let event_context = guest_call_arg(state, memory, 2)?;
                let name = if name_ptr == 0 {
                    None
                } else {
                    Some(read_utf16z(memory, name_ptr, 1024)?)
                };
                set_display_name(pid, this, name, event_context)
            }
            HostThunk::AudioSessionControlGetDisplayName => {
                let out = guest_call_arg(state, memory, 1)?;
                let capacity = guest_call_arg_u32(state, memory, 2)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match get_display_name(pid, this) {
                        Ok(name) => {
                            if write_utf16_buffer(memory, out, capacity as usize, &name) {
                                ACTIVATION_S_OK
                            } else {
                                AUDCLNT_E_INVALIDARG
                            }
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControlSetIconPath => {
                let path_ptr = guest_call_arg(state, memory, 1)?;
                let event_context = guest_call_arg(state, memory, 2)?;
                let path = if path_ptr == 0 {
                    None
                } else {
                    Some(read_utf16z(memory, path_ptr, 1024)?)
                };
                set_icon_path(pid, this, path, event_context)
            }
            HostThunk::AudioSessionControlGetIconPath => {
                let out = guest_call_arg(state, memory, 1)?;
                let capacity = guest_call_arg_u32(state, memory, 2)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match get_icon_path(pid, this) {
                        Ok(path) => {
                            let path = path.unwrap_or_default();
                            if write_utf16_buffer(memory, out, capacity as usize, &path) {
                                ACTIVATION_S_OK
                            } else {
                                AUDCLNT_E_INVALIDARG
                            }
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControlSetGroupingParam => {
                let override_ptr = guest_call_arg(state, memory, 1)?;
                let event_context = guest_call_arg(state, memory, 2)?;
                let param = if override_ptr == 0 {
                    None
                } else {
                    memory
                        .read_bytes(override_ptr, 16)
                        .ok()
                        .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
                };
                set_grouping_param(pid, this, param, event_context)
            }
            HostThunk::AudioSessionControlGetGroupingParam => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match get_grouping_param(pid, this) {
                        Ok(param) => {
                            for (index, byte) in param.iter().enumerate() {
                                write_u8(memory, out + index as u64, *byte);
                            }
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControlRegisterNotification => {
                let object = guest_call_arg(state, memory, 1)?;
                register_session_notification(pid, this, object)
            }
            HostThunk::AudioSessionControlUnregisterNotification => {
                let object = guest_call_arg(state, memory, 1)?;
                unregister_session_notification(pid, this, object)
            }
            HostThunk::AudioSessionControl2GetProcessId => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match session_process_id(pid, this) {
                        Ok(process_id) => {
                            write_u32(memory, out, process_id);
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControl2GetSessionIdentifier => {
                let out = guest_call_arg(state, memory, 1)?;
                let capacity = guest_call_arg_u32(state, memory, 2)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match session_identifier(pid, this) {
                        Ok(identifier) => {
                            if write_utf16_buffer(memory, out, capacity as usize, &identifier) {
                                ACTIVATION_S_OK
                            } else {
                                AUDCLNT_E_INVALIDARG
                            }
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControl2GetSessionInstanceIdentifier => {
                let out = guest_call_arg(state, memory, 1)?;
                let capacity = guest_call_arg_u32(state, memory, 2)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match session_instance_identifier(pid, this) {
                        Ok(identifier) => {
                            if write_utf16_buffer(memory, out, capacity as usize, &identifier) {
                                ACTIVATION_S_OK
                            } else {
                                AUDCLNT_E_INVALIDARG
                            }
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioSessionControl2IsSystemSoundsSession => {
                match is_system_sounds_session(pid, this) {
                    Ok(true) => AUDCLNT_S_OK,
                    Ok(false) => AUDCLNT_S_FALSE,
                    Err(hr) => hr,
                }
            }
            HostThunk::AudioSessionControl2SetDuckingPreference => {
                let opt_out = guest_call_arg_u32(state, memory, 1)? != 0;
                set_ducking_preference(pid, this, opt_out)
            }
            HostThunk::AudioCaptureClientGetBuffer => {
                let data_out = guest_call_arg(state, memory, 1)?;
                let frames_out = guest_call_arg(state, memory, 2)?;
                let flags_out = guest_call_arg(state, memory, 3)?;
                let device_position_out = guest_call_arg(state, memory, 4)?;
                let qpc_out = guest_call_arg(state, memory, 5)?;
                if data_out == 0 || frames_out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match capture_get_buffer(pid, this) {
                        Ok(packet) => {
                            let buffer = packet.buffer_address;
                            memory.map_bytes(buffer, &packet.sample_bytes());
                            let _ = write_guest_pointer(memory, data_out, buffer, self.guest_arch);
                            write_u32(memory, frames_out, packet.frames);
                            if flags_out != 0 {
                                write_u32(memory, flags_out, packet.flags);
                            }
                            if device_position_out != 0 {
                                write_u64(memory, device_position_out, packet.device_position);
                            }
                            if qpc_out != 0 {
                                write_u64(memory, qpc_out, packet.qpc_position);
                            }
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            HostThunk::AudioCaptureClientReleaseBuffer => {
                let frames = guest_call_arg_u32(state, memory, 1)?;
                let flags = guest_call_arg_u32(state, memory, 2).unwrap_or(0);
                match capture_release_buffer(pid, this, frames, flags) {
                    Ok(_) => ACTIVATION_S_OK,
                    Err(hr) => hr,
                }
            }
            HostThunk::AudioCaptureClientGetNextPacketSize => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    AUDCLNT_E_POINTER
                } else {
                    match capture_next_packet_size(pid, this) {
                        Ok(frames) => {
                            write_u32(memory, out, frames);
                            ACTIVATION_S_OK
                        }
                        Err(hr) => hr,
                    }
                }
            }
            _ => AUDCLNT_E_INVALIDARG,
        };
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient2::IsOffloadCapable(category, pbOffloadCapable)`.
    pub(crate) fn dispatch_audio_client_is_offload_capable(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_S_OK, AUDCLNT_E_DEVICE_INVALIDATED, AUDCLNT_E_POINTER,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let _category = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
        } else if !crate::audio_activation::has_audio_client(self.guest_pid, object) {
            state.set(Register::Rax, u64::from(AUDCLNT_E_DEVICE_INVALIDATED));
        } else {
            // Honest host answer: TRUE only when a real offload engine is
            // exposed by the backed host (never on the current hosts).
            write_u32(
                memory,
                out,
                u32::from(crate::audio_activation::host_offload_capability()),
            );
            state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient2::SetClientProperties(pProperties)`.
    pub(crate) fn dispatch_audio_client_set_client_properties(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            AUDCLNT_E_INVALIDARG, AUDCLNT_E_POINTER, set_client_properties,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let properties = guest_call_arg(state, memory, 1)?;
        if properties == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let bytes = match memory.read_bytes(properties, 12) {
            Ok(bytes) => bytes,
            Err(_) => {
                state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
                self.last_error = 0;
                return Ok(());
            }
        };
        let cb_size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if cb_size < 12 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_INVALIDARG));
            self.last_error = 0;
            return Ok(());
        }
        let offload_requested = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != 0;
        let category = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        // `AUDCLNT_STREAMOPTIONS Options` follows the 12-byte prefix when the
        // guest supplies the Windows 8.1+ `AudioClientProperties` size
        // (16 bytes: cbSize, bIsOffload, eCategory, Options).
        let options = if cb_size >= 16 {
            match memory.read_bytes(properties + 12, 4) {
                Ok(options) => u32::from_le_bytes([options[0], options[1], options[2], options[3]]),
                Err(_) => {
                    state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
                    self.last_error = 0;
                    return Ok(());
                }
            }
        } else {
            0
        };
        let raw_requested = options & crate::audio_activation::AUDCLNT_STREAMOPTIONS_RAW != 0;
        let hr = set_client_properties(
            self.guest_pid,
            object,
            category,
            offload_requested,
            raw_requested,
        );
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient2::GetBufferSizeLimits(pFormat, bEventDriven, pMin, pMax)`.
    pub(crate) fn dispatch_audio_client_get_buffer_size_limits(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{ACTIVATION_S_OK, AUDCLNT_E_POINTER, get_buffer_size_limits};
        let object = guest_call_arg(state, memory, 0)?;
        let format_ptr = guest_call_arg(state, memory, 1)?;
        let _event_driven = guest_call_arg_u32(state, memory, 2)?;
        let minimum_out = guest_call_arg(state, memory, 3)?;
        let maximum_out = guest_call_arg(state, memory, 4)?;
        if minimum_out == 0 && maximum_out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let format = match self.read_guest_wave_format(memory, format_ptr) {
            Ok(format) => format,
            Err(hr) => {
                state.set(Register::Rax, u64::from(hr));
                self.last_error = 0;
                return Ok(());
            }
        };
        match get_buffer_size_limits(self.guest_pid, object, &format) {
            Ok((minimum_hns, maximum_hns)) => {
                if minimum_out != 0 {
                    write_u64(memory, minimum_out, minimum_hns);
                }
                if maximum_out != 0 {
                    write_u64(memory, maximum_out, maximum_hns);
                }
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
            }
            Err(hr) => state.set(Register::Rax, u64::from(hr)),
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient3::GetSharedModeEnginePeriod(pFormat, pDefault,
    /// pFundamental, pMin, pMax)`.
    pub(crate) fn dispatch_audio_client_get_shared_mode_engine_period(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_S_OK, AUDCLNT_E_POINTER, get_shared_mode_engine_period,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let format_ptr = guest_call_arg(state, memory, 1)?;
        let default_out = guest_call_arg(state, memory, 2)?;
        let fundamental_out = guest_call_arg(state, memory, 3)?;
        let minimum_out = guest_call_arg(state, memory, 4)?;
        let maximum_out = guest_call_arg(state, memory, 5)?;
        if default_out == 0 && fundamental_out == 0 && minimum_out == 0 && maximum_out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let format = match self.read_guest_wave_format(memory, format_ptr) {
            Ok(format) => format,
            Err(hr) => {
                state.set(Register::Rax, u64::from(hr));
                self.last_error = 0;
                return Ok(());
            }
        };
        match get_shared_mode_engine_period(self.guest_pid, object, &format) {
            Ok((default_frames, fundamental_frames, minimum_frames, maximum_frames)) => {
                if default_out != 0 {
                    write_u32(memory, default_out, default_frames);
                }
                if fundamental_out != 0 {
                    write_u32(memory, fundamental_out, fundamental_frames);
                }
                if minimum_out != 0 {
                    write_u32(memory, minimum_out, minimum_frames);
                }
                if maximum_out != 0 {
                    write_u32(memory, maximum_out, maximum_frames);
                }
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
            }
            Err(hr) => state.set(Register::Rax, u64::from(hr)),
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient3::GetCurrentSharedModeEnginePeriod(ppFormat,
    /// pCurrentPeriod)`.
    pub(crate) fn dispatch_audio_client_get_current_shared_mode_engine_period(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_S_OK, AUDCLNT_E_POINTER, current_shared_mode_engine_period,
            wave_format_bytes,
        };
        let object = guest_call_arg(state, memory, 0)?;
        let format_out = guest_call_arg(state, memory, 1)?;
        let period_out = guest_call_arg(state, memory, 2)?;
        if format_out == 0 || period_out == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        match current_shared_mode_engine_period(self.guest_pid, object) {
            Ok((mix, current_frames)) => {
                let bytes = wave_format_bytes(&mix);
                let address = self.alloc_zeroed(memory, bytes.len(), 16)?;
                memory.map_bytes(address, &bytes);
                write_guest_pointer(memory, format_out, address, self.guest_arch)?;
                write_u32(memory, period_out, current_frames);
                state.set(Register::Rax, u64::from(ACTIVATION_S_OK));
            }
            Err(hr) => state.set(Register::Rax, u64::from(hr)),
        }
        self.last_error = 0;
        Ok(())
    }

    /// `IAudioClient3::InitializeSharedAudioStream(flags, period_frames,
    /// format, session_guid)`.
    pub(crate) fn dispatch_audio_client_initialize_shared_audio_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{AUDCLNT_E_POINTER, plan_initialize_shared_audio_stream};
        let object = guest_call_arg(state, memory, 0)?;
        let stream_flags = guest_call_arg_u32(state, memory, 1)?;
        let period_frames = guest_call_arg_u32(state, memory, 2)?;
        let format_ptr = guest_call_arg(state, memory, 3)?;
        let _session_guid = guest_call_arg(state, memory, 4)?;
        if format_ptr == 0 {
            state.set(Register::Rax, u64::from(AUDCLNT_E_POINTER));
            self.last_error = 0;
            return Ok(());
        }
        let format = match self.read_guest_wave_format(memory, format_ptr) {
            Ok(format) => format,
            Err(hr) => {
                state.set(Register::Rax, u64::from(hr));
                self.last_error = 0;
                return Ok(());
            }
        };
        let plan = match plan_initialize_shared_audio_stream(
            self.guest_pid,
            object,
            stream_flags,
            period_frames,
            &format,
        ) {
            Ok(plan) => plan,
            Err(hr) => {
                state.set(Register::Rax, u64::from(hr));
                self.last_error = 0;
                return Ok(());
            }
        };
        let hr = self.commit_audio_client_initialize(memory, object, &plan, &format)?;
        state.set(Register::Rax, u64::from(hr));
        self.last_error = 0;
        self.push_trace(
            "audio",
            "IAudioClient3::InitializeSharedAudioStream",
            BTreeMap::from([
                ("stream_flags".to_string(), json!(stream_flags)),
                ("period_frames".to_string(), json!(period_frames)),
                ("buffer_frames".to_string(), json!(plan.buffer_frames)),
            ]),
            json!(hr),
        );
        Ok(())
    }

    /// Raise the endpoint's ready event through the runtime's real guest
    /// event machinery (a no-op when the buffer is full or no event handle is
    /// bound; invalid handles are reported, never silently treated as
    /// success).
    pub(crate) fn signal_audio_ready_event(&mut self, endpoint: u64) {
        let Some(handle) = crate::audio_activation::take_ready_event(self.guest_pid, endpoint)
        else {
            return;
        };
        let handle = handle as u32;
        if let Err(error) = self.win32.set_event(handle) {
            eprintln!(
                "[RealAudio] audio-client ready event {handle:#x} cannot be signaled: {error}"
            );
        }
    }

    /// Servicing-point tick: every running event-driven audio client whose
    /// buffer has free space raises its ready event through the real guest
    /// event machinery, so a guest blocked in a wait wakes when the real
    /// playback clock frees a buffer.
    pub(crate) fn tick_audio_client_events(&mut self) {
        for handle in crate::audio_activation::take_ready_events(self.guest_pid) {
            if let Err(error) = self.win32.set_event(handle as u32) {
                eprintln!(
                    "[RealAudio] audio-client ready event {handle:#x} cannot be signaled: {error}"
                );
            }
        }
    }

    /// Attach the real IAudioClient method surface to the endpoint object an
    /// `ActivateAudioInterfaceAsync` dispatch produced: replace the activation
    /// wrapper vtable with the full method vtable and bind the per-endpoint
    /// real client state (bound device, riid, real period/latency values).
    pub(crate) fn attach_activated_audio_client_surface(
        &mut self,
        state: &CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use crate::audio_activation::{
            ACTIVATION_S_OK, AudioDirection, audio_activation_operation_methods,
            audio_client_methods, device_is_capture, endpoint_record, has_audio_client,
            register_activation_operation, register_audio_client_direction,
        };
        if state.get(Register::Rax) != u64::from(ACTIVATION_S_OK) {
            return Ok(());
        }
        let operation_out = guest_call_arg(state, memory, 4)?;
        if operation_out == 0 {
            return Ok(());
        }
        // The activation dispatch wrote the activated endpoint (0 on a failed
        // activation) here.  Turn the out-parameter into the real Windows
        // operation object; failed activations still get an operation whose
        // GetActivateResult reports the failure HRESULT.
        let interface_object = read_guest_pointer(memory, operation_out, self.guest_arch)?;
        let operation_vtable =
            self.alloc_guest_vtable(memory, audio_activation_operation_methods())?;
        let operation =
            self.alloc_guest_object(memory, GuestObjectKind::DirectSound8, operation_vtable)?;
        register_activation_operation(self.guest_pid, operation, interface_object);
        // One reference for the guest (the out-parameter) and one held by the
        // pending completion, so a guest that releases the operation before
        // the asynchronous completion still receives a valid operation.
        self.add_ref_guest_object(operation)?;
        write_guest_pointer(memory, operation_out, operation, self.guest_arch)?;
        if interface_object == 0 {
            return Ok(());
        }
        if has_audio_client(self.guest_pid, interface_object) {
            return Ok(());
        }
        let Some(record) = endpoint_record(self.guest_pid, interface_object) else {
            return Ok(());
        };
        let vtable = self.alloc_guest_vtable(memory, audio_client_methods())?;
        write_guest_pointer(memory, interface_object, vtable, self.guest_arch)?;
        let direction = if device_is_capture(&record.device) {
            AudioDirection::Capture
        } else {
            AudioDirection::Render
        };
        register_audio_client_direction(
            self.guest_pid,
            interface_object,
            record.device,
            record.requested_riid,
            direction,
        );
        Ok(())
    }

    /// Allocate a guest audio endpoint object carrying the full real
    /// IAudioClient method vtable and bind its real client state.  Used by the
    /// audio-client tests to build endpoints deterministically (the
    /// activation path attaches the same surface to the object the
    /// final-scraps activation produced).
    #[cfg(test)]
    pub(crate) fn alloc_audio_client_endpoint(
        &mut self,
        memory: &mut MemoryImage,
        device: &crate::real_audio::RealAudioDevice,
        requested_riid: [u8; 16],
    ) -> AppResult<u64> {
        let vtable =
            self.alloc_guest_vtable(memory, crate::audio_activation::audio_client_methods())?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::DirectSound8, vtable)?;
        crate::audio_activation::register_audio_client(
            self.guest_pid,
            object,
            device.clone(),
            requested_riid,
        );
        Ok(object)
    }
}
