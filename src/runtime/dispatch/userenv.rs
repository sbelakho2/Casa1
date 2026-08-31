//! User-environment dispatch: the userenv.dll exports, in a dedicated
//! module per the audit's modularity requirement.  `GetProfilesDirectoryW`
//! reports the runtime's profile directory; `GetProfileType` reports the
//! mandatory/local bits; `CreateEnvironmentBlock` builds the double-null
//! environment block from the runtime environment and `DestroyEnvironmentBlock`
//! releases it.  No user profiles are loaded, so the profile functions
//! answer the documented no-profile errors.
//!
//! Layer contract: the environment/profile functions return BOOL in EAX;
//! `GetProfilesDirectoryW` returns the directory length.

use super::super::*;

/// TRUE / FALSE.
const FALSE: u32 = 0;
/// ERROR_NOT_FOUND.
const ERROR_NOT_FOUND: u32 = 1168;
/// ERROR_INVALID_PARAMETER.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// The profile-type bits: PT_MANDATORY | PT_TEMPORARY.
const PROFILE_TYPE_MANDATORY: u32 = 0x0000_0001;

impl PeHostRuntime {
    /// Route every userenv thunk to its dispatch function.
    pub(crate) fn dispatch_userenv(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::GetProfilesDirectoryW => {
                let buffer = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg(state, memory, 1)?;
                let path = std::env::temp_dir().to_string_lossy().to_string();
                let units = path.encode_utf16().count() as u64;
                if buffer != 0 {
                    if size < units + 1 {
                        write_guest_u32(memory, size, (units + 1) as u32).ok();
                        state.set(Register::Rax, 0);
                        return Ok(());
                    }
                    let _ = size;
                    for (i, unit) in path.encode_utf16().enumerate() {
                        write_guest_u16(memory, buffer + (i as u64 * 2), unit).ok();
                    }
                    write_guest_u16(memory, buffer + (units * 2), 0).ok();
                }
                state.set(Register::Rax, units);
                Ok(())
            }
            HostThunk::GetProfileType => {
                let out = guest_call_arg(state, memory, 0)?;
                if out != 0 {
                    write_guest_u32(memory, out, PROFILE_TYPE_MANDATORY).ok();
                }
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::CreateEnvironmentBlock => {
                let out = guest_call_arg(state, memory, 0)?;
                let _token = guest_call_arg(state, memory, 1)?;
                let _inherit = guest_call_arg_u32(state, memory, 2)?;
                if out == 0 {
                    state.set(Register::Rax, u64::from(FALSE));
                    self.last_error = ERROR_INVALID_PARAMETER;
                    return Ok(());
                }
                // The double-null environment block.
                let mut block: Vec<u16> = Vec::new();
                let mut entries: Vec<String> = std::env::vars()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect();
                entries.sort();
                for entry in entries {
                    block.extend(entry.encode_utf16());
                    block.push(0);
                }
                block.push(0);
                let address = self.alloc_zeroed(memory, block.len() * 2 + 2, 8)?;
                for (i, unit) in block.iter().enumerate() {
                    write_guest_u16(memory, address + (i as u64 * 2), *unit).ok();
                }
                write_guest_u16(memory, address + (block.len() as u64 * 2), 0).ok();
                self.userenv_blocks.insert(address, block.len() as u32);
                write_guest_pointer(memory, out, address, self.guest_arch).ok();
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::DestroyEnvironmentBlock => {
                let block = guest_call_arg(state, memory, 0)?;
                self.userenv_blocks.remove(&block);
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::LoadUserProfileW
            | HostThunk::UnloadUserProfile
            | HostThunk::CreateAppContainerProfile
            | HostThunk::DeleteAppContainerProfile => {
                // No user profiles exist in the runtime.
                state.set(Register::Rax, u64::from(FALSE));
                self.last_error = ERROR_NOT_FOUND;
                Ok(())
            }
            HostThunk::GetAppContainerProfilePath => {
                // No app-container profiles exist.
                let _name = guest_call_arg(state, memory, 0)?;
                let path = guest_call_arg(state, memory, 1)?;
                let size = guest_call_arg(state, memory, 2)?;
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                let _ = path;
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted userenv thunk {thunk:?}"),
            )),
        }
    }
}
