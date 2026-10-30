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
use crate::vm::VmProtection;

/// TRUE / FALSE.
const FALSE: u32 = 0;
/// ERROR_NOT_FOUND.
const ERROR_NOT_FOUND: u32 = 1168;
/// ERROR_INVALID_PARAMETER.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_INSUFFICIENT_BUFFER.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// The profile-type bits: PT_MANDATORY | PT_TEMPORARY.
const PROFILE_TYPE_MANDATORY: u32 = 0x0000_0001;
/// The guest's profiles root (all guest users live under the GE drive).
const PROFILE_ROOT: &str = "C:\\Users";

/// Copy `path` into a caller buffer using the Win32 `*lpcchSize` contract:
/// the required TCHAR count (including the terminating NUL) is always
/// written back, a too-small buffer yields ERROR_INSUFFICIENT_BUFFER and is
/// never overrun.  Returns `(BOOL, last_error)`.
fn write_profile_path(
    memory: &mut MemoryImage,
    buffer: u64,
    size_ptr: u64,
    path: &str,
) -> (u64, u32) {
    if size_ptr == 0 {
        return (u64::from(FALSE), ERROR_INVALID_PARAMETER);
    }
    let required = path.encode_utf16().count() as u32 + 1;
    let capacity = read_guest_u32(memory, size_ptr).unwrap_or(0);
    if capacity < required {
        let _ = write_guest_u32(memory, size_ptr, required);
        return (u64::from(FALSE), ERROR_INSUFFICIENT_BUFFER);
    }
    if buffer == 0 {
        return (u64::from(FALSE), ERROR_INVALID_PARAMETER);
    }
    for (index, unit) in path.encode_utf16().enumerate() {
        let _ = write_guest_u16(memory, buffer + (index as u64 * 2), unit);
    }
    let _ = write_guest_u16(memory, buffer + (u64::from(required - 1) * 2), 0);
    let _ = write_guest_u32(memory, size_ptr, required);
    (1, 0)
}

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
                let size_ptr = guest_call_arg(state, memory, 1)?;
                let (result, last_error) =
                    write_profile_path(memory, buffer, size_ptr, PROFILE_ROOT);
                state.set(Register::Rax, result);
                self.last_error = last_error;
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
                // The guest process environment (never the host's): the
                // block is what CreateProcess/GetEnvironmentVariableW see.
                let mut block: Vec<u16> = Vec::new();
                for (key, value) in &self.process_environment {
                    block.extend(format!("{key}={value}").encode_utf16());
                    block.push(0);
                }
                block.push(0);
                // A dedicated private reservation makes DestroyEnvironmentBlock
                // an exact release instead of leaking a data-area bump block.
                let allocation =
                    self.alloc_private_pages(memory, 0, block.len() * 2, VmProtection::READ_WRITE);
                let address = allocation?;
                for (i, unit) in block.iter().enumerate() {
                    write_guest_u16(memory, address + (i as u64 * 2), *unit).ok();
                }
                self.userenv_blocks.insert(address, block.len() as u32);
                write_guest_pointer(memory, out, address, self.guest_arch).ok();
                state.set(Register::Rax, 1);
                self.last_error = 0;
                Ok(())
            }
            HostThunk::DestroyEnvironmentBlock => {
                let block = guest_call_arg(state, memory, 0)?;
                let Some(units) = self.userenv_blocks.remove(&block) else {
                    state.set(Register::Rax, u64::from(FALSE));
                    self.last_error = ERROR_INVALID_PARAMETER;
                    return Ok(());
                };
                let bytes = (units as usize).saturating_mul(2);
                let size = self
                    .win32
                    .address_space()
                    .region_size(block)
                    .map(|size| size as usize)
                    .unwrap_or(bytes);
                memory.unmap_range(block, size);
                let released = self.win32.address_space_mut().release(block);
                state.set(Register::Rax, u64::from(released));
                self.last_error = if released { 0 } else { ERROR_INVALID_PARAMETER };
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
                // No app-container profiles are materialized, but the path
                // buffer follows the same size contract as the profiles root.
                let _name = guest_call_arg(state, memory, 0)?;
                let path = guest_call_arg(state, memory, 1)?;
                let size_ptr = guest_call_arg(state, memory, 2)?;
                let (result, last_error) = write_profile_path(memory, path, size_ptr, PROFILE_ROOT);
                state.set(Register::Rax, result);
                self.last_error = last_error;
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted userenv thunk {thunk:?}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::*;
    use super::super::test_support::{dispatch_x86, with_big_stack, x86_fixture};
    use super::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER};

    const BUFFER: u64 = 0x70_000;
    const SIZE: u64 = 0x70_100;
    const OUT: u64 = 0x70_200;

    #[test]
    fn profiles_directory_small_buffer_is_rejected_without_overrun() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("userenv-profiles-small");
            fixture.memory.map_bytes(BUFFER, &[0xAA; 64]);
            fixture.memory.map_bytes(SIZE, &4_u32.to_le_bytes());
            let result = dispatch_x86(
                &mut fixture,
                HostThunk::GetProfilesDirectoryW,
                &[BUFFER as u32, SIZE as u32],
            );
            assert_eq!(result, 0);
            assert_eq!(fixture.runtime.last_error, ERROR_INSUFFICIENT_BUFFER);
            assert_eq!(read_u32(&fixture.memory, SIZE).expect("required size"), 9);
            assert_eq!(
                read_u16(&fixture.memory, BUFFER).expect("sentinel"),
                0xAAAA,
                "a too-small buffer must not be written"
            );
        });
    }

    #[test]
    fn app_container_profile_path_uses_the_same_rejecting_size_contract() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("userenv-acp-small");
            fixture.memory.map_bytes(BUFFER, &[0xAA; 64]);
            fixture.memory.map_bytes(SIZE, &4_u32.to_le_bytes());
            let result = dispatch_x86(
                &mut fixture,
                HostThunk::GetAppContainerProfilePath,
                &[0, BUFFER as u32, SIZE as u32],
            );
            assert_eq!(result, 0);
            assert_eq!(fixture.runtime.last_error, ERROR_INSUFFICIENT_BUFFER);
            assert_eq!(read_u32(&fixture.memory, SIZE).expect("required size"), 9);
            assert_eq!(
                read_u16(&fixture.memory, BUFFER).expect("sentinel"),
                0xAAAA,
                "a too-small buffer must not be written"
            );

            fixture.memory.map_bytes(SIZE, &9_u32.to_le_bytes());
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetAppContainerProfilePath,
                    &[0, BUFFER as u32, SIZE as u32],
                ),
                1
            );
            assert_eq!(fixture.runtime.last_error, 0);
            assert_eq!(
                read_utf16_string(&fixture.memory, BUFFER).expect("path"),
                "C:\\Users"
            );
        });
    }

    #[test]
    fn create_environment_block_rejects_host_environment_and_destroy_frees_it() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("userenv-guest-env");
            fixture.runtime.process_environment =
                std::collections::BTreeMap::from([("GUEST_ONLY".to_string(), "1".to_string())]);
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CreateEnvironmentBlock,
                    &[OUT as u32, 0, 0],
                ),
                1
            );
            let block = read_guest_pointer(&fixture.memory, OUT, GuestArch::X86)
                .expect("environment block pointer");
            assert_ne!(block, 0);
            assert_eq!(
                read_utf16_string(&fixture.memory, block).expect("first entry"),
                "GUEST_ONLY=1",
                "the block must be the guest environment, never std::env"
            );
            assert_eq!(
                fixture
                    .runtime
                    .win32
                    .address_space()
                    .region_size(block)
                    .is_some(),
                true
            );

            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::DestroyEnvironmentBlock,
                    &[block as u32],
                ),
                1
            );
            assert_eq!(
                fixture.runtime.win32.address_space().region_size(block),
                None,
                "DestroyEnvironmentBlock must release the guest allocation"
            );
            assert_eq!(fixture.runtime.userenv_blocks.contains_key(&block), false);
            assert_eq!(read_u16(&fixture.memory, block).is_err(), true);
        });
    }

    #[test]
    fn profiles_directory_without_a_size_pointer_is_invalid_parameter() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("userenv-null-size");
            fixture.memory.map_bytes(BUFFER, &[0xAA; 64]);
            let result = dispatch_x86(
                &mut fixture,
                HostThunk::GetProfilesDirectoryW,
                &[BUFFER as u32, 0],
            );
            assert_eq!(result, 0, "a null size pointer must fail");
            assert_eq!(fixture.runtime.last_error, ERROR_INVALID_PARAMETER);
            assert_eq!(
                read_u16(&fixture.memory, BUFFER).expect("sentinel"),
                0xAAAA,
                "nothing may be written without a size pointer"
            );
        });
    }

    #[test]
    fn profiles_directory_with_a_null_buffer_pointer_is_invalid_parameter() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("userenv-null-buffer");
            fixture.memory.map_bytes(SIZE, &9_u32.to_le_bytes());
            let result = dispatch_x86(
                &mut fixture,
                HostThunk::GetProfilesDirectoryW,
                &[0, SIZE as u32],
            );
            assert_eq!(result, 0, "a null buffer pointer must fail");
            assert_eq!(fixture.runtime.last_error, ERROR_INVALID_PARAMETER);
            assert_eq!(
                read_u32(&fixture.memory, SIZE).expect("capacity"),
                9,
                "a null buffer must not rewrite the caller's capacity"
            );
        });
    }

    #[test]
    fn destroy_environment_block_of_an_unknown_address_is_invalid_parameter() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("userenv-destroy-unknown");
            let result = dispatch_x86(
                &mut fixture,
                HostThunk::DestroyEnvironmentBlock,
                &[0xdead_0000u32],
            );
            assert_eq!(result, 0, "an unknown block pointer must fail");
            assert_eq!(fixture.runtime.last_error, ERROR_INVALID_PARAMETER);
            assert_eq!(
                fixture.runtime.userenv_blocks.contains_key(&0xdead_0000u64),
                false
            );
        });
    }
}
