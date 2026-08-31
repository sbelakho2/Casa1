//! ACM dispatch: the msacm32.dll / msacm32.drv exports, in a dedicated
//! module per the audit's modularity requirement.  No ACM drivers are
//! registered in the runtime, so the surface answers the documented
//! no-driver semantics: `acmDriverEnum` enumerates zero drivers,
//! `acmMetrics` reports the honest zero driver count, the driver/stream
//! open calls fail with MMSYSERR_NODRIVER, and the format suggestion fails
//! with ACMERR_NOTPOSSIBLE.
//!
//! Layer contract: every export returns its MMSYSERR/ACMERR code in EAX.

use super::super::*;

/// MMSYSERR_NOERROR.
const MMSYSERR_NOERROR: u32 = 0;
/// MMSYSERR_NODRIVER — no ACM driver is registered.
const MMSYSERR_NODRIVER: u32 = 2;
/// MMSYSERR_INVALHANDLE.
const MMSYSERR_INVALHANDLE: u32 = 5;
/// MMSYSERR_INVALPARAM.
const MMSYSERR_INVALPARAM: u32 = 11;
/// MMSYSERR_NOTSUPPORTED.
const MMSYSERR_NOTSUPPORTED: u32 = 8;
/// ACMERR_NOTPOSSIBLE.
const ACMERR_NOTPOSSIBLE: u32 = 0x2000e;
/// ACM_METRIC_COUNT_DRIVERS.
const ACM_METRIC_COUNT_DRIVERS: u32 = 1;

impl PeHostRuntime {
    /// Route every ACM thunk to its dispatch function.
    pub(crate) fn dispatch_acm(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::AcmDriverEnum => {
                // No ACM drivers: the enumeration succeeds without invoking
                // the callback.
                let _callback = guest_call_arg(state, memory, 0)?;
                let _instance = guest_call_arg(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                state.set(Register::Rax, u64::from(MMSYSERR_NOERROR));
                Ok(())
            }
            HostThunk::AcmMetrics => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let metric = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if metric == ACM_METRIC_COUNT_DRIVERS {
                    if out != 0 {
                        write_guest_u32(memory, out, 0).ok();
                    }
                    state.set(Register::Rax, u64::from(MMSYSERR_NOERROR));
                } else {
                    state.set(Register::Rax, u64::from(MMSYSERR_INVALPARAM));
                }
                Ok(())
            }
            HostThunk::AcmDriverOpen
            | HostThunk::AcmFormatDetails
            | HostThunk::AcmFormatEnum
            | HostThunk::AcmFormatDetailsW
            | HostThunk::AcmFormatEnumW
            | HostThunk::AcmStreamOpen => {
                state.set(Register::Rax, u64::from(MMSYSERR_NODRIVER));
                Ok(())
            }
            HostThunk::AcmDriverClose => {
                let handle = guest_call_arg(state, memory, 0)?;
                state.set(
                    Register::Rax,
                    u64::from(if handle == 0 {
                        MMSYSERR_INVALHANDLE
                    } else {
                        MMSYSERR_NOERROR
                    }),
                );
                Ok(())
            }
            HostThunk::AcmFormatSuggest => {
                state.set(Register::Rax, u64::from(ACMERR_NOTPOSSIBLE));
                Ok(())
            }
            HostThunk::AcmDriverMessage => {
                state.set(Register::Rax, u64::from(MMSYSERR_NOTSUPPORTED));
                Ok(())
            }
            HostThunk::AcmStreamClose | HostThunk::AcmStreamConvert | HostThunk::AcmStreamSize => {
                let handle = guest_call_arg(state, memory, 0)?;
                state.set(
                    Register::Rax,
                    u64::from(if handle == 0 {
                        MMSYSERR_INVALHANDLE
                    } else {
                        MMSYSERR_NOERROR
                    }),
                );
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted ACM thunk {thunk:?}"),
            )),
        }
    }
}
