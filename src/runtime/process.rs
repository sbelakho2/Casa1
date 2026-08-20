//! Process exit routing and main-thread bookkeeping.
use super::*;

impl PeHostRuntime {
    /// Record an explicit exit request for the calling guest thread.
    ///
    /// While a pumped thread is active, the request is handed to the pump,
    /// which ends the thread immediately (`ExitThread`/`_endthreadex` fire
    /// DLL_THREAD_DETACH, `TerminateThread` does not).  On a non-pumped
    /// context (the main thread) the request ends only the MAIN thread's
    /// execution: Windows ends the process when its LAST thread exits, so
    /// the run keeps pumping pending guest threads while
    /// `main_thread_exit_code` is set, and ends with that code once no
    /// pending threads remain (or a process-exit API is called).
    pub(crate) fn request_current_thread_exit(&mut self, code: u32, fire_detach: bool) {
        if self.active_pumped_guest_thread.is_some() {
            self.pumped_thread_exit_requested = Some(code);
            self.pumped_thread_exit_with_detach = fire_detach;
        } else {
            self.main_thread_exit_code = Some(code);
            // Record the code in the kernel thread state so a wait on the
            // main thread's handle completes (Windows: a thread handle is
            // signaled once the thread exits, even mid-process).
            let _ = self
                .win32
                .set_thread_exit_code_by_id(self.win32.current_thread_id(), code);
        }
    }
}

impl PeHostRuntime {
    /// Pump pending guest threads to completion after the MAIN thread exited
    /// via an explicit thread-exit API (`ExitThread`/`_endthreadex`/
    /// `_endthread`/`TerminateThread` on self) while workers were still
    /// queued.  Windows only ends the process when the LAST thread exits, so
    /// the run must keep pumping until no pending threads remain.
    ///
    /// Returns the final process exit code: a worker that calls a
    /// process-exit API (`ExitProcess`/`exit`/...) wins (process exit
    /// abandons every thread, per Windows); otherwise the main thread's exit
    /// code ends the run.
    pub(crate) fn drain_pending_guest_threads_after_main_exit(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<i32> {
        let main_thread_code = self.main_thread_exit_code.unwrap_or(0) as i32;
        loop {
            if self.pending_guest_threads.is_empty() {
                return Ok(main_thread_code);
            }
            let pump_outcome = self.pump_pending_guest_thread(memory)?;
            if let Some(code) = pump_outcome.process_exit {
                return Ok(code);
            }
            if !pump_outcome.did_work {
                // Nothing runnable (sleeping/suspended workers): advance the
                // guest clock so wake_ticks expire, then retry.
                std::thread::sleep(std::time::Duration::from_millis(1));
                self.win32.record_sleep_observation(1, 1);
            }
        }
    }
}
