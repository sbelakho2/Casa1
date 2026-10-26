use super::*;

pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsException {
    pub code: u32,
    pub address: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HostSignal {
    Segv,
    Bus,
    Ill,
    FpeIntDivideByZero,
    Trap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExceptionDisposition {
    ContinueExecution,
    ContinueSearch,
    ExecuteHandler(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionHandler {
    pub name: String,
    pub handles_code: Option<u32>,
    pub disposition: ExceptionDisposition,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionDispatcher {
    pub(crate) veh: Vec<ExceptionHandler>,
    pub(crate) seh: Vec<ExceptionHandler>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchTrace {
    pub visited: Vec<String>,
    pub result: ExceptionDisposition,
}

impl ExceptionDispatcher {
    pub fn dispatch(&self, exception: &WindowsException) -> DispatchTrace {
        let mut visited = Vec::new();
        for handler in &self.veh {
            visited.push(format!("veh:{}", handler.name));
            if (handler.handles_code.is_none() || handler.handles_code == Some(exception.code))
                && handler.disposition != ExceptionDisposition::ContinueSearch
            {
                return DispatchTrace {
                    visited,
                    result: handler.disposition.clone(),
                };
            }
        }
        for handler in self.seh.iter().rev() {
            visited.push(format!("seh:{}", handler.name));
            if (handler.handles_code.is_none() || handler.handles_code == Some(exception.code))
                && handler.disposition != ExceptionDisposition::ContinueSearch
            {
                return DispatchTrace {
                    visited,
                    result: handler.disposition.clone(),
                };
            }
        }
        DispatchTrace {
            visited,
            result: ExceptionDisposition::ContinueSearch,
        }
    }
}

pub fn map_host_signal(signal: HostSignal, address: u64) -> WindowsException {
    let code = match signal {
        HostSignal::Segv | HostSignal::Bus => EXCEPTION_ACCESS_VIOLATION,
        HostSignal::Ill => EXCEPTION_ILLEGAL_INSTRUCTION,
        HostSignal::FpeIntDivideByZero => EXCEPTION_INT_DIVIDE_BY_ZERO,
        HostSignal::Trap => EXCEPTION_BREAKPOINT,
    };
    WindowsException { code, address }
}
