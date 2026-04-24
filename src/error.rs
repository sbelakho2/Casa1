use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone)]
pub struct AppError {
    pub code: ReasonCode,
    pub message: String,
    pub reproduction_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub reason_code: u32,
    pub reason_name: String,
    pub message: String,
    pub reproduction_hints: Vec<String>,
}

impl AppError {
    pub fn new(code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            reproduction_hints: Vec::new(),
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.reproduction_hints.push(hint.into());
        self
    }

    pub fn from_io(code: ReasonCode, message: impl Into<String>, source: &std::io::Error) -> Self {
        Self::new(code, message).with_hint(source.to_string())
    }

    pub fn to_response(&self) -> ErrorResponse {
        ErrorResponse {
            reason_code: self.code.as_u32(),
            reason_name: self.code.name().to_string(),
            message: self.message.clone(),
            reproduction_hints: self.reproduction_hints.clone(),
        }
    }
}