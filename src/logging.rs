use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub event_id: u32,
    pub ts_ticks: u64,
    pub pid: u32,
    pub tid: u64,
    pub module: String,
    pub severity: String,
    pub reason_code: u32,
    pub win32_err: Option<u32>,
    pub ntstatus: Option<u32>,
    pub msg: String,
    pub kv: BTreeMap<String, Value>,
}

pub struct JsonlLogger {
    writer: BufWriter<File>,
    next_event_id: u32,
    started_at: Instant,
    pid: u32,
    dtm: bool,
}

impl JsonlLogger {
    pub fn new(path: &Path, pid: u32, dtm: bool) -> AppResult<Self> {
        crate::util::ensure_parent(path)?;
        let file = File::create(path).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", path.display()),
                &error,
            )
        })?;
        Ok(Self {
            writer: BufWriter::new(file),
            next_event_id: 1,
            started_at: Instant::now(),
            pid,
            dtm,
        })
    }

    pub fn log(
        &mut self,
        module: &str,
        severity: &str,
        reason_code: ReasonCode,
        message: impl Into<String>,
        kv: BTreeMap<String, Value>,
    ) -> AppResult<LogEvent> {
        let event = LogEvent {
            event_id: self.next_event_id,
            ts_ticks: if self.dtm {
                self.next_event_id as u64
            } else {
                self.started_at.elapsed().as_micros() as u64
            },
            pid: self.pid,
            tid: 1,
            module: module.to_string(),
            severity: severity.to_string(),
            reason_code: reason_code.as_u32(),
            win32_err: None,
            ntstatus: None,
            msg: message.into(),
            kv,
        };
        self.next_event_id += 1;
        let line = serde_json::to_string(&event).map_err(|error| {
            AppError::new(ReasonCode::RcIo, "failed to encode JSONL event")
                .with_hint(error.to_string())
        })?;
        writeln!(self.writer, "{line}").map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to write JSONL log event", &error)
        })?;
        self.writer.flush().map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to flush JSONL logger", &error)
        })?;
        Ok(event)
    }
}