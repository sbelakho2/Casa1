//! Bounds-checked TPM 2.0 wire-format reader and writer.
//!
//! Every read is checked against the remaining slice; a short read is
//! `TPM_RC_SIZE` (or `TPM_RC_AUTHSIZE` for the authorization area), never a
//! panic.  Writers never exceed [`MAX_RESPONSE_SIZE`].

use super::constants::MAX_RESPONSE_SIZE;

/// Little state machine over a command parameter buffer.
pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
    empty_code: u32,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            empty_code: super::constants::TPM_RC_SIZE,
        }
    }

    pub fn with_empty_code(data: &'a [u8], empty_code: u32) -> Self {
        Self {
            data,
            offset: 0,
            empty_code,
        }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    pub fn position(&self) -> usize {
        self.offset
    }

    pub fn u8(&mut self) -> Result<u8, u32> {
        let byte = *self.data.get(self.offset).ok_or(self.empty_code)?;
        self.offset += 1;
        Ok(byte)
    }

    pub fn u16(&mut self) -> Result<u16, u32> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, u32> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8], u32> {
        let end = self.offset.checked_add(count).ok_or(self.empty_code)?;
        let slice = self.data.get(self.offset..end).ok_or(self.empty_code)?;
        self.offset = end;
        Ok(slice)
    }

    /// Read a `TPM2B_*` (16-bit length prefix) and enforce `max`.
    pub fn tpm2b(&mut self, max: usize) -> Result<&'a [u8], u32> {
        let size = self.u16()? as usize;
        if size > max {
            return Err(self.empty_code);
        }
        self.bytes(size)
    }

    pub fn finish(&self) -> Result<(), u32> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(self.empty_code)
        }
    }
}

/// Growable response writer with a hard response-size cap.
pub struct Writer {
    data: Vec<u8>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(64),
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub fn u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    /// Write a `TPM2B_*`: 16-bit length followed by the payload.
    pub fn tpm2b(&mut self, bytes: &[u8]) {
        self.u16(bytes.len() as u16);
        self.bytes(bytes);
    }
}

/// Build a complete TPM response without an authorization area.
pub fn no_auth_response(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&(10u32 + body.len() as u32).to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Build a complete TPM response with a parameter-size prefix and an
/// authorization area (only used for session responses).
pub fn session_response(
    response_code: u32,
    handles: &[u32],
    parameters: &[u8],
    auth_area: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(10 + handles.len() * 4 + 4 + parameters.len() + auth_area.len());
    out.extend_from_slice(&super::constants::TPM_ST_SESSIONS.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&response_code.to_be_bytes());
    for handle in handles {
        out.extend_from_slice(&handle.to_be_bytes());
    }
    out.extend_from_slice(&(parameters.len() as u32).to_be_bytes());
    out.extend_from_slice(parameters);
    out.extend_from_slice(auth_area);
    if out.len() > MAX_RESPONSE_SIZE {
        return no_auth_response(
            super::constants::TPM_ST_NO_SESSIONS,
            super::constants::TPM_RC_SIZE,
            &[],
        );
    }
    let size = out.len() as u32;
    out[2..6].copy_from_slice(&size.to_be_bytes());
    out
}

/// Read the 10-byte TPM command header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub tag: u16,
    pub size: u32,
    pub code: u32,
}

impl Header {
    pub fn parse(command: &[u8]) -> Result<Self, u32> {
        use super::constants::{MAX_COMMAND_SIZE, TPM_RC_COMMAND_SIZE};
        if command.len() < 10 {
            return Err(TPM_RC_COMMAND_SIZE);
        }
        let tag = u16::from_be_bytes([command[0], command[1]]);
        let size = u32::from_be_bytes([command[2], command[3], command[4], command[5]]);
        let code = u32::from_be_bytes([command[6], command[7], command[8], command[9]]);
        if size as usize != command.len() || size < 10 || size as usize > MAX_COMMAND_SIZE {
            return Err(TPM_RC_COMMAND_SIZE);
        }
        Ok(Self { tag, size, code })
    }
}
