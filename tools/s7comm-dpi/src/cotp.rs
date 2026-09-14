//! COTP (ISO 8073) transport header.
//!
//! The first octet is a length indicator counting the header octets that follow
//! it, excluding user data. A DT (data) header is `02 F0 80`, so the S7 message
//! starts three octets in; a CR/CC header is longer.

/// COTP PDU type for data transfer (upper nibble).
pub const PDU_DT: u8 = 0xF0;
/// COTP PDU type for connection request (upper nibble).
pub const PDU_CR: u8 = 0xE0;
/// COTP PDU type for connection confirm (upper nibble).
pub const PDU_CC: u8 = 0xD0;

/// Decoded COTP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CotpHeader {
    /// PDU type (upper nibble of the second octet).
    pub pdu_type: u8,
    /// Full COTP header length in octets, including the length indicator.
    pub header_len: usize,
}

impl CotpHeader {
    /// True for a data-transfer PDU, the only type that carries S7 messages.
    pub fn is_data(&self) -> bool {
        self.pdu_type == PDU_DT
    }
}

/// Decode a COTP header from the start of `bytes`.
pub fn parse(bytes: &[u8]) -> Option<CotpHeader> {
    let indicator = usize::from(*bytes.first()?);
    if indicator < 2 {
        return None;
    }
    let header_len = 1 + indicator;
    if bytes.len() < header_len {
        return None;
    }
    Some(CotpHeader {
        pdu_type: bytes[1] & 0xF0,
        header_len,
    })
}
