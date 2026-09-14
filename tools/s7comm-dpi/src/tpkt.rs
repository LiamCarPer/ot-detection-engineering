//! TPKT (RFC 1006) framing, the outer wrapper for ISO-on-TCP traffic.
//!
//! Layout: `03 | reserved | length(2)` where `length` is the total TPKT size in
//! octets, including the 4-octet header. The remainder is a COTP PDU.

/// TPKT version octet.
pub const TPKT_VERSION: u8 = 0x03;
/// TPKT header size.
pub const HEADER_LEN: usize = 4;
/// Smallest valid TPKT length: header plus a minimal COTP DT header.
pub const MIN_LENGTH: u16 = 7;

/// Decoded TPKT header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpktHeader {
    /// Total length in octets, including the header.
    pub length: u16,
}

/// Reasons a buffer could not be decoded as a TPKT PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpktError {
    /// More octets are needed.
    Incomplete { needed: usize },
    /// The version octet is not `0x03`.
    BadVersion(u8),
    /// The length field is below the minimum.
    BadLength(u16),
}

impl std::fmt::Display for TpktError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpktError::Incomplete { needed } => write!(f, "incomplete TPKT: need {needed} octets"),
            TpktError::BadVersion(version) => write!(f, "unexpected TPKT version: {version:#04x}"),
            TpktError::BadLength(length) => write!(f, "invalid TPKT length: {length}"),
        }
    }
}

impl std::error::Error for TpktError {}

/// Decode the TPKT header and return it with the COTP payload.
pub fn parse(bytes: &[u8]) -> Result<(TpktHeader, &[u8]), TpktError> {
    if bytes.len() < HEADER_LEN {
        return Err(TpktError::Incomplete { needed: HEADER_LEN });
    }
    if bytes[0] != TPKT_VERSION {
        return Err(TpktError::BadVersion(bytes[0]));
    }
    let length = u16::from_be_bytes([bytes[2], bytes[3]]);
    if length < MIN_LENGTH {
        return Err(TpktError::BadLength(length));
    }
    let total = usize::from(length);
    if bytes.len() < total {
        return Err(TpktError::Incomplete { needed: total });
    }
    Ok((TpktHeader { length }, &bytes[HEADER_LEN..total]))
}
