//! DNP3 link layer.
//!
//! A frame is `05 64 | length | control | destination(2) | source(2) | crc(2)`
//! followed by user data split into blocks of up to 16 octets, each with its
//! own CRC. `length` counts the octets from `control` through the end of the
//! user data, excluding the start octets and every CRC.

use crate::crc::crc16;

/// Link start octets.
pub const START: [u8; 2] = [0x05, 0x64];
/// Fixed header size before the header CRC: start, length, control, dest, src.
pub const HEADER_LEN: usize = 8;
/// Maximum user-data block size before its CRC.
pub const MAX_BLOCK: usize = 16;
/// Smallest valid value of the length field (control + dest + src).
pub const MIN_LENGTH: usize = 5;

/// Reasons a byte stream could not be decoded as a DNP3 link frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The buffer does not yet contain a full frame; more octets are needed.
    Incomplete { needed: usize },
    /// The frame does not start with `05 64`.
    BadStart,
    /// The length field is smaller than the minimum.
    BadLength(u8),
    /// The header CRC does not match.
    HeaderCrc,
    /// A user-data block CRC does not match.
    DataCrc { block: usize },
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::Incomplete { needed } => write!(f, "incomplete frame: need {needed} octets"),
            LinkError::BadStart => write!(f, "frame does not start with 05 64"),
            LinkError::BadLength(len) => write!(f, "invalid length field: {len}"),
            LinkError::HeaderCrc => write!(f, "header CRC mismatch"),
            LinkError::DataCrc { block } => write!(f, "user-data block {block} CRC mismatch"),
        }
    }
}

impl std::error::Error for LinkError {}

/// Link layer control octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control {
    /// DIR bit: `false` for master-to-outstation, `true` for the reverse.
    pub from_outstation: bool,
    /// PRM bit: `true` for a primary frame, `false` for a secondary frame.
    pub primary: bool,
    /// FCB bit.
    pub fcb: bool,
    /// FCV/DFC bit.
    pub fcv: bool,
    /// Link function code (low nibble).
    pub function: u8,
}

impl Control {
    fn from_octet(octet: u8) -> Self {
        Control {
            from_outstation: octet & 0x80 != 0,
            primary: octet & 0x40 != 0,
            fcb: octet & 0x20 != 0,
            fcv: octet & 0x10 != 0,
            function: octet & 0x0F,
        }
    }

    /// Human-readable link function name.
    pub fn function_name(&self) -> &'static str {
        match self.function {
            0 => "Confirm",
            1 => "Read",
            2 => "Write",
            3 => "Select",
            4 => "Operate",
            5 => "Direct Operate",
            6 => "Direct Operate No Ack",
            9 => "Request Link Status",
            11 => "Unsolicited Response",
            15 => "Not Supported",
            _ => "Reserved",
        }
    }
}

/// A decoded link frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkFrame {
    /// Control octet.
    pub control: Control,
    /// DNP3 destination address.
    pub destination: u16,
    /// DNP3 source address.
    pub source: u16,
    /// Reassembled user data (transport + application layers).
    pub user_data: Vec<u8>,
}

/// Decode one link frame from `bytes`, returning the frame and how many octets
/// it consumed. Callers can advance by the consumed count to read the next.
pub fn parse_frame(bytes: &[u8]) -> Result<(LinkFrame, usize), LinkError> {
    if bytes.len() < HEADER_LEN + 2 {
        return Err(LinkError::Incomplete {
            needed: HEADER_LEN + 2,
        });
    }
    if bytes[0] != START[0] || bytes[1] != START[1] {
        return Err(LinkError::BadStart);
    }

    let length = bytes[2] as usize;
    if length < MIN_LENGTH {
        return Err(LinkError::BadLength(bytes[2]));
    }
    let user_data_len = length - MIN_LENGTH;
    let blocks = user_data_len.div_ceil(MAX_BLOCK);
    let total = HEADER_LEN + 2 + user_data_len + blocks * 2;
    if bytes.len() < total {
        return Err(LinkError::Incomplete { needed: total });
    }

    let header_crc = u16::from_le_bytes([bytes[8], bytes[9]]);
    if crc16(&bytes[..HEADER_LEN]) != header_crc {
        return Err(LinkError::HeaderCrc);
    }

    let mut user_data = Vec::with_capacity(user_data_len);
    let mut offset = HEADER_LEN + 2;
    let mut remaining = user_data_len;
    let mut block = 0;
    while remaining > 0 {
        let block_len = remaining.min(MAX_BLOCK);
        let data = &bytes[offset..offset + block_len];
        let expected =
            u16::from_le_bytes([bytes[offset + block_len], bytes[offset + block_len + 1]]);
        if crc16(data) != expected {
            return Err(LinkError::DataCrc { block });
        }
        user_data.extend_from_slice(data);
        offset += block_len + 2;
        remaining -= block_len;
        block += 1;
    }

    Ok((
        LinkFrame {
            control: Control::from_octet(bytes[3]),
            destination: u16::from_le_bytes([bytes[4], bytes[5]]),
            source: u16::from_le_bytes([bytes[6], bytes[7]]),
            user_data,
        },
        total,
    ))
}
