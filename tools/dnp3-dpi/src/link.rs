//! DNP3 link layer.
//!
//! A frame is `05 64 | length | control | destination(2) | source(2) | crc(2)`
//! followed by user data split into blocks of up to 16 octets, each with its
//! own CRC. `length` counts the octets from `control` through the end of the
//! user data, excluding the start octets and every CRC.
//!
//! The link function codes are IEEE 1815 link functions, not application
//! function codes. In particular function 4 is UNCONFIRMED_USER_DATA, never
//! "Operate". The DIR bit of the control octet is the authority for direction:
//! `DIR=0` is master-to-outstation, `DIR=1` is outstation-to-master.

use crate::crc::crc16;

/// Link start octets.
pub const START: [u8; 2] = [0x05, 0x64];
/// Fixed header size before the header CRC: start, length, control, dest, src.
pub const HEADER_LEN: usize = 8;
/// Maximum user-data block size before its CRC.
pub const MAX_BLOCK: usize = 16;
/// Smallest valid value of the length field (control + dest + src).
pub const MIN_LENGTH: usize = 5;

/// Primary link function: reset the link states.
pub const FUNCTION_RESET_LINK_STATES: u8 = 0;
/// Primary link function: reset the user process.
pub const FUNCTION_RESET_USER_PROCESS: u8 = 1;
/// Primary link function: test the link states.
pub const FUNCTION_TEST_LINK_STATES: u8 = 2;
/// Primary link function: confirmed user data.
pub const FUNCTION_CONFIRMED_USER_DATA: u8 = 3;
/// Primary link function: unconfirmed user data.
pub const FUNCTION_UNCONFIRMED_USER_DATA: u8 = 4;
/// Primary link function: request link status.
pub const FUNCTION_REQUEST_LINK_STATUS: u8 = 9;
/// Secondary link function: link status.
pub const FUNCTION_LINK_STATUS: u8 = 11;

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

    /// Human-readable link function name for this control octet.
    pub fn function_name(&self) -> &'static str {
        link_function_name(self.function, self.primary)
    }

    /// Whether this is a confirmed or unconfirmed user-data frame.
    pub fn is_user_data(&self) -> bool {
        self.primary
            && matches!(
                self.function,
                FUNCTION_CONFIRMED_USER_DATA | FUNCTION_UNCONFIRMED_USER_DATA
            )
    }
}

/// Human-readable IEEE 1815 link function name.
///
/// Primary and secondary frames reuse several function numbers, so `primary`
/// selects the correct name. Codes 5 and 6 are reserved.
pub fn link_function_name(function: u8, primary: bool) -> &'static str {
    match function {
        0 if primary => "RESET_LINK_STATES",
        0 => "ACK",
        1 if primary => "RESET_USER_PROCESS",
        1 => "NACK",
        2 if primary => "TEST_LINK_STATES",
        3 if primary => "CONFIRMED_USER_DATA",
        4 if primary => "UNCONFIRMED_USER_DATA",
        9 if primary => "REQUEST_LINK_STATUS",
        11 => "LINK_STATUS",
        15 if !primary => "NOT_SUPPORTED",
        _ => "Reserved",
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
    /// Reassembled user data (transport + application layers). Per-block CRCs
    /// have been validated and stripped.
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
