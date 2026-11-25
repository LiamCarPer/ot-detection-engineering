//! Modbus/TCP MBAP header framing.
//!
//! The MBAP header is seven octets: transaction identifier, protocol
//! identifier, length and unit identifier. The length field counts the unit
//! identifier plus the PDU, so a complete frame is `6 + length` octets.

/// Length of the MBAP header in octets.
pub const HEADER_LEN: usize = 7;

/// The only protocol identifier defined for Modbus/TCP.
pub const PROTOCOL_ID: u16 = 0;

/// A decoded MBAP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbapHeader {
    /// Transaction identifier, echoed by the server.
    pub transaction_id: u16,
    /// Protocol identifier; zero for Modbus/TCP.
    pub protocol_id: u16,
    /// Number of octets following the length field (unit id plus PDU).
    pub length: u16,
    /// Modbus unit identifier.
    pub unit_id: u8,
}

/// Reasons an MBAP frame could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbapError {
    /// Fewer than seven octets were available for the MBAP header.
    Incomplete { needed: usize, available: usize },
    /// The protocol identifier was not zero.
    BadProtocolId(u16),
    /// The length field cannot hold a unit identifier and a function code.
    InvalidLength(u16),
    /// The declared length runs past the end of the buffer.
    LengthMismatch { declared: u16, available: usize },
}

impl std::fmt::Display for MbapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MbapError::Incomplete { needed, available } => write!(
                f,
                "truncated MBAP header: need {needed} octets, have {available}"
            ),
            MbapError::BadProtocolId(id) => {
                write!(f, "unexpected MBAP protocol id 0x{id:04X}, expected 0")
            }
            MbapError::InvalidLength(length) => write!(
                f,
                "invalid MBAP length {length}: need at least 2 octets for unit id and function code"
            ),
            MbapError::LengthMismatch {
                declared,
                available,
            } => write!(
                f,
                "MBAP length {declared} needs {declared} octets after the length field, have {available}"
            ),
        }
    }
}

impl std::error::Error for MbapError {}

/// Parse the MBAP header and return it with the PDU and the octets consumed.
pub fn parse(bytes: &[u8]) -> Result<(MbapHeader, &[u8], usize), MbapError> {
    if bytes.len() < HEADER_LEN {
        return Err(MbapError::Incomplete {
            needed: HEADER_LEN,
            available: bytes.len(),
        });
    }

    let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let protocol_id = u16::from_be_bytes([bytes[2], bytes[3]]);
    let length = u16::from_be_bytes([bytes[4], bytes[5]]);

    if protocol_id != PROTOCOL_ID {
        return Err(MbapError::BadProtocolId(protocol_id));
    }
    if length < 2 {
        return Err(MbapError::InvalidLength(length));
    }

    // `6 + length` is the whole frame: six header octets before the length
    // field's payload plus the unit identifier and PDU. The cast is safe on
    // every supported target and the comparison is done in `usize`.
    let total = 6 + usize::from(length);
    if bytes.len() < total {
        return Err(MbapError::LengthMismatch {
            declared: length,
            available: bytes.len() - 6,
        });
    }

    let header = MbapHeader {
        transaction_id,
        protocol_id,
        length,
        unit_id: bytes[6],
    };
    Ok((header, &bytes[7..total], total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_header_and_pdu() {
        let frame = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ];
        let (header, pdu, consumed) = parse(&frame).expect("frame parses");
        assert_eq!(header.transaction_id, 1);
        assert_eq!(header.protocol_id, 0);
        assert_eq!(header.length, 6);
        assert_eq!(header.unit_id, 1);
        assert_eq!(pdu, &frame[7..]);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn rejects_a_bad_protocol_id() {
        let frame = [0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x01, 0x03];
        assert_eq!(parse(&frame), Err(MbapError::BadProtocolId(1)));
    }

    #[test]
    fn rejects_a_length_smaller_than_unit_and_function() {
        let frame = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01];
        assert_eq!(parse(&frame), Err(MbapError::InvalidLength(1)));
    }

    #[test]
    fn rejects_a_declared_length_past_the_buffer() {
        // Declares 6 octets after the length field but supplies only two.
        let frame = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03];
        assert_eq!(
            parse(&frame),
            Err(MbapError::LengthMismatch {
                declared: 6,
                available: 2
            })
        );
    }

    #[test]
    fn rejects_a_short_header() {
        assert_eq!(
            parse(&[0x00, 0x01, 0x00]),
            Err(MbapError::Incomplete {
                needed: 7,
                available: 3
            })
        );
    }
}
