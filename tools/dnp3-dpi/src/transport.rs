//! DNP3 transport layer (a single octet: FIN, FIR and a 6-bit sequence).

/// Decoded transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHeader {
    /// Final fragment of a message.
    pub fin: bool,
    /// First fragment of a message.
    pub fir: bool,
    /// Transport sequence number (0-63).
    pub sequence: u8,
}

impl TransportHeader {
    /// Decode a transport octet.
    pub fn from_octet(octet: u8) -> Self {
        TransportHeader {
            fin: octet & 0x80 != 0,
            fir: octet & 0x40 != 0,
            sequence: octet & 0x3F,
        }
    }
}
