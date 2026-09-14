//! OPC UA TCP message header.
//!
//! Layout: a 3-octet ASCII message type, a 1-octet chunk type and a little
//! endian 4-octet message size that includes the header itself.

/// Message header size.
pub const HEADER_LEN: usize = 8;

/// The message types defined by the OPC UA TCP binding.
pub const MESSAGE_TYPES: [[u8; 3]; 7] = [
    *b"HEL", *b"ACK", *b"ERR", *b"RHE", *b"OPN", *b"MSG", *b"CLO",
];

/// Chunk type: final, intermediate or abort.
pub const CHUNK_FINAL: u8 = b'F';
/// Chunk type: intermediate.
pub const CHUNK_INTERMEDIATE: u8 = b'C';
/// Chunk type: abort.
pub const CHUNK_ABORT: u8 = b'A';

/// Decoded message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    /// ASCII message type.
    pub message_type: [u8; 3],
    /// Chunk type octet.
    pub chunk_type: u8,
    /// Total message size including the header.
    pub size: u32,
}

impl MessageHeader {
    /// Message type as a string.
    pub fn type_str(&self) -> String {
        String::from_utf8_lossy(&self.message_type).into_owned()
    }
}

/// Reasons a buffer could not be decoded as an OPC UA message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// More octets are needed for a full message.
    Incomplete { needed: usize },
    /// The message type is not one of the OPC UA types.
    BadType,
    /// The chunk type is not final, intermediate or abort.
    BadChunk(u8),
    /// The size field is smaller than the header.
    BadSize(u32),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::Incomplete { needed } => {
                write!(f, "incomplete message: need {needed} octets")
            }
            MessageError::BadType => write!(f, "unrecognized OPC UA message type"),
            MessageError::BadChunk(chunk) => write!(f, "invalid chunk type: {chunk:#04x}"),
            MessageError::BadSize(size) => write!(f, "invalid message size: {size}"),
        }
    }
}

impl std::error::Error for MessageError {}

/// Decode the message header and return it with the message body.
pub fn parse(bytes: &[u8]) -> Result<(MessageHeader, &[u8]), MessageError> {
    if bytes.len() < HEADER_LEN {
        return Err(MessageError::Incomplete { needed: HEADER_LEN });
    }
    let message_type = [bytes[0], bytes[1], bytes[2]];
    if !MESSAGE_TYPES.contains(&message_type) {
        return Err(MessageError::BadType);
    }
    let chunk_type = bytes[3];
    if !matches!(chunk_type, CHUNK_FINAL | CHUNK_INTERMEDIATE | CHUNK_ABORT) {
        return Err(MessageError::BadChunk(chunk_type));
    }
    let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if size < HEADER_LEN as u32 {
        return Err(MessageError::BadSize(size));
    }
    let total = size as usize;
    if bytes.len() < total {
        return Err(MessageError::Incomplete { needed: total });
    }
    Ok((
        MessageHeader {
            message_type,
            chunk_type,
            size,
        },
        &bytes[HEADER_LEN..total],
    ))
}
