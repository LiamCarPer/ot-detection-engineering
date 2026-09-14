//! OPC UA deep packet inspection.
//!
//! Decodes the OPC UA TCP message header, the secure conversation header and the
//! service NodeId from message bodies, and emits a normalized event that the
//! repository's detection content consumes. Dependency-free and
//! `#![forbid(unsafe_code)]` so it can run at an OT network edge.
//!
//! Service bodies are only readable when they are not encrypted, so a channel
//! using `SignAndEncrypt` yields message and conversation metadata but no
//! service. This is a deliberate, documented limit of passive inspection.
//!
//! ```
//! use opcua_dpi::parse_frame;
//!
//! # fn frame() -> Vec<u8> { vec![] }
//! # let bytes = frame();
//! if let Ok((frame, _consumed)) = parse_frame(&bytes) {
//!     println!("{}", frame.event().to_json());
//! }
//! ```

#![forbid(unsafe_code)]

pub mod conversation;
pub mod message;
pub mod service;

pub use conversation::ConversationHeader;
pub use message::{MessageError, MessageHeader};
pub use service::ServiceNodeId;

/// Reasons a buffer could not be decoded as an OPC UA message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Message header error.
    Message(MessageError),
}

impl From<MessageError> for ParseError {
    fn from(error: MessageError) -> Self {
        ParseError::Message(error)
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Message(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A decoded OPC UA message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcUaFrame {
    /// TCP message header.
    pub header: MessageHeader,
    /// Secure conversation header, present on OPN, MSG and CLO.
    pub conversation: Option<ConversationHeader>,
    /// Service NodeId parsed from a plaintext message body.
    pub service: Option<ServiceNodeId>,
}

/// Decode one OPC UA message, returning it and how many octets it consumed.
pub fn parse_frame(bytes: &[u8]) -> Result<(OpcUaFrame, usize), ParseError> {
    let (header, body) = message::parse(bytes)?;
    let conversation = match &header.message_type {
        b"OPN" | b"MSG" | b"CLO" => conversation::parse(&header.message_type, body),
        _ => None,
    };
    let service = conversation
        .as_ref()
        .and_then(|conversation| service::parse_node_id(&conversation.body));
    let consumed = header.size as usize;
    Ok((
        OpcUaFrame {
            header,
            conversation,
            service,
        },
        consumed,
    ))
}

impl OpcUaFrame {
    /// Build the normalized detection event for this message.
    pub fn event(&self) -> Event {
        let service_name = self.service.and_then(|node| {
            if node.namespace == 0 {
                service::service_name(node.identifier)
            } else {
                None
            }
        });
        Event {
            message_type: self.header.type_str(),
            chunk_type: char::from(self.header.chunk_type).to_string(),
            secure_channel_id: self.conversation.as_ref().map(|c| c.secure_channel_id),
            security_policy_uri: self
                .conversation
                .as_ref()
                .and_then(|c| c.security_policy_uri.clone()),
            token_id: self.conversation.as_ref().and_then(|c| c.token_id),
            sequence_number: self.conversation.as_ref().map(|c| c.sequence_number),
            request_id: self.conversation.as_ref().map(|c| c.request_id),
            service_id: self.service.map(|node| node.identifier),
            // Named "opcua_service" rather than "service_name" because Loki
            // promotes a "service_name" field to a stream label, which would
            // break the generated LogQL rules.
            opcua_service: service_name.map(str::to_string),
            direction: service_name.map(|name| service::direction(name).to_string()),
        }
    }
}

/// Normalized OPC UA event emitted for each decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Message type: HEL, ACK, ERR, OPN, MSG or CLO.
    pub message_type: String,
    /// Chunk type: F, C or A.
    pub chunk_type: String,
    /// Secure channel id.
    pub secure_channel_id: Option<u32>,
    /// Security policy URI from OPN.
    pub security_policy_uri: Option<String>,
    /// Symmetric token id from MSG/CLO.
    pub token_id: Option<u32>,
    /// Sequence number.
    pub sequence_number: Option<u32>,
    /// Request id.
    pub request_id: Option<u32>,
    /// Service NodeId identifier.
    pub service_id: Option<u32>,
    /// Service name, when the body is plaintext and the service is known.
    pub opcua_service: Option<String>,
    /// Request or response.
    pub direction: Option<String>,
}

impl Event {
    /// Serialize the event as a single JSON object.
    pub fn to_json(&self) -> String {
        let mut fields = vec![
            format!("\"message_type\":\"{}\"", self.message_type),
            format!("\"chunk_type\":\"{}\"", self.chunk_type),
        ];
        if let Some(value) = self.secure_channel_id {
            fields.push(format!("\"secure_channel_id\":{value}"));
        }
        if let Some(value) = &self.security_policy_uri {
            fields.push(format!("\"security_policy_uri\":\"{value}\""));
        }
        if let Some(value) = self.token_id {
            fields.push(format!("\"token_id\":{value}"));
        }
        if let Some(value) = self.sequence_number {
            fields.push(format!("\"sequence_number\":{value}"));
        }
        if let Some(value) = self.request_id {
            fields.push(format!("\"request_id\":{value}"));
        }
        if let Some(value) = self.service_id {
            fields.push(format!("\"service_id\":{value}"));
        }
        if let Some(value) = &self.opcua_service {
            fields.push(format!("\"opcua_service\":\"{value}\""));
        }
        if let Some(value) = &self.direction {
            fields.push(format!("\"direction\":\"{value}\""));
        }
        format!("{{{}}}", fields.join(","))
    }
}

/// Decode every complete message in `bytes`, stopping at the first error.
pub fn parse_stream(bytes: &[u8]) -> Vec<Result<OpcUaFrame, ParseError>> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        match parse_frame(&bytes[offset..]) {
            Ok((frame, consumed)) => {
                frames.push(Ok(frame));
                offset += consumed;
            }
            Err(error) => {
                frames.push(Err(error));
                break;
            }
        }
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(message_type: &[u8; 3], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(*message_type);
        bytes.push(message::CHUNK_FINAL);
        bytes.extend_from_slice(&(8u32 + payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn null_byte_string() -> [u8; 4] {
        (-1i32).to_le_bytes()
    }

    #[test]
    fn parses_a_hello_message() {
        let bytes = frame(b"HEL", &[0; 20]);
        let (parsed, consumed) = parse_frame(&bytes).expect("frame parses");
        assert_eq!(consumed, bytes.len());
        let event = parsed.event();
        assert_eq!(event.message_type, "HEL");
        assert_eq!(event.chunk_type, "F");
        assert!(event.secure_channel_id.is_none());
    }

    #[test]
    fn parses_an_open_secure_channel() {
        let mut payload = 1u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&4i32.to_le_bytes());
        payload.extend_from_slice(b"None");
        payload.extend_from_slice(&null_byte_string());
        payload.extend_from_slice(&null_byte_string());
        payload.extend_from_slice(&1u32.to_le_bytes()); // sequence number
        payload.extend_from_slice(&1u32.to_le_bytes()); // request id

        let bytes = frame(b"OPN", &payload);
        let (parsed, _) = parse_frame(&bytes).expect("frame parses");
        let event = parsed.event();
        assert_eq!(event.message_type, "OPN");
        assert_eq!(event.secure_channel_id, Some(1));
        assert_eq!(event.security_policy_uri.as_deref(), Some("None"));
        assert_eq!(event.sequence_number, Some(1));
    }

    #[test]
    fn parses_a_write_request_service() {
        // Secure channel id, token id, sequence, request id, then the service
        // NodeId for WriteRequest_Encoding_DefaultBinary (673) in the four-byte
        // encoding, and the ExtensionObject encoding byte.
        let mut payload = 1u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&[0x01, 0x00, 0xA1, 0x02, 0x01, 0x00, 0x00, 0x00]);

        let bytes = frame(b"MSG", &payload);
        let (parsed, _) = parse_frame(&bytes).expect("frame parses");
        let event = parsed.event();
        assert_eq!(event.message_type, "MSG");
        assert_eq!(event.secure_channel_id, Some(1));
        assert_eq!(event.token_id, Some(1));
        assert_eq!(event.service_id, Some(673));
        assert_eq!(event.opcua_service.as_deref(), Some("WriteRequest"));
        assert_eq!(event.direction.as_deref(), Some("request"));
    }

    #[test]
    fn encrypted_body_yields_no_service() {
        let mut payload = 1u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let bytes = frame(b"MSG", &payload);
        let (parsed, _) = parse_frame(&bytes).expect("frame parses");
        assert!(parsed.service.is_none());
        assert!(parsed.event().opcua_service.is_none());
    }

    #[test]
    fn rejects_an_unknown_message_type() {
        let mut bytes = frame(b"HEL", &[]);
        bytes[0] = b'X';
        assert_eq!(
            parse_frame(&bytes),
            Err(ParseError::Message(MessageError::BadType))
        );
    }

    #[test]
    fn reports_an_incomplete_message() {
        let bytes = frame(b"HEL", &[0; 20]);
        assert!(matches!(
            parse_frame(&bytes[..bytes.len() - 1]),
            Err(ParseError::Message(MessageError::Incomplete { .. }))
        ));
    }

    #[test]
    fn classifies_service_names_and_direction() {
        assert_eq!(service::service_name(673), Some("WriteRequest"));
        assert_eq!(service::service_name(676), Some("WriteResponse"));
        assert_eq!(service::service_name(9999), None);
        assert_eq!(service::direction("CallRequest"), "request");
        assert_eq!(service::direction("CallResponse"), "response");
    }
}
