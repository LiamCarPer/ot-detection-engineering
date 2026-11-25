//! Modbus/TCP deep packet inspection.
//!
//! Decodes the MBAP header and the Modbus PDU from raw frames and emits a
//! normalized event that the repository's detection content consumes. The
//! crate is deliberately dependency-free and forbids unsafe code so it can run
//! at an OT network edge with a minimal trust surface.
//!
//! ```
//! use modbus_dpi::parse_frame;
//!
//! # fn frame() -> Vec<u8> { vec![] }
//! # let bytes = frame();
//! if let Ok((frame, _consumed)) = parse_frame(&bytes) {
//!     println!("{}", frame.event().to_json());
//! }
//! ```

#![forbid(unsafe_code)]

pub mod mbap;
pub mod pdu;

pub use mbap::{MbapError as ParseError, MbapHeader, HEADER_LEN, PROTOCOL_ID};
pub use pdu::{DecodeError, DecodedPdu, DeviceIdObject, Direction};

/// A decoded Modbus/TCP frame: the MBAP fields plus the raw PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Transaction identifier.
    pub transaction_id: u16,
    /// Protocol identifier (zero for Modbus/TCP).
    pub protocol_id: u16,
    /// MBAP length field (unit identifier plus PDU length).
    pub length: u16,
    /// Unit identifier.
    pub unit_id: u8,
    /// Raw PDU bytes, starting with the function code.
    pub pdu: Vec<u8>,
}

/// Decode one Modbus/TCP frame, returning it and how many octets it consumed.
///
/// Trailing octets are left for the caller (or `parse_stream`) so a buffer can
/// hold several frames. A frame whose declared MBAP length runs past the end
/// of the buffer is rejected rather than partially decoded.
pub fn parse_frame(bytes: &[u8]) -> Result<(Frame, usize), ParseError> {
    let (header, pdu, consumed) = mbap::parse(bytes)?;
    let frame = Frame {
        transaction_id: header.transaction_id,
        protocol_id: header.protocol_id,
        length: header.length,
        unit_id: header.unit_id,
        pdu: pdu.to_vec(),
    };
    Ok((frame, consumed))
}

impl Frame {
    /// Decode the PDU strictly, returning a structured error on bad input.
    pub fn decode(&self) -> Result<DecodedPdu, DecodeError> {
        pdu::decode(&self.pdu)
    }

    /// Build the normalized event. Framing has already succeeded, so this
    /// always returns an event: a PDU that cannot be decoded is surfaced with
    /// `decode_error` instead of being dropped.
    pub fn event(&self) -> Event {
        let decoded = match self.decode() {
            Ok(decoded) => decoded,
            Err(error) => pdu::error_event(&self.pdu, &error),
        };
        Event::from_parts(self, decoded)
    }
}

/// Normalized Modbus event emitted for each decoded request or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Request or response.
    pub direction: Direction,
    /// Function code with any exception bit removed.
    pub function_code: u8,
    /// Raw function-code octet for exception responses.
    pub raw_function_code: Option<u8>,
    /// Function name, or `Unsupported`.
    pub function_name: String,
    /// MBAP transaction identifier.
    pub transaction_id: u16,
    /// MBAP protocol identifier.
    pub protocol_id: u16,
    /// MBAP unit identifier.
    pub unit_id: u8,
    /// Length of the raw PDU in octets.
    pub pdu_length: usize,
    /// Exception code for an exception response.
    pub exception_code: Option<u8>,
    /// Starting register for FC3/4/6/16/22/23.
    pub register: Option<u16>,
    /// Last register covered by `register + quantity - 1`, when both are known.
    pub register_end: Option<u32>,
    /// Register quantity for FC3/4/16/23 and coil quantity for FC1/2/15.
    pub quantity: Option<u16>,
    /// Written value for FC5/6/16/23 where derivable.
    pub value: Option<u32>,
    /// Register values for multi-register reads and writes.
    pub values: Vec<u16>,
    /// Coil values for FC1/2/5/15.
    pub coils: Vec<bool>,
    /// Byte count on the wire.
    pub byte_count: Option<u16>,
    /// AND mask for FC22.
    pub and_mask: Option<u16>,
    /// OR mask for FC22.
    pub or_mask: Option<u16>,
    /// Write starting register for the write half of FC23.
    pub write_register: Option<u16>,
    /// Last register covered by the FC23 write half.
    pub write_register_end: Option<u32>,
    /// Write quantity for the write half of FC23.
    pub write_quantity: Option<u16>,
    /// MEI type for FC43.
    pub mei_type: Option<u8>,
    /// Read Device Identification read code.
    pub read_device_id_code: Option<u8>,
    /// Requested or first object identifier for FC43.
    pub object_id: Option<u8>,
    /// Conformity level in a Read Device Identification response.
    pub conformity_level: Option<u8>,
    /// More-follows flag in a Read Device Identification response.
    pub more_follows: Option<bool>,
    /// Next object identifier for a continuation response.
    pub next_object_id: Option<u8>,
    /// Objects returned by Read Device Identification.
    pub device_id_objects: Vec<DeviceIdObject>,
    /// Structured reason the PDU could not be decoded.
    pub decode_error: Option<String>,
}

impl Event {
    fn from_parts(frame: &Frame, decoded: DecodedPdu) -> Self {
        Event {
            direction: decoded.direction,
            function_code: decoded.function_code,
            raw_function_code: decoded.raw_function_code,
            function_name: decoded.function_name.to_string(),
            transaction_id: frame.transaction_id,
            protocol_id: frame.protocol_id,
            unit_id: frame.unit_id,
            pdu_length: frame.pdu.len(),
            exception_code: decoded.exception_code,
            register: decoded.register,
            register_end: _register_end(decoded.register, decoded.quantity, decoded.function_code),
            quantity: decoded.quantity,
            value: decoded.value,
            values: decoded.values,
            coils: decoded.coils,
            byte_count: decoded.byte_count,
            and_mask: decoded.and_mask,
            or_mask: decoded.or_mask,
            write_register: decoded.write_register,
            write_register_end: _register_end(
                decoded.write_register,
                decoded.write_quantity,
                decoded.function_code,
            ),
            write_quantity: decoded.write_quantity,
            mei_type: decoded.mei_type,
            read_device_id_code: decoded.read_device_id_code,
            object_id: decoded.object_id,
            conformity_level: decoded.conformity_level,
            more_follows: decoded.more_follows,
            next_object_id: decoded.next_object_id,
            device_id_objects: decoded.objects,
            decode_error: decoded.decode_error,
        }
    }

    /// Serialize the event as a single JSON object.
    pub fn to_json(&self) -> String {
        let mut fields = vec![
            format!("\"direction\":\"{}\"", self.direction.as_str()),
            format!("\"function_code\":{}", self.function_code),
            format!("\"function_name\":\"{}\"", escape_json(&self.function_name)),
            format!("\"transaction_id\":{}", self.transaction_id),
            format!("\"protocol_id\":{}", self.protocol_id),
            format!("\"unit_id\":{}", self.unit_id),
            format!("\"pdu_length\":{}", self.pdu_length),
        ];

        push_u8(&mut fields, "raw_function_code", self.raw_function_code);
        push_u8(&mut fields, "exception_code", self.exception_code);
        push_u16(&mut fields, "register", self.register);
        if let Some(end) = self.register_end {
            fields.push(format!("\"register_end\":{end}"));
        }
        push_u16(&mut fields, "quantity", self.quantity);
        if let Some(value) = self.value {
            fields.push(format!("\"value\":{value}"));
        }
        push_u16(&mut fields, "byte_count", self.byte_count);
        push_u16(&mut fields, "and_mask", self.and_mask);
        push_u16(&mut fields, "or_mask", self.or_mask);
        push_u16(&mut fields, "write_register", self.write_register);
        if let Some(end) = self.write_register_end {
            fields.push(format!("\"write_register_end\":{end}"));
        }
        push_u16(&mut fields, "write_quantity", self.write_quantity);
        push_u8(&mut fields, "mei_type", self.mei_type);
        push_u8(&mut fields, "read_device_id_code", self.read_device_id_code);
        push_u8(&mut fields, "object_id", self.object_id);
        push_u8(&mut fields, "conformity_level", self.conformity_level);
        if let Some(more_follows) = self.more_follows {
            fields.push(format!("\"more_follows\":{more_follows}"));
        }
        push_u8(&mut fields, "next_object_id", self.next_object_id);

        if !self.values.is_empty() {
            let values: Vec<String> = self.values.iter().map(u16::to_string).collect();
            fields.push(format!("\"values\":[{}]", values.join(",")));
        }
        if !self.coils.is_empty() {
            let coils: Vec<String> = self.coils.iter().map(bool::to_string).collect();
            fields.push(format!("\"coils\":[{}]", coils.join(",")));
        }
        if !self.device_id_objects.is_empty() {
            let objects: Vec<String> = self
                .device_id_objects
                .iter()
                .map(|object| {
                    format!(
                        "{{\"object_id\":{},\"length\":{},\"value\":\"{}\"}}",
                        object.object_id,
                        object.length,
                        escape_json(&object.value)
                    )
                })
                .collect();
            fields.push(format!("\"device_id_objects\":[{}]", objects.join(",")));
        }

        if let Some(error) = &self.decode_error {
            fields.push(format!("\"decode_error\":\"{}\"", escape_json(error)));
        }

        format!("{{{}}}", fields.join(","))
    }
}

/// Last address covered by a starting address and quantity.
///
/// Single-address writes (FC5/FC6/FC22) do not carry a quantity on the wire, so
/// they default to one. A zero quantity has no range.
fn _register_end(start: Option<u16>, quantity: Option<u16>, function: u8) -> Option<u32> {
    let start = start?;
    let quantity = quantity.or(match function {
        5 | 6 | 22 => Some(1),
        _ => None,
    })?;
    if quantity == 0 {
        return None;
    }
    Some(u32::from(start) + u32::from(quantity) - 1)
}

fn push_u16(fields: &mut Vec<String>, name: &str, value: Option<u16>) {
    if let Some(value) = value {
        fields.push(format!("\"{name}\":{value}"));
    }
}

fn push_u8(fields: &mut Vec<String>, name: &str, value: Option<u8>) {
    if let Some(value) = value {
        fields.push(format!("\"{name}\":{value}"));
    }
}

/// Escape a string for JSON output. Device identification values come from the
/// wire and are attacker-controlled, so quotes, backslashes and control
/// characters must not break the one-object-per-line output.
fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

/// Decode every complete frame in `bytes`, stopping at the first error.
pub fn parse_stream(bytes: &[u8]) -> Vec<Result<Frame, ParseError>> {
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

    fn build_frame(transaction_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
        let length = u16::try_from(pdu.len() + 1).expect("PDU fits the MBAP length");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&transaction_id.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(unit_id);
        bytes.extend_from_slice(pdu);
        bytes
    }

    fn event_for(transaction_id: u16, pdu: &[u8]) -> Event {
        let bytes = build_frame(transaction_id, 1, pdu);
        parse_frame(&bytes).expect("frame is well formed").0.event()
    }

    #[test]
    fn parses_a_read_holding_registers_request() {
        let event = event_for(7, &[3, 0x00, 0x00, 0x00, 0x0A]);
        assert_eq!(event.direction, Direction::Request);
        assert_eq!(event.function_code, 3);
        assert_eq!(event.function_name, "Read Holding Registers");
        assert_eq!(event.transaction_id, 7);
        assert_eq!(event.unit_id, 1);
        assert_eq!(event.register, Some(0));
        assert_eq!(event.quantity, Some(10));
        assert!(event.decode_error.is_none());
    }

    #[test]
    fn parses_an_exception_response() {
        let event = event_for(9, &[0x83, 0x02]);
        assert_eq!(event.direction, Direction::Response);
        assert_eq!(event.function_code, 3);
        assert_eq!(event.raw_function_code, Some(0x83));
        assert_eq!(event.exception_code, Some(2));
        assert!(event.to_json().contains("\"exception_code\":2"));
    }

    #[test]
    fn parses_a_coil_write() {
        let event = event_for(5, &[5, 0x00, 0xAC, 0xFF, 0x00]);
        assert_eq!(event.function_code, 5);
        assert_eq!(event.register, Some(172));
        assert_eq!(event.value, Some(1));
        assert_eq!(event.coils, vec![true]);
    }

    #[test]
    fn surfaces_an_unknown_function_code() {
        let event = event_for(11, &[0x07]);
        assert_eq!(event.function_code, 7);
        assert_eq!(event.function_name, "Unsupported");
        assert!(event.decode_error.as_deref().is_some_and(|e| !e.is_empty()));
        assert!(event.to_json().contains("\"decode_error\""));
    }

    #[test]
    fn rejects_a_truncated_mbap_header() {
        let bytes = build_frame(1, 1, &[3, 0, 0, 0, 1]);
        assert!(matches!(
            parse_frame(&bytes[..4]),
            Err(ParseError::Incomplete { .. })
        ));
    }

    #[test]
    fn rejects_a_mbap_length_past_the_buffer() {
        let mut bytes = build_frame(1, 1, &[3, 0, 0, 0, 1]);
        bytes[5] = 0xFF;
        assert!(matches!(
            parse_frame(&bytes),
            Err(ParseError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn parses_two_frames_from_one_buffer() {
        let mut stream = build_frame(1, 1, &[3, 0, 0, 0, 1]);
        stream.extend_from_slice(&build_frame(2, 1, &[6, 0, 0, 0, 1]));
        let frames = parse_stream(&stream);
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(Result::is_ok));
    }

    #[test]
    fn escapes_device_identification_strings() {
        let event = event_for(3, &[43, 0x0E, 1, 1, 0, 0, 1, 0, 3, b'"', b'\\', b'\n']);
        let json = event.to_json();
        assert!(json.contains("\\\""));
        assert!(json.contains("\\\\"));
        assert!(!json.contains('\n'));
    }
}
