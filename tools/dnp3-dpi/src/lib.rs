//! DNP3 deep packet inspection.
//!
//! Decodes DNP3 link, transport and application layers from raw frames and
//! emits a normalized event that the repository's detection content consumes.
//! The crate is deliberately dependency-free and forbids unsafe code so it can
//! run at an OT network edge with a minimal trust surface.
//!
//! ```
//! use dnp3_dpi::parse_frame;
//!
//! # fn build_frame() -> Vec<u8> { vec![] }
//! # let bytes = build_frame();
//! if let Ok((frame, _consumed)) = parse_frame(&bytes) {
//!     if let Some(event) = frame.event() {
//!         println!("{}", event.to_json());
//!     }
//! }
//! ```

#![forbid(unsafe_code)]

pub mod application;
pub mod crc;
pub mod link;
pub mod transport;

pub use application::ApplicationHeader;
pub use link::{parse_frame, LinkError, LinkFrame};
pub use transport::TransportHeader;

/// Direction of an application message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A request from a master to an outstation.
    Request,
    /// A response or unsolicited response from an outstation.
    Response,
}

impl Direction {
    /// Lowercase label used in the normalized event.
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

impl LinkFrame {
    /// Decode the transport header from the start of the user data.
    pub fn transport(&self) -> Option<TransportHeader> {
        self.user_data
            .first()
            .map(|&octet| TransportHeader::from_octet(octet))
    }

    /// Decode the application header. Returns `None` for a non-first transport
    /// fragment, because the application header is only present on the first.
    pub fn application(&self) -> Option<ApplicationHeader> {
        let transport = self.transport()?;
        if !transport.fir {
            return None;
        }
        application::parse(&self.user_data[1..])
    }

    /// Build the normalized detection event for this frame.
    pub fn event(&self) -> Option<Event> {
        let transport = self.transport()?;
        let application = self.application()?;
        let direction = if application.function == application::FUNCTION_RESPONSE
            || application.function == application::FUNCTION_UNSOLICITED_RESPONSE
        {
            Direction::Response
        } else {
            Direction::Request
        };
        let object = application.objects.first();
        Some(Event {
            direction,
            function_code: application.function,
            function_name: application::function_name(application.function).to_string(),
            link_source: self.source,
            link_destination: self.destination,
            link_function: self.control.function,
            link_function_name: self.control.function_name().to_string(),
            object_group: object.map(|o| o.group),
            object_variation: object.map(|o| o.variation),
            object_count: object.and_then(|o| o.count),
            control_code: application.control_code,
            iin: application.iin,
            transport_sequence: transport.sequence,
            application_sequence: application.sequence,
        })
    }
}

/// Normalized DNP3 event emitted for each decoded application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Request or response.
    pub direction: Direction,
    /// Application function code.
    pub function_code: u8,
    /// Application function name.
    pub function_name: String,
    /// DNP3 source address.
    pub link_source: u16,
    /// DNP3 destination address.
    pub link_destination: u16,
    /// Link function code.
    pub link_function: u8,
    /// Link function name.
    pub link_function_name: String,
    /// First object group.
    pub object_group: Option<u8>,
    /// First object variation.
    pub object_variation: Option<u8>,
    /// Object count from the first header.
    pub object_count: Option<u32>,
    /// Control code for a binary-output control object.
    pub control_code: Option<u8>,
    /// Internal indications for responses.
    pub iin: Option<u16>,
    /// Transport sequence number.
    pub transport_sequence: u8,
    /// Application sequence number.
    pub application_sequence: u8,
}

impl Event {
    /// Serialize the event as a single JSON object.
    pub fn to_json(&self) -> String {
        let mut fields = vec![
            format!("\"direction\":\"{}\"", self.direction.as_str()),
            format!("\"function_code\":{}", self.function_code),
            format!("\"function_name\":\"{}\"", self.function_name),
            format!("\"link_source\":{}", self.link_source),
            format!("\"link_destination\":{}", self.link_destination),
            format!("\"link_function\":{}", self.link_function),
            format!("\"link_function_name\":\"{}\"", self.link_function_name),
            format!("\"transport_sequence\":{}", self.transport_sequence),
            format!("\"application_sequence\":{}", self.application_sequence),
        ];
        if let Some(group) = self.object_group {
            fields.push(format!("\"object_group\":{group}"));
        }
        if let Some(variation) = self.object_variation {
            fields.push(format!("\"object_variation\":{variation}"));
        }
        if let Some(count) = self.object_count {
            fields.push(format!("\"object_count\":{count}"));
        }
        if let Some(code) = self.control_code {
            fields.push(format!("\"control_code\":{code}"));
        }
        if let Some(iin) = self.iin {
            fields.push(format!("\"iin\":{iin}"));
        }
        format!("{{{}}}", fields.join(","))
    }
}

/// Decode every complete frame in `bytes`, stopping at the first error.
pub fn parse_stream(bytes: &[u8]) -> Vec<Result<LinkFrame, link::LinkError>> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        match link::parse_frame(&bytes[offset..]) {
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
    use crate::crc::crc16;
    use crate::link::START;

    /// Build a link frame with valid header and data CRCs.
    fn build_frame(control: u8, destination: u16, source: u16, user_data: &[u8]) -> Vec<u8> {
        let length = (link::MIN_LENGTH + user_data.len()) as u8;
        let mut header = vec![START[0], START[1], length, control];
        header.extend_from_slice(&destination.to_le_bytes());
        header.extend_from_slice(&source.to_le_bytes());
        let header_crc = crc16(&header);
        let mut frame = header;
        frame.extend_from_slice(&header_crc.to_le_bytes());
        for block in user_data.chunks(link::MAX_BLOCK) {
            frame.extend_from_slice(block);
            frame.extend_from_slice(&crc16(block).to_le_bytes());
        }
        frame
    }

    #[test]
    fn parses_a_direct_operate_control_request() {
        // transport FIR+FIN seq 0, app FIR+FIN seq 0, function 5 (Direct Operate),
        // object group 12 variation 1, qualifier 0x17 (2-octet start/stop range),
        // one CROB whose control code is 0x03 (LATCH_ON).
        let user_data = [
            0xC0, 0xC0, 0x05, 0x0C, 0x01, 0x17, 0x00, 0x00, 0x00, 0x00, 0x03,
        ];
        let bytes = build_frame(0x44, 1, 3, &user_data);
        let (frame, consumed) = link::parse_frame(&bytes).expect("frame parses");
        assert_eq!(consumed, bytes.len());
        assert_eq!(frame.source, 3);
        assert_eq!(frame.destination, 1);
        assert_eq!(frame.control.function, 4);
        assert!(frame.control.primary);

        let event = frame.event().expect("event");
        assert_eq!(event.direction, Direction::Request);
        assert_eq!(event.function_code, 5);
        assert_eq!(event.function_name, "Direct Operate");
        assert_eq!(event.object_group, Some(12));
        assert_eq!(event.object_variation, Some(1));
        assert_eq!(event.object_count, Some(1));
        assert_eq!(event.control_code, Some(3));
        assert!(event.to_json().contains("\"function_code\":5"));
    }

    #[test]
    fn parses_a_response_with_iin() {
        // transport FIR+FIN seq 1, app FIR+FIN seq 1, function 129 (Response),
        // IIN 0x0000.
        let user_data = [0xC1, 0xC1, 0x81, 0x00, 0x00];
        let bytes = build_frame(0xC4, 3, 1, &user_data);
        let (frame, _) = link::parse_frame(&bytes).expect("frame parses");
        let event = frame.event().expect("event");
        assert_eq!(event.direction, Direction::Response);
        assert_eq!(event.function_code, 129);
        assert_eq!(event.iin, Some(0));
    }

    #[test]
    fn rejects_a_corrupted_header_crc() {
        let mut bytes = build_frame(0x44, 1, 3, &[0xC0, 0xC0, 0x01]);
        bytes[8] ^= 0xFF;
        assert_eq!(link::parse_frame(&bytes), Err(link::LinkError::HeaderCrc));
    }

    #[test]
    fn reports_an_incomplete_frame() {
        let bytes = build_frame(0x44, 1, 3, &[0xC0, 0xC0, 0x01]);
        let short = &bytes[..bytes.len() - 1];
        assert!(matches!(
            link::parse_frame(short),
            Err(link::LinkError::Incomplete { .. })
        ));
    }

    #[test]
    fn parses_multiple_frames_from_a_stream() {
        let first = build_frame(
            0x44,
            1,
            3,
            &[0xC0, 0xC0, 0x05, 0x0C, 0x01, 0x17, 0, 0, 0, 0, 3],
        );
        let second = build_frame(0xC4, 3, 1, &[0xC1, 0xC1, 0x81, 0x00, 0x00]);
        let mut stream = first.clone();
        stream.extend_from_slice(&second);
        let frames = parse_stream(&stream);
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|f| f.is_ok()));
    }
}
