//! S7comm deep packet inspection.
//!
//! Decodes TPKT (RFC 1006), COTP (ISO 8073) and the classic S7comm application
//! layer from raw frames and emits a normalized event that the repository's
//! detection content consumes. Dependency-free and `#![forbid(unsafe_code)]` so
//! it can run at an OT network edge with a minimal trust surface.
//!
//! Only classic S7comm (protocol id `0x32`) is decoded; S7comm Plus (`0x72`)
//! and COTP connection setup carry no S7 job and produce no event.
//!
//! ```
//! use s7comm_dpi::parse_frame;
//!
//! # fn frame() -> Vec<u8> { vec![] }
//! # let bytes = frame();
//! if let Ok((frame, _consumed)) = parse_frame(&bytes) {
//!     if let Some(event) = frame.event() {
//!         println!("{}", event.to_json());
//!     }
//! }
//! ```

#![forbid(unsafe_code)]

pub mod cotp;
pub mod s7;
pub mod tpkt;

pub use cotp::CotpHeader;
pub use s7::S7Header;
pub use tpkt::{TpktError, TpktHeader};

/// Direction of an S7 message, derived from the ROSCTR octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A job sent to the controller.
    Request,
    /// An acknowledgement or acknowledgement-with-data from the controller.
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

/// Reasons a buffer could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// TPKT framing error.
    Tpkt(TpktError),
    /// COTP header error.
    Cotp,
}

impl From<TpktError> for ParseError {
    fn from(error: TpktError) -> Self {
        ParseError::Tpkt(error)
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Tpkt(error) => write!(f, "{error}"),
            ParseError::Cotp => write!(f, "invalid COTP header"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A decoded TPKT/COTP frame, with the S7 header when it is a data PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S7CommFrame {
    /// TPKT length field.
    pub tpkt_length: u16,
    /// COTP PDU type (upper nibble).
    pub cotp_type: u8,
    /// S7 header, present only for data PDUs carrying classic S7comm.
    pub s7: Option<S7Header>,
}

/// Decode one TPKT frame, returning it and how many octets it consumed.
pub fn parse_frame(bytes: &[u8]) -> Result<(S7CommFrame, usize), ParseError> {
    let (tpkt, payload) = tpkt::parse(bytes)?;
    let cotp = cotp::parse(payload).ok_or(ParseError::Cotp)?;
    let s7 = if cotp.is_data() {
        s7::parse(&payload[cotp.header_len..])
    } else {
        None
    };
    let frame = S7CommFrame {
        tpkt_length: tpkt.length,
        cotp_type: cotp.pdu_type,
        s7,
    };
    Ok((frame, usize::from(tpkt.length)))
}

impl S7CommFrame {
    /// Build the normalized detection event, or `None` for a non-data PDU.
    pub fn event(&self) -> Option<Event> {
        let s7 = self.s7?;
        let direction = match s7.rosctr {
            0x02 | 0x03 => Direction::Response,
            _ => Direction::Request,
        };
        Some(Event {
            direction,
            function_code: s7.function,
            function_name: s7::function_name(s7.function).to_string(),
            rosctr: s7.rosctr,
            pdu_reference: s7.pdu_reference,
            parameter_length: s7.parameter_length,
            data_length: s7.data_length,
            cotp_type: self.cotp_type,
        })
    }
}

/// Normalized S7comm event emitted for each decoded S7 job or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Request or response.
    pub direction: Direction,
    /// S7 function code.
    pub function_code: u8,
    /// S7 function name.
    pub function_name: String,
    /// ROSCTR message type.
    pub rosctr: u8,
    /// PDU reference.
    pub pdu_reference: u16,
    /// Parameter block length.
    pub parameter_length: u16,
    /// Data block length.
    pub data_length: u16,
    /// COTP PDU type.
    pub cotp_type: u8,
}

impl Event {
    /// Serialize the event as a single JSON object.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"direction\":\"{}\",\"function_code\":{},\"function_name\":\"{}\",\
             \"rosctr\":{},\"pdu_reference\":{},\"parameter_length\":{},\
             \"data_length\":{},\"cotp_type\":{}}}",
            self.direction.as_str(),
            self.function_code,
            self.function_name,
            self.rosctr,
            self.pdu_reference,
            self.parameter_length,
            self.data_length,
            self.cotp_type,
        )
    }
}

/// Decode every complete frame in `bytes`, stopping at the first error.
pub fn parse_stream(bytes: &[u8]) -> Vec<Result<S7CommFrame, ParseError>> {
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

    /// Documented Read Var job: Merker byte 368, two bytes.
    const READ_VAR: &[u8] = &[
        0x03, 0x00, 0x00, 0x1F, 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x02, 0x6B, 0x00, 0x0E,
        0x00, 0x00, 0x04, 0x01, 0x12, 0x0A, 0x10, 0x02, 0x00, 0x02, 0x00, 0x00, 0x83, 0x00, 0x01,
        0x70,
    ];

    fn write_var() -> Vec<u8> {
        vec![
            0x03, 0x00, 0x00, 0x12, 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x00, 0x05,
        ]
    }

    #[test]
    fn parses_a_read_var_job() {
        let (frame, consumed) = parse_frame(READ_VAR).expect("frame parses");
        assert_eq!(consumed, READ_VAR.len());
        let event = frame.event().expect("event");
        assert_eq!(event.direction, Direction::Request);
        assert_eq!(event.function_code, 0x04);
        assert_eq!(event.function_name, "Read Var");
        assert_eq!(event.pdu_reference, 0x026B);
        assert_eq!(event.parameter_length, 14);
        assert_eq!(event.data_length, 0);
    }

    #[test]
    fn parses_a_write_var_job() {
        let (frame, _) = parse_frame(&write_var()).expect("frame parses");
        let event = frame.event().expect("event");
        assert_eq!(event.function_code, 0x05);
        assert_eq!(event.function_name, "Write Var");
        assert_eq!(event.parameter_length, 1);
        assert!(event.to_json().contains("\"function_code\":5"));
    }

    #[test]
    fn connection_request_has_no_s7_event() {
        // Minimal COTP connection request (CR) with no S7 payload.
        let cr: &[u8] = &[
            0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];
        let (frame, consumed) = parse_frame(cr).expect("frame parses");
        assert_eq!(consumed, cr.len());
        assert_eq!(frame.cotp_type, cotp::PDU_CR);
        assert!(frame.s7.is_none());
        assert!(frame.event().is_none());
    }

    #[test]
    fn rejects_a_bad_tpkt_version() {
        let mut bytes = write_var();
        bytes[0] = 0x02;
        assert_eq!(
            parse_frame(&bytes),
            Err(ParseError::Tpkt(TpktError::BadVersion(0x02)))
        );
    }

    #[test]
    fn reports_an_incomplete_frame() {
        let bytes = write_var();
        assert!(matches!(
            parse_frame(&bytes[..bytes.len() - 1]),
            Err(ParseError::Tpkt(TpktError::Incomplete { .. }))
        ));
    }

    #[test]
    fn parses_multiple_frames_from_a_stream() {
        let mut stream = READ_VAR.to_vec();
        stream.extend_from_slice(&write_var());
        let frames = parse_stream(&stream);
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|frame| frame.is_ok()));
    }

    #[test]
    fn classifies_function_codes() {
        assert!(s7::is_download(s7::function::REQUEST_DOWNLOAD));
        assert!(s7::is_download(s7::function::DOWNLOAD_BLOCK));
        assert!(s7::is_upload(s7::function::START_UPLOAD));
        assert!(s7::is_upload(s7::function::END_UPLOAD));
        assert!(!s7::is_download(s7::function::READ_VAR));
        assert_eq!(s7::function_name(s7::function::PLC_STOP), "PLC Stop");
    }
}
