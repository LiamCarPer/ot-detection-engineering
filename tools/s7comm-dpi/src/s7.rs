//! S7 application layer (classic S7comm, protocol id `0x32`).
//!
//! Header layout: protocol id, ROSCTR, redundancy id (2), PDU reference (2),
//! parameter length (2), data length (2), then the parameter block whose first
//! octet is the function code, then the data block.

/// Classic S7comm protocol identifier.
pub const PROTOCOL_ID: u8 = 0x32;
/// Fixed header size before the parameter block.
pub const HEADER_LEN: usize = 10;

/// S7comm function codes.
pub mod function {
    pub const CPU_SERVICES: u8 = 0x00;
    pub const READ_VAR: u8 = 0x04;
    pub const WRITE_VAR: u8 = 0x05;
    pub const REQUEST_DOWNLOAD: u8 = 0x1A;
    pub const DOWNLOAD_BLOCK: u8 = 0x1B;
    pub const DOWNLOAD_ENDED: u8 = 0x1C;
    pub const START_UPLOAD: u8 = 0x1D;
    pub const UPLOAD: u8 = 0x1E;
    pub const END_UPLOAD: u8 = 0x1F;
    pub const PLC_CONTROL: u8 = 0x28;
    pub const PLC_STOP: u8 = 0x29;
    pub const SETUP_COMMUNICATION: u8 = 0xF0;
}

/// Decoded S7 header and function code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S7Header {
    /// Remote operating service control (message type).
    pub rosctr: u8,
    /// PDU reference.
    pub pdu_reference: u16,
    /// Parameter block length.
    pub parameter_length: u16,
    /// Data block length.
    pub data_length: u16,
    /// Function code (first octet of the parameter block).
    pub function: u8,
}

/// Human-readable function name.
pub fn function_name(function: u8) -> &'static str {
    match function {
        function::CPU_SERVICES => "CPU Services",
        function::READ_VAR => "Read Var",
        function::WRITE_VAR => "Write Var",
        function::REQUEST_DOWNLOAD => "Request Download",
        function::DOWNLOAD_BLOCK => "Download Block",
        function::DOWNLOAD_ENDED => "Download Ended",
        function::START_UPLOAD => "Start Upload",
        function::UPLOAD => "Upload",
        function::END_UPLOAD => "End Upload",
        function::PLC_CONTROL => "PLC Control",
        function::PLC_STOP => "PLC Stop",
        function::SETUP_COMMUNICATION => "Setup Communication",
        _ => "Unknown",
    }
}

/// True for a function that downloads a program block to the controller.
pub fn is_download(function: u8) -> bool {
    matches!(
        function,
        function::REQUEST_DOWNLOAD | function::DOWNLOAD_BLOCK | function::DOWNLOAD_ENDED
    )
}

/// True for a function that uploads a program block from the controller.
pub fn is_upload(function: u8) -> bool {
    matches!(
        function,
        function::START_UPLOAD | function::UPLOAD | function::END_UPLOAD
    )
}

/// Decode the S7 header from the octets that follow the COTP header.
pub fn parse(bytes: &[u8]) -> Option<S7Header> {
    if bytes.len() < HEADER_LEN || bytes[0] != PROTOCOL_ID {
        return None;
    }
    Some(S7Header {
        rosctr: bytes[1],
        pdu_reference: u16::from_be_bytes([bytes[4], bytes[5]]),
        parameter_length: u16::from_be_bytes([bytes[6], bytes[7]]),
        data_length: u16::from_be_bytes([bytes[8], bytes[9]]),
        function: bytes[HEADER_LEN],
    })
}
