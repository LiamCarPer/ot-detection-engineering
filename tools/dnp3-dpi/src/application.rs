//! DNP3 application layer.
//!
//! The application header is an application-control octet followed by a
//! function code. Responses (function 129) and unsolicited responses (function
//! 130) carry two internal-indication octets. Object headers follow.
//!
//! Only the first object header is decoded: continuing past it requires
//! variation-specific object sizes, which is out of scope for a DPI telemetry
//! layer. That first header is enough to distinguish control objects
//! (group 12, binary output; group 41, analog output) from monitoring data.

/// Application response function code.
pub const FUNCTION_RESPONSE: u8 = 129;
/// Application unsolicited-response function code.
pub const FUNCTION_UNSOLICITED_RESPONSE: u8 = 130;

/// Decoded object header prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Object group.
    pub group: u8,
    /// Object variation.
    pub variation: u8,
    /// Raw qualifier octet.
    pub qualifier: u8,
    /// Number of objects, when the qualifier encodes a count or range.
    pub count: Option<u32>,
}

/// Decoded application header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationHeader {
    /// Final fragment.
    pub fin: bool,
    /// First fragment.
    pub fir: bool,
    /// Confirmation requested.
    pub con: bool,
    /// Unsolicited response.
    pub uns: bool,
    /// Application sequence number (0-15).
    pub sequence: u8,
    /// Application function code.
    pub function: u8,
    /// Internal indications, present on responses.
    pub iin: Option<u16>,
    /// Decoded object headers (first header only).
    pub objects: Vec<ObjectHeader>,
    /// Control code for a binary-output control object (group 12), if present.
    pub control_code: Option<u8>,
}

/// Human-readable application function name.
pub fn function_name(function: u8) -> &'static str {
    match function {
        0 => "Confirm",
        1 => "Read",
        2 => "Write",
        3 => "Select",
        4 => "Operate",
        5 => "Direct Operate",
        6 => "Direct Operate No Ack",
        7 => "Immediate Freeze",
        8 => "Immediate Freeze No Ack",
        9 => "Freeze and Clear",
        10 => "Freeze and Clear No Ack",
        11 => "Freeze with Time",
        12 => "Freeze with Time No Ack",
        13 => "Cold Restart",
        14 => "Warm Restart",
        15 => "Initialize Data",
        16 => "Initialize Application",
        17 => "Start Application",
        18 => "Stop Application",
        19 => "Save Configuration",
        20 => "Enable Unsolicited",
        21 => "Disable Unsolicited",
        22 => "Assign Class",
        23 => "Delay Measure",
        24 => "Record Current Time",
        25 => "Open File",
        26 => "Close File",
        27 => "Delete File",
        28 => "Get File Info",
        29 => "Authenticate File",
        30 => "Abort File",
        129 => "Response",
        130 => "Unsolicited Response",
        _ => "Reserved",
    }
}

/// Decode the application layer from the octets that follow the transport
/// header. Returns `None` if the buffer is too short to hold a header.
pub fn parse(bytes: &[u8]) -> Option<ApplicationHeader> {
    if bytes.len() < 2 {
        return None;
    }
    let control = bytes[0];
    let function = bytes[1];
    let mut offset = 2;
    let iin = if function == FUNCTION_RESPONSE || function == FUNCTION_UNSOLICITED_RESPONSE {
        if bytes.len() < 4 {
            return None;
        }
        let value = u16::from_le_bytes([bytes[2], bytes[3]]);
        offset = 4;
        Some(value)
    } else {
        None
    };

    let (objects, control_code) = parse_objects(&bytes[offset..]);
    Some(ApplicationHeader {
        fin: control & 0x40 != 0,
        fir: control & 0x80 != 0,
        con: control & 0x20 != 0,
        uns: control & 0x10 != 0,
        sequence: control & 0x0F,
        function,
        iin,
        objects,
        control_code,
    })
}

fn parse_objects(mut bytes: &[u8]) -> (Vec<ObjectHeader>, Option<u8>) {
    let mut objects = Vec::new();
    let mut control_code = None;
    if bytes.len() < 3 {
        return (objects, control_code);
    }

    let group = bytes[0];
    let variation = bytes[1];
    let qualifier = bytes[2];
    bytes = &bytes[3..];

    let prefix = qualifier >> 4;
    let count = match prefix {
        0 if bytes.len() >= 2 => {
            let start = u32::from(bytes[0]);
            let stop = u32::from(bytes[1]);
            bytes = &bytes[2..];
            Some(stop.saturating_sub(start) + 1)
        }
        1 if bytes.len() >= 4 => {
            let start = u32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            let stop = u32::from(u16::from_le_bytes([bytes[2], bytes[3]]));
            bytes = &bytes[4..];
            Some(stop.saturating_sub(start) + 1)
        }
        2 if bytes.len() >= 8 => {
            let start = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let stop = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            bytes = &bytes[8..];
            Some(stop.saturating_sub(start) + 1)
        }
        3 if !bytes.is_empty() => {
            let value = u32::from(bytes[0]);
            bytes = &bytes[1..];
            Some(value)
        }
        4 if bytes.len() >= 2 => {
            let value = u32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            bytes = &bytes[2..];
            Some(value)
        }
        5 if bytes.len() >= 4 => {
            let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            bytes = &bytes[4..];
            Some(value)
        }
        6 => Some(0),
        _ => None,
    };

    if group == 12 {
        control_code = bytes.first().copied();
    }

    objects.push(ObjectHeader {
        group,
        variation,
        qualifier,
        count,
    });
    (objects, control_code)
}
