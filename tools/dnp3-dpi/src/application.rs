//! DNP3 application layer.
//!
//! The application header is an application-control octet followed by a
//! function code. Responses (function 129) and unsolicited responses (function
//! 130) carry two internal-indication octets. Object headers follow.
//!
//! The object layer is decoded far enough to expose the first header's group,
//! variation, qualifier, range/count and (when the qualifier prefixes indexes)
//! the first object index. Additional headers are decoded only when the size of
//! the preceding object bodies is known; otherwise decoding stops after the
//! header that can be decoded safely. No object header is invented when the
//! application PDU carries none, as with Cold Restart.

/// Application confirm function code.
pub const FUNCTION_CONFIRM: u8 = 0;
/// Application read function code.
pub const FUNCTION_READ: u8 = 1;
/// Application write function code.
pub const FUNCTION_WRITE: u8 = 2;
/// Application select function code.
pub const FUNCTION_SELECT: u8 = 3;
/// Application operate function code.
pub const FUNCTION_OPERATE: u8 = 4;
/// Application direct-operate function code.
pub const FUNCTION_DIRECT_OPERATE: u8 = 5;
/// Application direct-operate-no-acknowledgement function code.
pub const FUNCTION_DIRECT_OPERATE_NO_ACK: u8 = 6;
/// Application cold-restart function code.
pub const FUNCTION_COLD_RESTART: u8 = 13;
/// Application warm-restart function code.
pub const FUNCTION_WARM_RESTART: u8 = 14;
/// Application enable-unsolicited function code.
pub const FUNCTION_ENABLE_UNSOLICITED: u8 = 20;
/// Application disable-unsolicited function code.
pub const FUNCTION_DISABLE_UNSOLICITED: u8 = 21;
/// Application response function code.
pub const FUNCTION_RESPONSE: u8 = 129;
/// Application unsolicited-response function code.
pub const FUNCTION_UNSOLICITED_RESPONSE: u8 = 130;

/// Reasons an application PDU could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationError {
    /// The application control/function header is incomplete.
    TruncatedHeader { needed: usize, available: usize },
    /// An object header (group, variation, qualifier) is incomplete.
    TruncatedObjectHeader { needed: usize, available: usize },
    /// The range, index prefix or object body runs past the application bytes.
    TruncatedObjectData { needed: usize, available: usize },
}

impl std::fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplicationError::TruncatedHeader { needed, available } => write!(
                f,
                "application header needs {needed} octets, only {available} available"
            ),
            ApplicationError::TruncatedObjectHeader { needed, available } => write!(
                f,
                "object header needs {needed} octets, only {available} available"
            ),
            ApplicationError::TruncatedObjectData { needed, available } => write!(
                f,
                "object data needs {needed} octets, only {available} available"
            ),
        }
    }
}

impl std::error::Error for ApplicationError {}

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
    /// First object index/point, when one is present in the qualifier range or
    /// index prefix.
    pub index: Option<u32>,
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
    /// Decoded object headers. Empty when the PDU carries no objects.
    pub objects: Vec<ObjectHeader>,
    /// Control code for a binary-output control object (group 12, variation 1),
    /// if present.
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
/// header. Returns an error if the header or a range field is truncated.
pub fn parse(bytes: &[u8]) -> Result<ApplicationHeader, ApplicationError> {
    if bytes.len() < 2 {
        return Err(ApplicationError::TruncatedHeader {
            needed: 2,
            available: bytes.len(),
        });
    }
    let control = bytes[0];
    let function = bytes[1];
    let is_response = matches!(function, FUNCTION_RESPONSE | FUNCTION_UNSOLICITED_RESPONSE);
    let mut offset = 2;
    let iin = if is_response {
        if bytes.len() < 4 {
            return Err(ApplicationError::TruncatedHeader {
                needed: 4,
                available: bytes.len(),
            });
        }
        let value = u16::from_le_bytes([bytes[2], bytes[3]]);
        offset = 4;
        Some(value)
    } else {
        None
    };

    let (objects, control_code) = parse_objects(&bytes[offset..], is_response)?;
    Ok(ApplicationHeader {
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

/// Range and prefix fields decoded from a qualifier octet.
#[derive(Debug, Clone, Copy)]
struct RangeFields {
    count: Option<u32>,
    start: Option<u32>,
}

/// Decode the range field selected by the low nibble of `qualifier`.
///
/// Returns `Ok(None)` for a reserved range code: the object header is still
/// reported, but its range cannot be interpreted and decoding must stop.
fn parse_range(
    qualifier: u8,
    bytes: &[u8],
) -> Result<Option<(RangeFields, usize)>, ApplicationError> {
    let available = bytes.len();
    let range_code = qualifier & 0x0F;

    let (start, stop, width) = match range_code {
        // 1-octet start/stop.
        0 | 3 => {
            if available < 2 {
                return Err(truncated_data(2, available));
            }
            (Some(u32::from(bytes[0])), Some(u32::from(bytes[1])), 2)
        }
        // 2-octet start/stop.
        1 | 4 => {
            if available < 4 {
                return Err(truncated_data(4, available));
            }
            let start = u32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            let stop = u32::from(u16::from_le_bytes([bytes[2], bytes[3]]));
            (Some(start), Some(stop), 4)
        }
        // 4-octet start/stop.
        2 | 5 => {
            if available < 8 {
                return Err(truncated_data(8, available));
            }
            let start = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let stop = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            (Some(start), Some(stop), 8)
        }
        // No range field: all objects.
        6 => {
            return Ok(Some((
                RangeFields {
                    count: None,
                    start: None,
                },
                0,
            )))
        }
        // 1-octet count (range codes 7 and 0xB).
        7 | 0xB => {
            if available < 1 {
                return Err(truncated_data(1, available));
            }
            return Ok(Some((
                RangeFields {
                    count: Some(u32::from(bytes[0])),
                    start: None,
                },
                1,
            )));
        }
        // 2-octet count.
        8 => {
            if available < 2 {
                return Err(truncated_data(2, available));
            }
            return Ok(Some((
                RangeFields {
                    count: Some(u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))),
                    start: None,
                },
                2,
            )));
        }
        // 4-octet count.
        9 => {
            if available < 4 {
                return Err(truncated_data(4, available));
            }
            return Ok(Some((
                RangeFields {
                    count: Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                    start: None,
                },
                4,
            )));
        }
        // Reserved range code.
        _ => return Ok(None),
    };

    let count = match (start, stop) {
        (Some(start), Some(stop)) => Some(count_from_range(start, stop)),
        _ => None,
    };
    Ok(Some((RangeFields { count, start }, width)))
}

/// Number of objects named by a start/stop range, saturating instead of
/// overflowing for the full 32-bit range.
fn count_from_range(start: u32, stop: u32) -> u32 {
    if stop < start {
        return 0;
    }
    stop.checked_sub(start)
        .map_or(u32::MAX, |distance| distance.saturating_add(1))
}

fn truncated_data(needed: usize, available: usize) -> ApplicationError {
    ApplicationError::TruncatedObjectData { needed, available }
}

/// Decode the object headers that follow the application header.
fn parse_objects(
    mut bytes: &[u8],
    is_response: bool,
) -> Result<(Vec<ObjectHeader>, Option<u8>), ApplicationError> {
    let mut objects = Vec::new();
    let mut control_code = None;

    while bytes.len() >= 3 {
        let group = bytes[0];
        let variation = bytes[1];
        let qualifier = bytes[2];

        let Some((range, range_len)) = parse_range(qualifier, &bytes[3..])? else {
            // Reserved range code: report the header but cannot walk further.
            objects.push(ObjectHeader {
                group,
                variation,
                qualifier,
                count: None,
                index: None,
            });
            break;
        };

        let objects_start = 3 + range_len;
        let prefix_code = qualifier >> 4;
        let index_width = match prefix_code {
            1 => 1,
            2 => 2,
            3 => 4,
            _ => 0,
        };

        let mut index = range.start;
        let mut first_object = objects_start;
        if index_width > 0 && range.count != Some(0) {
            let needed = objects_start + index_width;
            if bytes.len() < needed {
                return Err(truncated_data(needed, bytes.len()));
            }
            index = Some(read_uint(&bytes[objects_start..needed]));
            first_object = needed;
        }
        if range.count == Some(0) {
            index = None;
        }

        if group == 12
            && variation == 1
            && range.count != Some(0)
            && matches!(prefix_code, 0..=3)
            && control_code.is_none()
        {
            control_code = bytes.get(first_object).copied();
        }

        objects.push(ObjectHeader {
            group,
            variation,
            qualifier,
            count: range.count,
            index,
        });

        // A zero-count header has no object bodies to walk past.
        if range.count == Some(0) {
            break;
        }

        // Walking to a following header requires knowing the body size. When
        // the variation is not in the table, the first header is still exposed
        // and decoding stops rather than guessing.
        let Some(size) = object_body_size(group, variation, is_response) else {
            break;
        };
        if !matches!(prefix_code, 0..=3) {
            break;
        }
        let total = match range.count {
            Some(count) => {
                let per_object = index_width + size;
                match usize::try_from(count)
                    .ok()
                    .and_then(|count| count.checked_mul(per_object))
                {
                    Some(total) => total,
                    None => break,
                }
            }
            None if size == 0 => 0,
            None => break,
        };
        let next = match objects_start.checked_add(total) {
            Some(next) => next,
            None => break,
        };
        if bytes.len() < next {
            // The header itself is intact; the object body is truncated. Keep
            // the header so the application function and control code remain
            // observable, and stop without reading past the PDU.
            break;
        }
        bytes = &bytes[next..];
    }

    // One or two trailing octets cannot form an object header.
    if !bytes.is_empty() && bytes.len() < 3 {
        return Err(ApplicationError::TruncatedObjectHeader {
            needed: 3,
            available: bytes.len(),
        });
    }

    Ok((objects, control_code))
}

/// Read a little-endian unsigned integer of 1, 2 or 4 octets.
fn read_uint(bytes: &[u8]) -> u32 {
    match bytes {
        [value] => u32::from(*value),
        [low, high] => u32::from(u16::from_le_bytes([*low, *high])),
        [b0, b1, b2, b3] => u32::from_le_bytes([*b0, *b1, *b2, *b3]),
        _ => 0,
    }
}

/// Object body size, excluding any qualifier index prefix.
///
/// Only variations whose wire size is fixed and well known are listed. A
/// `None` return makes the parser stop after the current header; it never
/// guesses an object size for packed or vendor-specific variations.
fn object_body_size(group: u8, variation: u8, is_response: bool) -> Option<usize> {
    match (group, variation) {
        // Class-data requests carry headers but no objects.
        (60, _) if !is_response => Some(0),
        // Binary-output control (CROB): 10 octets, plus a status in responses.
        (12, 1) => Some(if is_response { 11 } else { 10 }),
        // Analog-output control: value plus a status in responses.
        (41, 1) => Some(if is_response { 5 } else { 4 }),
        (41, 2) => Some(if is_response { 3 } else { 2 }),
        (41, 3) => Some(if is_response { 5 } else { 4 }),
        (41, 4) => Some(if is_response { 9 } else { 8 }),
        // Binary input: flags, flags+absolute time, flags+relative time.
        (1, 1) => Some(1),
        (1, 2) => Some(7),
        (1, 3) => Some(3),
        // Double-bit input.
        (3, 1) => Some(1),
        (3, 2) => Some(7),
        (3, 3) => Some(3),
        // Binary output status.
        (10, 1) => Some(1),
        (10, 2) => Some(7),
        // Analog input.
        (30, 1) | (30, 5) => Some(5),
        (30, 2) => Some(3),
        (30, 3) => Some(4),
        (30, 4) => Some(2),
        (30, 6) => Some(9),
        // Analog output status: same variation layout as analog input.
        (40, 1) | (40, 5) => Some(5),
        (40, 2) => Some(3),
        (40, 3) => Some(4),
        (40, 4) => Some(2),
        (40, 6) => Some(9),
        _ => None,
    }
}
