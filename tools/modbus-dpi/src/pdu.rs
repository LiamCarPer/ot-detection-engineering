//! Modbus/TCP PDU decoding.
//!
//! The decoder understands the function codes used by OT detections: coil and
//! register reads, single and multiple writes, mask writes, read/write
//! multiple registers and Read Device Identification (MEI type 14). Anything
//! else is surfaced as `Unsupported` with a structured decode error rather
//! than being dropped.

use std::fmt;

/// Modbus function code for Read Coils.
pub const READ_COILS: u8 = 1;
/// Modbus function code for Read Discrete Inputs.
pub const READ_DISCRETE_INPUTS: u8 = 2;
/// Modbus function code for Read Holding Registers.
pub const READ_HOLDING_REGISTERS: u8 = 3;
/// Modbus function code for Read Input Registers.
pub const READ_INPUT_REGISTERS: u8 = 4;
/// Modbus function code for Write Single Coil.
pub const WRITE_SINGLE_COIL: u8 = 5;
/// Modbus function code for Write Single Register.
pub const WRITE_SINGLE_REGISTER: u8 = 6;
/// Modbus function code for Write Multiple Coils.
pub const WRITE_MULTIPLE_COILS: u8 = 15;
/// Modbus function code for Write Multiple Registers.
pub const WRITE_MULTIPLE_REGISTERS: u8 = 16;
/// Modbus function code for Mask Write Register.
pub const MASK_WRITE_REGISTER: u8 = 22;
/// Modbus function code for Read/Write Multiple Registers.
pub const READ_WRITE_MULTIPLE_REGISTERS: u8 = 23;
/// Modbus function code for Read Device Identification.
pub const READ_DEVICE_IDENTIFICATION: u8 = 43;

/// Modbus encapsulation interface transport type for Read Device Identification.
pub const MEI_TYPE_READ_DEVICE_ID: u8 = 0x0E;

/// Maximum read quantity for coils and discrete inputs.
pub const MAX_READ_BITS: u16 = 2000;
/// Maximum read quantity for holding and input registers.
pub const MAX_READ_REGISTERS: u16 = 125;
/// Maximum write quantity for coils.
pub const MAX_WRITE_COILS: u16 = 1968;
/// Maximum write quantity for registers.
pub const MAX_WRITE_REGISTERS: u16 = 123;
/// Maximum write quantity on the write half of Read/Write Multiple Registers.
pub const MAX_WRITE_REGISTERS_FC23: u16 = 121;

/// Direction of a Modbus message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Direction {
    /// A request from a client to a server.
    #[default]
    Request,
    /// A response, including an exception response, from a server.
    Response,
}

impl Direction {
    /// Lowercase label used in the normalized event.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// Human-readable name for a supported Modbus function code.
pub fn function_name(function: u8) -> &'static str {
    match function {
        READ_COILS => "Read Coils",
        READ_DISCRETE_INPUTS => "Read Discrete Inputs",
        READ_HOLDING_REGISTERS => "Read Holding Registers",
        READ_INPUT_REGISTERS => "Read Input Registers",
        WRITE_SINGLE_COIL => "Write Single Coil",
        WRITE_SINGLE_REGISTER => "Write Single Register",
        WRITE_MULTIPLE_COILS => "Write Multiple Coils",
        WRITE_MULTIPLE_REGISTERS => "Write Multiple Registers",
        MASK_WRITE_REGISTER => "Mask Write Register",
        READ_WRITE_MULTIPLE_REGISTERS => "Read/Write Multiple Registers",
        READ_DEVICE_IDENTIFICATION => "Read Device Identification",
        _ => "Unsupported",
    }
}

/// One object returned by Read Device Identification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdObject {
    /// Object identifier (0 vendor, 1 product code, 2 revision, ...).
    pub object_id: u8,
    /// Length of the value in octets.
    pub length: u8,
    /// Object value decoded as UTF-8 (lossy).
    pub value: String,
}

/// Reasons a PDU could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The PDU is empty, so there is no function code.
    EmptyPdu,
    /// The function code is reserved or not implemented by this decoder.
    UnsupportedFunction(u8),
    /// The PDU is shorter than the function code requires.
    TruncatedPdu {
        function: u8,
        needed: usize,
        available: usize,
    },
    /// A quantity is zero or above the protocol limit for the function.
    InvalidQuantity {
        function: u8,
        quantity: u16,
        max: u16,
    },
    /// `register + quantity` runs past the 16-bit address space.
    AddressOverflow { register: u16, quantity: u16 },
    /// A byte count in the PDU does not match the quantity or payload.
    ByteCountMismatch {
        function: u8,
        declared: u8,
        expected: usize,
    },
    /// Write Single Coil carries a value other than `0x0000` or `0xFF00`.
    InvalidCoilValue(u16),
    /// Read Device Identification used a MEI type other than 14.
    InvalidMeiType(u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::EmptyPdu => write!(f, "empty PDU: no function code"),
            DecodeError::UnsupportedFunction(function) => {
                write!(f, "unsupported function code {function} (0x{function:02X})")
            }
            DecodeError::TruncatedPdu {
                function,
                needed,
                available,
            } => write!(
                f,
                "truncated PDU for function {function}: need {needed} octets, have {available}"
            ),
            DecodeError::InvalidQuantity {
                function,
                quantity,
                max,
            } => write!(
                f,
                "invalid quantity {quantity} for function {function}: expected 1..={max}"
            ),
            DecodeError::AddressOverflow { register, quantity } => {
                write!(f, "register range {register}+{quantity} runs past 65535")
            }
            DecodeError::ByteCountMismatch {
                function,
                declared,
                expected,
            } => write!(
                f,
                "byte count {declared} for function {function} does not match expected {expected}"
            ),
            DecodeError::InvalidCoilValue(value) => write!(
                f,
                "invalid Write Single Coil value 0x{value:04X}, expected 0x0000 or 0xFF00"
            ),
            DecodeError::InvalidMeiType(mei) => write!(
                f,
                "invalid MEI type 0x{mei:02X}, expected 0x0E for Read Device Identification"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Protocol fields decoded from one Modbus PDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecodedPdu {
    /// Request or response.
    pub direction: Direction,
    /// Function code with any exception bit removed.
    pub function_code: u8,
    /// Raw function-code octet, only when it differs (exception responses).
    pub raw_function_code: Option<u8>,
    /// Function name, or `Unsupported`.
    pub function_name: &'static str,
    /// Exception code for an exception response.
    pub exception_code: Option<u8>,
    /// Starting register for FC3/4/6/16/22/23 (and the read half of FC23).
    pub register: Option<u16>,
    /// Register quantity for FC3/4/16/23 and coil quantity for FC1/2/15.
    pub quantity: Option<u16>,
    /// Written value for FC5/6/16/23 where it is derivable from the frame.
    pub value: Option<u32>,
    /// Register values for multi-register reads and writes.
    pub values: Vec<u16>,
    /// Coil values for FC1/2/5/15.
    pub coils: Vec<bool>,
    /// Byte count carried by a read response or a multiple write request.
    pub byte_count: Option<u16>,
    /// AND mask for FC22.
    pub and_mask: Option<u16>,
    /// OR mask for FC22.
    pub or_mask: Option<u16>,
    /// Write starting register for the write half of FC23.
    pub write_register: Option<u16>,
    /// Write quantity for the write half of FC23.
    pub write_quantity: Option<u16>,
    /// MEI type for FC43.
    pub mei_type: Option<u8>,
    /// Read Device Identification read code for FC43.
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
    pub objects: Vec<DeviceIdObject>,
    /// Structured error for a PDU that was surfaced instead of decoded.
    pub decode_error: Option<String>,
}

impl DecodedPdu {
    fn new(function: u8, direction: Direction) -> Self {
        DecodedPdu {
            direction,
            function_code: function,
            function_name: function_name(function),
            ..DecodedPdu::default()
        }
    }
}

/// Classify a PDU as a request or a response.
///
/// Modbus has no direction bit, so this is a shape heuristic. Requests and
/// responses for FC5, FC6 and FC22 are byte-identical, so those default to
/// `Request`; a caller that sees both sides of a TCP connection knows the real
/// direction from the endpoint.
pub fn infer_direction(function: u8, pdu: &[u8]) -> Direction {
    if function & 0x80 != 0 {
        return Direction::Response;
    }
    match function {
        READ_COILS | READ_DISCRETE_INPUTS | READ_HOLDING_REGISTERS | READ_INPUT_REGISTERS => {
            if pdu.len() == 5 {
                Direction::Request
            } else if response_byte_count_matches(pdu) {
                Direction::Response
            } else {
                Direction::Request
            }
        }
        WRITE_MULTIPLE_COILS | WRITE_MULTIPLE_REGISTERS => {
            if pdu.len() == 5 {
                Direction::Response
            } else {
                Direction::Request
            }
        }
        READ_WRITE_MULTIPLE_REGISTERS => {
            if read_write_request_shape(pdu) {
                Direction::Request
            } else if response_byte_count_matches(pdu) {
                Direction::Response
            } else {
                Direction::Request
            }
        }
        READ_DEVICE_IDENTIFICATION => {
            if pdu.len() == 4 {
                Direction::Request
            } else {
                Direction::Response
            }
        }
        _ => Direction::Request,
    }
}

/// Decode one Modbus PDU.
pub fn decode(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = *pdu.first().ok_or(DecodeError::EmptyPdu)?;
    if function & 0x80 != 0 {
        return decode_exception(pdu);
    }
    match function {
        READ_COILS | READ_DISCRETE_INPUTS => decode_read_bits(function, pdu),
        READ_HOLDING_REGISTERS | READ_INPUT_REGISTERS => decode_read_registers(function, pdu),
        WRITE_SINGLE_COIL => decode_write_single_coil(pdu),
        WRITE_SINGLE_REGISTER => decode_write_single_register(pdu),
        WRITE_MULTIPLE_COILS => decode_write_multiple_coils(pdu),
        WRITE_MULTIPLE_REGISTERS => decode_write_multiple_registers(pdu),
        MASK_WRITE_REGISTER => decode_mask_write_register(pdu),
        READ_WRITE_MULTIPLE_REGISTERS => decode_read_write_multiple_registers(pdu),
        READ_DEVICE_IDENTIFICATION => decode_read_device_identification(pdu),
        other => Err(DecodeError::UnsupportedFunction(other)),
    }
}

/// Build a structured error event for a PDU that failed to decode.
pub fn error_event(pdu: &[u8], error: &DecodeError) -> DecodedPdu {
    let raw_function = pdu.first().copied().unwrap_or(0);
    let function = raw_function & 0x7F;
    let direction = if raw_function & 0x80 != 0 {
        Direction::Response
    } else {
        infer_direction(raw_function, pdu)
    };
    let mut info = DecodedPdu::new(function, direction);
    info.decode_error = Some(error.to_string());
    if direction == Direction::Response && raw_function & 0x80 != 0 {
        info.raw_function_code = Some(raw_function);
    }
    info
}

fn decode_exception(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let raw_function = pdu[0];
    if pdu.len() < 2 {
        return Err(DecodeError::TruncatedPdu {
            function: raw_function,
            needed: 2,
            available: pdu.len(),
        });
    }
    let function = raw_function & 0x7F;
    let mut info = DecodedPdu::new(function, Direction::Response);
    info.raw_function_code = Some(raw_function);
    info.exception_code = Some(pdu[1]);
    if function_name(function) == "Unsupported" {
        info.decode_error = Some(DecodeError::UnsupportedFunction(function).to_string());
    }
    Ok(info)
}

fn decode_read_bits(function: u8, pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    if infer_direction(function, pdu) == Direction::Request {
        need(pdu, 5, function)?;
        let register = read_u16(pdu, 1, function)?;
        let quantity = read_u16(pdu, 3, function)?;
        check_quantity(function, quantity, MAX_READ_BITS)?;
        check_range(register, quantity)?;
        let mut info = DecodedPdu::new(function, Direction::Request);
        info.register = Some(register);
        info.quantity = Some(quantity);
        return Ok(info);
    }

    need(pdu, 2, function)?;
    let byte_count = pdu[1];
    let data = &pdu[2..];
    check_byte_count(function, byte_count, data.len())?;
    let bits = u16::from(byte_count) * 8;
    if bits == 0 || bits > MAX_READ_BITS {
        return Err(DecodeError::InvalidQuantity {
            function,
            quantity: bits,
            max: MAX_READ_BITS,
        });
    }
    let mut info = DecodedPdu::new(function, Direction::Response);
    info.byte_count = Some(u16::from(byte_count));
    info.quantity = Some(u16::from(byte_count) * 8);
    info.coils = bits_to_coils(data, data.len() * 8);
    Ok(info)
}

fn decode_read_registers(function: u8, pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    if infer_direction(function, pdu) == Direction::Request {
        need(pdu, 5, function)?;
        let register = read_u16(pdu, 1, function)?;
        let quantity = read_u16(pdu, 3, function)?;
        check_quantity(function, quantity, MAX_READ_REGISTERS)?;
        check_range(register, quantity)?;
        let mut info = DecodedPdu::new(function, Direction::Request);
        info.register = Some(register);
        info.quantity = Some(quantity);
        return Ok(info);
    }

    need(pdu, 2, function)?;
    let byte_count = pdu[1];
    let data = &pdu[2..];
    check_byte_count(function, byte_count, data.len())?;
    if byte_count == 0 {
        return Err(DecodeError::InvalidQuantity {
            function,
            quantity: 0,
            max: MAX_READ_REGISTERS,
        });
    }
    if !byte_count.is_multiple_of(2) {
        return Err(DecodeError::ByteCountMismatch {
            function,
            declared: byte_count,
            expected: usize::from(byte_count).div_ceil(2) * 2,
        });
    }
    let values = registers(data);
    if values.len() > usize::from(MAX_READ_REGISTERS) {
        return Err(DecodeError::InvalidQuantity {
            function,
            quantity: values.len() as u16,
            max: MAX_READ_REGISTERS,
        });
    }
    let mut info = DecodedPdu::new(function, Direction::Response);
    info.byte_count = Some(u16::from(byte_count));
    info.quantity = Some(values.len() as u16);
    info.values = values;
    Ok(info)
}

fn decode_write_single_coil(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = WRITE_SINGLE_COIL;
    need(pdu, 5, function)?;
    let register = read_u16(pdu, 1, function)?;
    let raw = read_u16(pdu, 3, function)?;
    let on = match raw {
        0x0000 => false,
        0xFF00 => true,
        _ => return Err(DecodeError::InvalidCoilValue(raw)),
    };
    // A response echoes the request byte-for-byte, so a bare frame cannot be
    // classified further than "request".
    let mut info = DecodedPdu::new(function, Direction::Request);
    info.register = Some(register);
    info.value = Some(u32::from(on));
    info.coils = vec![on];
    Ok(info)
}

fn decode_write_single_register(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = WRITE_SINGLE_REGISTER;
    need(pdu, 5, function)?;
    let register = read_u16(pdu, 1, function)?;
    let value = read_u16(pdu, 3, function)?;
    let mut info = DecodedPdu::new(function, Direction::Request);
    info.register = Some(register);
    info.value = Some(u32::from(value));
    Ok(info)
}

fn decode_write_multiple_coils(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = WRITE_MULTIPLE_COILS;
    if infer_direction(function, pdu) == Direction::Response {
        need(pdu, 5, function)?;
        let register = read_u16(pdu, 1, function)?;
        let quantity = read_u16(pdu, 3, function)?;
        check_quantity(function, quantity, MAX_WRITE_COILS)?;
        check_range(register, quantity)?;
        let mut info = DecodedPdu::new(function, Direction::Response);
        info.register = Some(register);
        info.quantity = Some(quantity);
        return Ok(info);
    }

    need(pdu, 6, function)?;
    let register = read_u16(pdu, 1, function)?;
    let quantity = read_u16(pdu, 3, function)?;
    let byte_count = pdu[5];
    check_quantity(function, quantity, MAX_WRITE_COILS)?;
    check_range(register, quantity)?;
    let expected = usize::from(quantity).div_ceil(8);
    check_byte_count(function, byte_count, expected)?;
    need(pdu, 6 + usize::from(byte_count), function)?;
    let data = &pdu[6..6 + usize::from(byte_count)];
    let mut info = DecodedPdu::new(function, Direction::Request);
    info.register = Some(register);
    info.quantity = Some(quantity);
    info.byte_count = Some(u16::from(byte_count));
    info.coils = bits_to_coils(data, usize::from(quantity));
    Ok(info)
}

fn decode_write_multiple_registers(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = WRITE_MULTIPLE_REGISTERS;
    if infer_direction(function, pdu) == Direction::Response {
        need(pdu, 5, function)?;
        let register = read_u16(pdu, 1, function)?;
        let quantity = read_u16(pdu, 3, function)?;
        check_quantity(function, quantity, MAX_WRITE_REGISTERS)?;
        check_range(register, quantity)?;
        let mut info = DecodedPdu::new(function, Direction::Response);
        info.register = Some(register);
        info.quantity = Some(quantity);
        return Ok(info);
    }

    need(pdu, 6, function)?;
    let register = read_u16(pdu, 1, function)?;
    let quantity = read_u16(pdu, 3, function)?;
    let byte_count = pdu[5];
    check_quantity(function, quantity, MAX_WRITE_REGISTERS)?;
    check_range(register, quantity)?;
    let expected = usize::from(quantity) * 2;
    check_byte_count(function, byte_count, expected)?;
    need(pdu, 6 + usize::from(byte_count), function)?;
    let values = registers(&pdu[6..6 + usize::from(byte_count)]);
    let mut info = DecodedPdu::new(function, Direction::Request);
    info.register = Some(register);
    info.quantity = Some(quantity);
    info.byte_count = Some(u16::from(byte_count));
    info.value = values.first().copied().map(u32::from);
    info.values = values;
    Ok(info)
}

fn decode_mask_write_register(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = MASK_WRITE_REGISTER;
    need(pdu, 7, function)?;
    let register = read_u16(pdu, 1, function)?;
    let and_mask = read_u16(pdu, 3, function)?;
    let or_mask = read_u16(pdu, 5, function)?;
    // The written value depends on the register's current contents, which the
    // frame does not carry, so no `value` is invented here.
    let mut info = DecodedPdu::new(function, Direction::Request);
    info.register = Some(register);
    info.and_mask = Some(and_mask);
    info.or_mask = Some(or_mask);
    Ok(info)
}

fn decode_read_write_multiple_registers(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = READ_WRITE_MULTIPLE_REGISTERS;
    if infer_direction(function, pdu) == Direction::Response {
        need(pdu, 2, function)?;
        let byte_count = pdu[1];
        let data = &pdu[2..];
        check_byte_count(function, byte_count, data.len())?;
        if byte_count == 0 {
            return Err(DecodeError::InvalidQuantity {
                function,
                quantity: 0,
                max: MAX_READ_REGISTERS,
            });
        }
        if !byte_count.is_multiple_of(2) {
            return Err(DecodeError::ByteCountMismatch {
                function,
                declared: byte_count,
                expected: usize::from(byte_count).div_ceil(2) * 2,
            });
        }
        let values = registers(data);
        if values.len() > usize::from(MAX_READ_REGISTERS) {
            return Err(DecodeError::InvalidQuantity {
                function,
                quantity: values.len() as u16,
                max: MAX_READ_REGISTERS,
            });
        }
        let mut info = DecodedPdu::new(function, Direction::Response);
        info.byte_count = Some(u16::from(byte_count));
        info.quantity = Some(values.len() as u16);
        info.values = values;
        return Ok(info);
    }

    need(pdu, 10, function)?;
    let read_register = read_u16(pdu, 1, function)?;
    let read_quantity = read_u16(pdu, 3, function)?;
    let write_register = read_u16(pdu, 5, function)?;
    let write_quantity = read_u16(pdu, 7, function)?;
    let byte_count = pdu[9];
    check_quantity(function, read_quantity, MAX_READ_REGISTERS)?;
    check_quantity(function, write_quantity, MAX_WRITE_REGISTERS_FC23)?;
    check_range(read_register, read_quantity)?;
    check_range(write_register, write_quantity)?;
    let expected = usize::from(write_quantity) * 2;
    check_byte_count(function, byte_count, expected)?;
    need(pdu, 10 + usize::from(byte_count), function)?;
    let values = registers(&pdu[10..10 + usize::from(byte_count)]);
    let mut info = DecodedPdu::new(function, Direction::Request);
    info.register = Some(read_register);
    info.quantity = Some(read_quantity);
    info.write_register = Some(write_register);
    info.write_quantity = Some(write_quantity);
    info.byte_count = Some(u16::from(byte_count));
    info.value = values.first().copied().map(u32::from);
    info.values = values;
    Ok(info)
}

fn decode_read_device_identification(pdu: &[u8]) -> Result<DecodedPdu, DecodeError> {
    let function = READ_DEVICE_IDENTIFICATION;
    need(pdu, 4, function)?;
    let mei_type = pdu[1];
    if mei_type != MEI_TYPE_READ_DEVICE_ID {
        return Err(DecodeError::InvalidMeiType(mei_type));
    }

    let direction = infer_direction(function, pdu);
    if direction == Direction::Request {
        let mut info = DecodedPdu::new(function, Direction::Request);
        info.mei_type = Some(mei_type);
        info.read_device_id_code = Some(pdu[2]);
        info.object_id = Some(pdu[3]);
        return Ok(info);
    }

    need(pdu, 7, function)?;
    let object_count = pdu[6];
    let mut offset = 7;
    let mut objects = Vec::new();
    for _ in 0..object_count {
        need(pdu, offset + 2, function)?;
        let object_id = pdu[offset];
        let length = pdu[offset + 1];
        offset += 2;
        need(pdu, offset + usize::from(length), function)?;
        let value = String::from_utf8_lossy(&pdu[offset..offset + usize::from(length)]).into();
        offset += usize::from(length);
        objects.push(DeviceIdObject {
            object_id,
            length,
            value,
        });
    }

    let mut info = DecodedPdu::new(function, Direction::Response);
    info.mei_type = Some(mei_type);
    info.read_device_id_code = Some(pdu[2]);
    info.conformity_level = Some(pdu[3]);
    info.more_follows = Some(pdu[4] != 0);
    info.next_object_id = Some(pdu[5]);
    info.object_id = objects.first().map(|object| object.object_id);
    info.objects = objects;
    Ok(info)
}

/// Whether the PDU has the shape of a read response: byte count then payload.
fn response_byte_count_matches(pdu: &[u8]) -> bool {
    pdu.len() >= 2 && usize::from(pdu[1]) == pdu.len() - 2
}

/// Whether an FC23 PDU has the fixed request shape.
fn read_write_request_shape(pdu: &[u8]) -> bool {
    if pdu.len() < 10 {
        return false;
    }
    let byte_count = usize::from(pdu[9]);
    let write_quantity = u16::from_be_bytes([pdu[7], pdu[8]]);
    byte_count.is_multiple_of(2)
        && usize::from(write_quantity) * 2 == byte_count
        && pdu.len() == 10 + byte_count
}

fn need(pdu: &[u8], needed: usize, function: u8) -> Result<(), DecodeError> {
    if pdu.len() < needed {
        return Err(DecodeError::TruncatedPdu {
            function,
            needed,
            available: pdu.len(),
        });
    }
    Ok(())
}

fn read_u16(pdu: &[u8], offset: usize, function: u8) -> Result<u16, DecodeError> {
    need(pdu, offset + 2, function)?;
    Ok(u16::from_be_bytes([pdu[offset], pdu[offset + 1]]))
}

fn check_quantity(function: u8, quantity: u16, max: u16) -> Result<(), DecodeError> {
    if quantity == 0 || quantity > max {
        return Err(DecodeError::InvalidQuantity {
            function,
            quantity,
            max,
        });
    }
    Ok(())
}

fn check_range(register: u16, quantity: u16) -> Result<(), DecodeError> {
    // `quantity` is validated as non-zero before this is called. A range is
    // valid when the last addressed unit is still inside 0..=65535.
    if u32::from(register) + u32::from(quantity) > 0x1_0000 {
        return Err(DecodeError::AddressOverflow { register, quantity });
    }
    Ok(())
}

fn check_byte_count(function: u8, declared: u8, available: usize) -> Result<(), DecodeError> {
    if usize::from(declared) != available {
        return Err(DecodeError::ByteCountMismatch {
            function,
            declared,
            expected: available,
        });
    }
    Ok(())
}

fn registers(data: &[u8]) -> Vec<u16> {
    data.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect()
}

fn bits_to_coils(data: &[u8], count: usize) -> Vec<bool> {
    (0..count)
        .map(|index| {
            data.get(index / 8)
                .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_directions() {
        // FC3 request: five octets, fixed shape.
        assert_eq!(infer_direction(3, &[3, 0, 0, 0, 10]), Direction::Request);
        // FC3 response: byte count matches the payload.
        assert_eq!(infer_direction(3, &[3, 4, 0, 1, 0, 2]), Direction::Response);
        // FC16 response is the five-octet echo.
        assert_eq!(infer_direction(16, &[16, 0, 0, 0, 2]), Direction::Response);
        // Exception bit forces a response.
        assert_eq!(infer_direction(0x83, &[0x83, 2]), Direction::Response);
    }

    #[test]
    fn decodes_an_exception_response() {
        let info = decode(&[0x83, 0x02]).expect("exception decodes");
        assert_eq!(info.direction, Direction::Response);
        assert_eq!(info.function_code, 3);
        assert_eq!(info.function_name, "Read Holding Registers");
        assert_eq!(info.exception_code, Some(2));
        assert!(info.decode_error.is_none());
    }

    #[test]
    fn rejects_a_short_exception() {
        assert_eq!(
            decode(&[0x83]),
            Err(DecodeError::TruncatedPdu {
                function: 0x83,
                needed: 2,
                available: 1
            })
        );
    }

    #[test]
    fn rejects_a_quantity_above_the_protocol_limit() {
        assert_eq!(
            decode(&[3, 0, 0, 0x01, 0x00]),
            Err(DecodeError::InvalidQuantity {
                function: 3,
                quantity: 256,
                max: 125
            })
        );
    }

    #[test]
    fn rejects_zero_quantity() {
        assert_eq!(
            decode(&[1, 0, 0, 0, 0]),
            Err(DecodeError::InvalidQuantity {
                function: 1,
                quantity: 0,
                max: MAX_READ_BITS
            })
        );
    }

    #[test]
    fn rejects_an_address_range_that_overflows() {
        assert_eq!(
            decode(&[3, 0xFF, 0xFF, 0, 2]),
            Err(DecodeError::AddressOverflow {
                register: 0xFFFF,
                quantity: 2
            })
        );
    }

    #[test]
    fn accepts_a_block_write_that_ends_inside_the_address_space() {
        let mut pdu = vec![16, 0x0F, 0x9F, 0x00, 0x0A, 20];
        for value in 0u16..10 {
            pdu.extend_from_slice(&value.to_be_bytes());
        }
        let info = decode(&pdu).expect("write decodes");
        assert_eq!(info.register, Some(3999));
        assert_eq!(info.quantity, Some(10));
        assert_eq!(info.value, Some(0));
        assert_eq!(info.values.len(), 10);
    }

    #[test]
    fn rejects_a_short_fc16_payload() {
        // Quantity says 2 registers (four data octets) but only two follow.
        assert_eq!(
            decode(&[16, 0, 1, 0, 2, 4, 0, 1]),
            Err(DecodeError::TruncatedPdu {
                function: 16,
                needed: 10,
                available: 8
            })
        );
    }

    #[test]
    fn rejects_a_fc43_wrong_mei_type() {
        assert_eq!(
            decode(&[43, 0x0D, 1, 0]),
            Err(DecodeError::InvalidMeiType(0x0D))
        );
    }

    #[test]
    fn surfaces_an_unknown_function() {
        assert_eq!(decode(&[7]), Err(DecodeError::UnsupportedFunction(7)));
        let info = error_event(&[7], &DecodeError::UnsupportedFunction(7));
        assert_eq!(info.function_name, "Unsupported");
        assert_eq!(info.direction, Direction::Request);
        assert!(info.decode_error.is_some());
    }

    #[test]
    fn decodes_device_identification_objects() {
        // Read code 1, conformity 1, no more follows, three objects.
        let pdu = [
            43, 0x0E, 1, 1, 0, 0, 3, 0, 2, b'A', b'c', 1, 1, b'1', 2, 2, b'2', b'.',
        ];
        let info = decode(&pdu).expect("device id decodes");
        assert_eq!(info.direction, Direction::Response);
        assert_eq!(info.conformity_level, Some(1));
        assert_eq!(info.more_follows, Some(false));
        assert_eq!(info.objects.len(), 3);
        assert_eq!(info.objects[1].value, "1");
    }

    #[test]
    fn parses_coil_bits_little_endian_within_a_byte() {
        let info = decode(&[1, 2, 0b0000_0101, 0b0000_0010]).expect("coils decode");
        assert_eq!(info.coils.len(), 16);
        assert!(info.coils[0]);
        assert!(!info.coils[1]);
        assert!(info.coils[2]);
        assert!(info.coils[9]);
    }
}
