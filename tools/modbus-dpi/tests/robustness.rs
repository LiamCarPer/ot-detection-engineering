//! Robustness tests: decoding malformed input must never panic.
//!
//! The decoder sits at a trust boundary and parses attacker-controlled bytes,
//! so every truncation and single-byte mutation of a known-good frame is fed
//! back through the public entry points. A panic here is a denial-of-service
//! bug.

use modbus_dpi::{mbap, parse_frame, parse_stream, DecodeError, ParseError};

/// Decode every non-comment line of `examples/frames.hex` into bytes.
fn example_frames() -> Vec<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/frames.hex");
    let text = std::fs::read_to_string(&path).expect("examples/frames.hex is readable");
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            (0..line.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&line[i..i + 2], 16).expect("line is hex"))
                .collect()
        })
        .collect()
}

/// Build a frame from the raw PDU with a correct MBAP length.
fn frame(transaction_id: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
    let length = u16::try_from(pdu.len() + 1).expect("PDU fits the MBAP length");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&transaction_id.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.push(unit_id);
    bytes.extend_from_slice(pdu);
    bytes
}

/// Feed bytes through the full consumption path, including event building.
fn check(bytes: &[u8]) {
    for frame in parse_stream(bytes).into_iter().flatten() {
        let _ = frame.decode();
        let _ = frame.event().to_json();
    }
}

#[test]
fn truncations_and_mutations_never_panic() {
    for frame in example_frames() {
        for cut in 0..=frame.len() {
            check(&frame[..cut]);
        }
        for index in 0..frame.len() {
            for value in [0x00u8, 0xFF] {
                let mut mutated = frame.clone();
                mutated[index] = value;
                check(&mutated);
            }
        }
    }
}

#[test]
fn a_bad_mbap_length_is_rejected() {
    let mut bytes = frame(1, 1, &[3, 0, 0, 0, 1]);
    bytes[4] = 0x00;
    bytes[5] = 0xFF;
    assert_eq!(
        parse_frame(&bytes),
        Err(ParseError::LengthMismatch {
            declared: 255,
            available: 6
        })
    );
}

#[test]
fn a_truncated_frame_is_rejected() {
    let bytes = frame(1, 1, &[3, 0, 0, 0, 1]);
    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        parse_frame(truncated),
        Err(ParseError::LengthMismatch {
            declared: 6,
            available: 5
        })
    );
}

#[test]
fn a_nonzero_protocol_id_is_rejected() {
    let mut bytes = frame(1, 1, &[3, 0, 0, 0, 1]);
    bytes[3] = 0x01;
    assert_eq!(parse_frame(&bytes), Err(ParseError::BadProtocolId(1)));
}

#[test]
fn an_empty_pdu_is_rejected_by_the_strict_decoder() {
    // MBAP length 1 is rejected at framing time because the unit id and the
    // function code are mandatory.
    let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01];
    assert_eq!(parse_frame(&bytes), Err(ParseError::InvalidLength(1)));
    assert_eq!(mbap::parse(&bytes), Err(ParseError::InvalidLength(1)));
}

#[test]
fn an_unknown_function_is_surfaced_as_an_event() {
    let bytes = frame(1, 1, &[0x07]);
    let event = parse_frame(&bytes).expect("framing is valid").0.event();
    assert_eq!(event.function_code, 0x07);
    assert_eq!(event.function_name, "Unsupported");
    assert!(event.decode_error.is_some());
}

#[test]
fn a_short_fc16_payload_is_surfaced_as_an_event() {
    let bytes = frame(1, 1, &[16, 0, 1, 0, 2, 4, 0, 1]);
    let event = parse_frame(&bytes).expect("framing is valid").0.event();
    assert_eq!(event.function_code, 16);
    assert!(event.decode_error.is_some());
}

#[test]
fn an_fc16_range_overflow_is_surfaced_as_an_event() {
    let pdu = [16, 0xFF, 0xFF, 0, 2, 4, 0, 1, 0, 2];
    let bytes = frame(1, 1, &pdu);
    let event = parse_frame(&bytes).expect("framing is valid").0.event();
    assert!(event
        .decode_error
        .as_deref()
        .is_some_and(|error| error.contains("runs past")));
}

#[test]
fn an_fc43_wrong_mei_type_is_surfaced_as_an_event() {
    let bytes = frame(1, 1, &[43, 0x0D, 1, 0]);
    let event = parse_frame(&bytes).expect("framing is valid").0.event();
    assert_eq!(event.function_code, 43);
    assert!(event
        .decode_error
        .as_deref()
        .is_some_and(|error| error.contains("MEI type")));
}

#[test]
fn a_quantity_of_zero_is_surfaced_as_an_event() {
    let bytes = frame(1, 1, &[3, 0, 0, 0, 0]);
    let event = parse_frame(&bytes).expect("framing is valid").0.event();
    assert!(event
        .decode_error
        .as_deref()
        .is_some_and(|error| error.contains("quantity 0")));
}

#[test]
fn decode_errors_display_without_panicking() {
    let errors = [
        DecodeError::EmptyPdu,
        DecodeError::UnsupportedFunction(7),
        DecodeError::TruncatedPdu {
            function: 3,
            needed: 5,
            available: 2,
        },
        DecodeError::InvalidQuantity {
            function: 3,
            quantity: 0,
            max: 125,
        },
        DecodeError::AddressOverflow {
            register: 0xFFFF,
            quantity: 2,
        },
        DecodeError::ByteCountMismatch {
            function: 16,
            declared: 2,
            expected: 4,
        },
        DecodeError::InvalidCoilValue(0x1234),
        DecodeError::InvalidMeiType(1),
    ];
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}
