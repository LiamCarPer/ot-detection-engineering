//! Protocol-correctness regressions for the DNP3 decoder.
//!
//! These tests pin the link-function names, DIR-based direction, user-data
//! reassembly and object-header boundaries that the detection content depends
//! on. They deliberately use only the public API.

use dnp3_dpi::application::{self, ApplicationError};
use dnp3_dpi::crc::crc16;
use dnp3_dpi::link::{self, LinkError};
use dnp3_dpi::{parse_frame, Direction, Event};

const MAX_BLOCK: usize = 16;

/// Build a link frame with valid header and data CRCs.
fn build_frame(control: u8, destination: u16, source: u16, user_data: &[u8]) -> Vec<u8> {
    let length = (link::MIN_LENGTH + user_data.len()) as u8;
    let mut header = vec![link::START[0], link::START[1], length, control];
    header.extend_from_slice(&destination.to_le_bytes());
    header.extend_from_slice(&source.to_le_bytes());
    let header_crc = crc16(&header);
    let mut frame = header;
    frame.extend_from_slice(&header_crc.to_le_bytes());
    for block in user_data.chunks(MAX_BLOCK) {
        frame.extend_from_slice(block);
        frame.extend_from_slice(&crc16(block).to_le_bytes());
    }
    frame
}

/// Confirmed user data carrying one Direct Operate CROB on point 7. The user
/// data is 18 octets, so the link layer must reassemble two CRC-protected
/// blocks before the application layer sees it.
fn direct_operate_user_data() -> Vec<u8> {
    vec![
        0xC0, // transport FIR+FIN, sequence 0
        0xC0, // application FIR+FIN, sequence 0
        0x05, // Direct Operate
        0x0C, 0x01, // group 12 (CROB), variation 1
        0x17, // 8-bit count with 8-bit index prefixes
        0x01, // one object
        0x07, // point index 7
        0x03, // LATCH_ON
        0x01, // operation count
        0x00, 0x00, 0x00, 0x00, // on time
        0x00, 0x00, 0x00, 0x00, // off time
    ]
}

fn event_for(bytes: &[u8]) -> Event {
    let (frame, consumed) = parse_frame(bytes).expect("frame parses");
    assert_eq!(consumed, bytes.len());
    frame
        .try_event()
        .expect("application parses")
        .expect("event")
}

#[test]
fn confirmed_user_data_has_the_correct_link_function() {
    let bytes = build_frame(0x53, 1, 3, &direct_operate_user_data());
    let (frame, _) = parse_frame(&bytes).expect("frame parses");
    assert_eq!(frame.control.function, 3);
    assert!(frame.control.primary);
    assert!(frame.control.is_user_data());
    assert_eq!(frame.control.function_name(), "CONFIRMED_USER_DATA");

    let event = frame.event().expect("event");
    assert_eq!(event.link_function, 3);
    assert_eq!(event.link_function_name, "CONFIRMED_USER_DATA");
}

#[test]
fn unconfirmed_user_data_has_the_correct_link_function() {
    let bytes = build_frame(0x44, 1, 3, &[0xC0, 0xC0, 0x15]);
    let (frame, _) = parse_frame(&bytes).expect("frame parses");
    assert_eq!(frame.control.function, 4);
    assert!(frame.control.primary);
    assert!(frame.control.is_user_data());
    assert_eq!(frame.control.function_name(), "UNCONFIRMED_USER_DATA");
    assert_ne!(frame.control.function_name(), "Operate");

    let event = frame.event().expect("event");
    assert_eq!(event.link_function, 4);
    assert_eq!(event.link_function_name, "UNCONFIRMED_USER_DATA");
}

#[test]
fn link_function_names_follow_ieee_1815() {
    let cases = [
        (0x40, "RESET_LINK_STATES"),
        (0x41, "RESET_USER_PROCESS"),
        (0x42, "TEST_LINK_STATES"),
        (0x43, "CONFIRMED_USER_DATA"),
        (0x44, "UNCONFIRMED_USER_DATA"),
        (0x45, "Reserved"),
        (0x46, "Reserved"),
        (0x49, "REQUEST_LINK_STATUS"),
        (0x8B, "LINK_STATUS"),
        (0x80, "ACK"),
        (0x81, "NACK"),
        (0x8F, "NOT_SUPPORTED"),
    ];
    for (control, expected) in cases {
        let bytes = build_frame(control, 1, 3, &[]);
        let (frame, _) = parse_frame(&bytes).expect("frame parses");
        assert_eq!(
            frame.control.function_name(),
            expected,
            "control octet 0x{control:02X}"
        );
    }
}

#[test]
fn link_status_frame_is_decoded_and_has_no_application_event() {
    // Secondary LINK_STATUS from the outstation: DIR=1, PRM=0, function 11.
    let bytes = build_frame(0x8B, 3, 1, &[]);
    let (frame, consumed) = parse_frame(&bytes).expect("frame parses");
    assert_eq!(consumed, bytes.len());
    assert_eq!(frame.control.function, 11);
    assert!(!frame.control.primary);
    assert_eq!(frame.control.function_name(), "LINK_STATUS");
    assert_eq!(frame.direction(), Direction::Response);
    assert!(frame.user_data.is_empty());
    assert!(frame.event().is_none());
}

#[test]
fn a_bad_user_data_block_crc_is_rejected() {
    let user_data = direct_operate_user_data();
    let mut bytes = build_frame(0x53, 1, 3, &user_data);
    // Header is 10 octets; the first block is 16 data octets plus a 2-octet
    // CRC, so the second block's data starts at offset 28.
    let second_block = 10 + MAX_BLOCK + 2;
    bytes[second_block] ^= 0xFF;
    assert_eq!(parse_frame(&bytes), Err(LinkError::DataCrc { block: 1 }));
}

#[test]
fn a_truncated_link_frame_is_reported() {
    let bytes = build_frame(0x53, 1, 3, &direct_operate_user_data());
    let short = &bytes[..bytes.len() - 1];
    assert!(matches!(
        parse_frame(short),
        Err(LinkError::Incomplete { .. })
    ));
}

#[test]
fn a_two_block_application_payload_is_reassembled_without_phantom_objects() {
    let user_data = direct_operate_user_data();
    assert!(user_data.len() > MAX_BLOCK, "the test needs two blocks");
    let bytes = build_frame(0x53, 1, 3, &user_data);
    let (frame, consumed) = parse_frame(&bytes).expect("frame parses");
    assert_eq!(consumed, bytes.len());
    assert_eq!(
        frame.user_data, user_data,
        "CRCs must not leak into the PDU"
    );

    let event = frame.event().expect("event");
    assert_eq!(event.object_group, Some(12));
    assert_eq!(event.object_variation, Some(1));
    assert_eq!(event.object_qualifier, Some(0x17));
    assert_eq!(event.object_count, Some(1));
    assert_eq!(event.object_index, Some(7));
    assert_eq!(event.control_code, Some(3));
    assert!(!event.to_json().contains("\"object_group\":156"));
    assert!(!event.to_json().contains("\"object_group\":134"));
}

#[test]
fn a_cold_restart_pdu_has_no_object_header() {
    let bytes = build_frame(0x44, 1, 3, &[0xC0, 0xC0, 0x0D]);
    let (frame, _) = parse_frame(&bytes).expect("frame parses");
    let application = frame.application().expect("application parses");
    assert_eq!(application.function, 13);
    assert!(application.objects.is_empty());

    let event = frame.event().expect("event");
    assert_eq!(event.function_code, 13);
    assert_eq!(event.object_group, None);
    assert_eq!(event.object_variation, None);
    assert_eq!(event.object_qualifier, None);
    assert_eq!(event.object_count, None);
    assert_eq!(event.object_index, None);
    assert!(!event.to_json().contains("object_group"));
}

#[test]
fn the_dir_bit_controls_direction() {
    let application = direct_operate_user_data();

    // Master to outstation: DIR=0, even though the application function is a
    // control request.
    let master = build_frame(0x44, 1, 3, &application);
    assert_eq!(event_for(&master).direction, Direction::Request);

    // Outstation to master: DIR=1. The same Direct Operate bytes now decode as
    // a response because direction comes from the link header.
    let outstation = build_frame(0xC4, 3, 1, &application);
    let event = event_for(&outstation);
    assert_eq!(event.direction, Direction::Response);
    assert_eq!(event.function_code, 5);
    assert_eq!(event.link_source, 1);
    assert_eq!(event.link_destination, 3);
}

#[test]
fn a_confirm_from_the_master_is_a_request() {
    // Application Confirm (function 0) in a master-to-outstation frame.
    let bytes = build_frame(0x44, 1, 3, &[0xC0, 0xC0, 0x00]);
    let event = event_for(&bytes);
    assert_eq!(event.direction, Direction::Request);
    assert_eq!(event.function_code, 0);
    assert_eq!(event.function_name, "Confirm");
}

#[test]
fn multiple_object_headers_are_exposed() {
    // A class poll: three Group 60 headers, each with the "all objects"
    // qualifier and no object bodies.
    let application = [
        0xC0, 0x01, // application control, Read
        0x3C, 0x02, 0x06, // group 60, variation 2 (class 1), all objects
        0x3C, 0x03, 0x06, // group 60, variation 3 (class 2), all objects
        0x3C, 0x04, 0x06, // group 60, variation 4 (class 3), all objects
    ];
    let header = application::parse(&application).expect("application parses");
    assert_eq!(header.objects.len(), 3);
    let variations: Vec<u8> = header
        .objects
        .iter()
        .map(|object| object.variation)
        .collect();
    assert_eq!(variations, vec![2, 3, 4]);
    for object in &header.objects {
        assert_eq!(object.group, 60);
        assert_eq!(object.qualifier, 0x06);
        assert_eq!(object.count, None);
        assert_eq!(object.index, None);
    }
}

#[test]
fn multiple_object_headers_with_bodies_are_exposed() {
    // A response with two binary-input objects followed by one binary-output
    // status object. Correctly skipping the first bodies is what makes the
    // second header visible.
    let application = [
        0xC0, 0x81, 0x00, 0x00, // application control, Response, IIN 0
        0x01, 0x01, 0x00, 0x00, 0x01, // group 1 var 1, indexes 0..=1
        0x01, 0x00, // two flags
        0x0A, 0x01, 0x00, 0x02, 0x02, // group 10 var 1, index 2
        0x01, // one flag
    ];
    let header = application::parse(&application).expect("application parses");
    assert_eq!(header.objects.len(), 2);

    assert_eq!(header.objects[0].group, 1);
    assert_eq!(header.objects[0].count, Some(2));
    assert_eq!(header.objects[0].index, Some(0));

    assert_eq!(header.objects[1].group, 10);
    assert_eq!(header.objects[1].count, Some(1));
    assert_eq!(header.objects[1].index, Some(2));
}

#[test]
fn responses_expose_the_raw_iin_word() {
    let bytes = build_frame(0xC4, 3, 1, &[0xC0, 0xC1, 0x81, 0x40, 0x01]);
    let event = event_for(&bytes);
    assert_eq!(event.direction, Direction::Response);
    assert_eq!(event.function_code, 129);
    assert_eq!(event.iin, Some(0x0140));
}

#[test]
fn object_range_parsing_does_not_read_past_the_application_bytes() {
    // Qualifier 0x17 announces a count byte, but the PDU ends at the qualifier.
    let truncated_range = [0xC0, 0x05, 0x0C, 0x01, 0x17];
    assert!(matches!(
        application::parse(&truncated_range),
        Err(ApplicationError::TruncatedObjectData { .. })
    ));

    // A partial object header (group and variation but no qualifier).
    let truncated_header = [0xC0, 0x05, 0x0C, 0x01];
    assert!(matches!(
        application::parse(&truncated_header),
        Err(ApplicationError::TruncatedObjectHeader { .. })
    ));

    // A truncated object body after a complete header and index prefix: the
    // header remains observable, but the parser must not read past the PDU.
    let truncated_body = [0xC0, 0x05, 0x0C, 0x01, 0x17, 0x01, 0x07, 0x03];
    let header = application::parse(&truncated_body).expect("header is intact");
    assert_eq!(header.objects.len(), 1);
    assert_eq!(header.objects[0].group, 12);
    assert_eq!(header.objects[0].count, Some(1));
    assert_eq!(header.objects[0].index, Some(7));
    assert_eq!(header.control_code, Some(3));
}
