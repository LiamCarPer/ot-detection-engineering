//! Regression test for the committed example frames.
//!
//! The example input and the decoder must not drift: these frames are the ones
//! a collector or `tools/decoder_check.py` feeds through the detection rules,
//! so a change in framing has to break a test here before it breaks the
//! detection proof.

use modbus_dpi::{parse_stream, Direction, Event};

/// Decode every non-comment line of `examples/frames.hex` into events.
fn example_events() -> Vec<Event> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/frames.hex");
    let text = std::fs::read_to_string(&path).expect("examples/frames.hex is readable");
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes: Vec<u8> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).expect("line is hex"))
            .collect();
        for frame in parse_stream(&bytes) {
            events.push(frame.expect("example frame parses").event());
        }
    }
    events
}

#[test]
fn examples_cover_the_supported_function_codes() {
    let functions: Vec<u8> = example_events()
        .iter()
        .map(|event| event.function_code)
        .collect();
    for expected in [1u8, 2, 3, 4, 5, 6, 15, 16, 22, 23, 43] {
        assert!(
            functions.contains(&expected),
            "examples/frames.hex no longer decodes function {expected}: {functions:?}"
        );
    }
}

#[test]
fn every_example_decodes_without_a_structured_error() {
    for event in example_events() {
        assert!(
            event.decode_error.is_none(),
            "example event unexpectedly failed: {event:?}"
        );
    }
}

#[test]
fn examples_decode_representative_fields_for_each_function() {
    let events = example_events();
    let find = |function: u8, direction: Direction| {
        events
            .iter()
            .find(|event| event.function_code == function && event.direction == direction)
            .unwrap_or_else(|| panic!("missing FC{function} {direction:?}"))
    };

    let fc1 = find(1, Direction::Request);
    assert_eq!((fc1.register, fc1.quantity), (Some(19), Some(10)));
    let fc1_response = find(1, Direction::Response);
    assert_eq!(fc1_response.byte_count, Some(2));
    assert_eq!(fc1_response.coils.len(), 16);

    let fc2 = find(2, Direction::Request);
    assert_eq!((fc2.register, fc2.quantity), (Some(0), Some(8)));
    assert_eq!(find(2, Direction::Response).coils.len(), 8);

    let fc3 = find(3, Direction::Request);
    assert_eq!((fc3.register, fc3.quantity), (Some(0), Some(10)));
    assert_eq!(
        find(3, Direction::Response).values,
        (0u16..10).collect::<Vec<_>>()
    );

    let fc4 = find(4, Direction::Request);
    assert_eq!((fc4.register, fc4.quantity), (Some(0), Some(1)));
    assert_eq!(find(4, Direction::Response).values, vec![123]);

    let fc6 = find(6, Direction::Request);
    assert_eq!((fc6.register, fc6.value), (Some(1024), Some(1)));

    let fc15 = find(15, Direction::Request);
    assert_eq!((fc15.register, fc15.quantity), (Some(19), Some(10)));
    assert_eq!(fc15.coils.len(), 10);
    assert_eq!(find(15, Direction::Response).quantity, Some(10));

    let fc22 = find(22, Direction::Request);
    assert_eq!(fc22.register, Some(4));
    assert_eq!((fc22.and_mask, fc22.or_mask), (Some(0x00FF), Some(0x0010)));

    let fc23 = find(23, Direction::Request);
    assert_eq!((fc23.register, fc23.quantity), (Some(0), Some(2)));
    assert_eq!(
        (fc23.write_register, fc23.write_quantity),
        (Some(16), Some(2))
    );
    assert_eq!(fc23.values, vec![10, 11]);
    assert_eq!(find(23, Direction::Response).values, vec![1, 2]);

    let fc43 = find(43, Direction::Request);
    assert_eq!(
        (fc43.mei_type, fc43.read_device_id_code),
        (Some(14), Some(1))
    );
    assert_eq!(fc43.object_id, Some(0));
}

#[test]
fn examples_include_an_exception_response() {
    let exception = example_events()
        .into_iter()
        .find(|event| event.exception_code.is_some())
        .expect("an exception response is present");
    assert_eq!(exception.direction, Direction::Response);
    assert_eq!(exception.function_code, 3);
    assert_eq!(exception.exception_code, Some(2));
    assert!(exception.to_json().contains("\"exception_code\":2"));
}

#[test]
fn examples_include_a_coil_write() {
    let coil = example_events()
        .into_iter()
        .find(|event| event.function_code == 5)
        .expect("a coil write is present");
    assert_eq!(coil.register, Some(172));
    assert_eq!(coil.value, Some(1));
    assert_eq!(coil.coils, vec![true]);
}

#[test]
fn examples_include_the_block_write_range_boundary() {
    let block = example_events()
        .into_iter()
        .find(|event| event.function_code == 16 && event.register == Some(3999))
        .expect("the 3999 block write is present");
    assert_eq!(block.quantity, Some(10));
    assert_eq!(block.register_end, Some(4008));
    assert_eq!(block.values.len(), 10);
}

#[test]
fn examples_include_read_device_identification() {
    let objects = example_events()
        .into_iter()
        .filter(|event| event.function_code == 43)
        .find_map(|event| {
            if event.device_id_objects.is_empty() {
                None
            } else {
                Some(event.device_id_objects)
            }
        })
        .expect("a device identification response is present");
    assert_eq!(objects.len(), 3);
    assert_eq!(objects[0].value, "Acme");
    assert_eq!(objects[1].value, "M221");
    assert_eq!(objects[2].value, "1.2.3");
}
