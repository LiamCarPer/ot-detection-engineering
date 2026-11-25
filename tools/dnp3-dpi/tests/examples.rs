//! Regression test for the committed example frames.
//!
//! The example input and the decoder must not drift: these frames are the ones
//! `tools/decoder_check.py` feeds through the Sigma rules, so a change in
//! framing has to break a test here before it breaks the detection proof.

use dnp3_dpi::parse_stream;

/// Decode every non-comment line of `examples/frames.hex` into events.
fn example_events() -> Vec<dnp3_dpi::Event> {
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
            if let Some(event) = frame.expect("example frame parses").event() {
                events.push(event);
            }
        }
    }
    events
}

#[test]
fn example_frames_cover_the_detection_rules() {
    let events = example_events();
    let functions: Vec<u8> = events.iter().map(|event| event.function_code).collect();
    // Direct Operate, Disable Unsolicited and Cold Restart: one frame per rule.
    for expected in [5u8, 21, 13] {
        assert!(
            functions.contains(&expected),
            "examples/frames.hex no longer decodes function {expected}: {functions:?}"
        );
    }
}

#[test]
fn example_frames_exercise_the_corrected_paths() {
    let events = example_events();
    assert!(events
        .iter()
        .all(|event| event.direction == dnp3_dpi::Direction::Request));

    // The Direct Operate example is confirmed user data, spans two blocks and
    // carries a CROB on point 7.
    let direct_operate = events
        .iter()
        .find(|event| event.function_code == 5)
        .expect("Direct Operate example");
    assert_eq!(direct_operate.link_function, 3);
    assert_eq!(direct_operate.link_function_name, "CONFIRMED_USER_DATA");
    assert_eq!(direct_operate.object_group, Some(12));
    assert_eq!(direct_operate.object_qualifier, Some(0x17));
    assert_eq!(direct_operate.object_index, Some(7));
    assert_eq!(direct_operate.control_code, Some(3));

    // Cold Restart has no object header: no phantom group from CRC octets.
    let cold_restart = events
        .iter()
        .find(|event| event.function_code == 13)
        .expect("Cold Restart example");
    assert_eq!(cold_restart.object_group, None);
    assert_eq!(cold_restart.link_function_name, "UNCONFIRMED_USER_DATA");
}
