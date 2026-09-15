//! Robustness tests: decoding malformed input must never panic.
//!
//! The decoders sit at a trust boundary and parse attacker-controlled bytes, so
//! every truncation and single-byte mutation of a known-good frame is fed back
//! through the public entry points. A panic here is a denial-of-service bug.

use s7comm_dpi::{parse_frame, parse_stream};

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

#[test]
fn truncations_and_mutations_never_panic() {
    for frame in example_frames() {
        for cut in 0..=frame.len() {
            let prefix = &frame[..cut];
            let _ = parse_frame(prefix);
            let _ = parse_stream(prefix);
        }
        for index in 0..frame.len() {
            for value in [0x00u8, 0xFF] {
                let mut mutated = frame.clone();
                mutated[index] = value;
                let _ = parse_frame(&mutated);
                let _ = parse_stream(&mutated);
            }
        }
    }
}

#[test]
fn a_header_only_s7_payload_is_rejected_without_panicking() {
    // TPKT length 17: a 3-octet COTP data header and exactly 10 S7 octets, so
    // there is no parameter block and no function code to read.
    let frame = [
        0x03, 0x00, 0x00, 0x11, // TPKT: version 3, length 17
        0x02, 0xF0, 0x80, // COTP: indicator 2 -> header_len 3, DT
        0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // S7 header only
    ];
    let (parsed, consumed) = parse_frame(&frame).expect("framing is valid");
    assert_eq!(consumed, frame.len());
    assert!(parsed.s7.is_none());
    assert!(parsed.event().is_none());
}
