//! Robustness tests: decoding malformed input must never panic.
//!
//! The decoders sit at a trust boundary and parse attacker-controlled bytes, so
//! every truncation and single-byte mutation of a known-good frame is fed back
//! through the public entry points. A panic here is a denial-of-service bug.

use dnp3_dpi::parse_stream;

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

/// Feed bytes through the full consumption path, including application/event.
fn check(bytes: &[u8]) {
    for frame in parse_stream(bytes).into_iter().flatten() {
        let _ = frame.application();
        let _ = frame.event();
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
fn a_32_bit_object_range_does_not_overflow() {
    // Control, Direct Operate, group 12 variation 1, qualifier 0x20 (32-bit
    // start/stop) with start 0 and stop 0xFFFFFFFF: the count must saturate
    // instead of overflowing.
    let application = [
        0x00, 0x05, // application control, Direct Operate
        0x0C, 0x01, // group 12, variation 1
        0x20, // qualifier: 32-bit start/stop
        0x00, 0x00, 0x00, 0x00, // start
        0xFF, 0xFF, 0xFF, 0xFF, // stop
    ];
    let header = dnp3_dpi::application::parse(&application).expect("application parses");
    assert_eq!(header.objects.len(), 1);
    assert_eq!(header.objects[0].count, Some(u32::MAX));
}
