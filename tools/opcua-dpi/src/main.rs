//! Command-line front end for the OPC UA DPI decoder.
//!
//! Reads hex-encoded OPC UA messages (one per line, whitespace tolerated, `#`
//! comments ignored) from a file or standard input and writes one normalized
//! JSON event per message to standard output.

use std::io::{self, Read, Write};

use opcua_dpi::parse_stream;

/// Decode one ASCII hex digit.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(line: &str) -> Option<Vec<u8>> {
    // Work on bytes rather than a `str` slice: slicing a multi-byte UTF-8
    // character on an even offset used to panic on a char boundary.
    let cleaned: Vec<u8> = line
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b':' && *byte != b'-')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| Some((hex_nibble(cleaned[i])? << 4) | hex_nibble(cleaned[i + 1])?))
        .collect()
}

fn usage() {
    eprintln!("opcua-dpi — decode OPC UA messages into normalized JSON events");
    eprintln!();
    eprintln!("USAGE: opcua-dpi [FILE]");
    eprintln!();
    eprintln!("Reads hex-encoded messages from FILE, or standard input when omitted.");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        usage();
        return;
    }

    let mut input = String::new();
    if let Some(path) = args.first() {
        if let Err(error) = std::fs::read_to_string(path).map(|text| input = text) {
            eprintln!("error: cannot read {path}: {error}");
            std::process::exit(2);
        }
    } else if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("error: cannot read standard input: {error}");
        std::process::exit(2);
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut decoded = 0usize;
    let mut errors = 0usize;

    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(bytes) = decode_hex(line) else {
            eprintln!("line {}: invalid hex", index + 1);
            errors += 1;
            continue;
        };
        for result in parse_stream(&bytes) {
            match result {
                Ok(frame) => {
                    writeln!(out, "{}", frame.event().to_json()).ok();
                    decoded += 1;
                }
                Err(error) => {
                    eprintln!("line {}: {error}", index + 1);
                    errors += 1;
                }
            }
        }
    }

    eprintln!("decoded {decoded} event(s), {errors} error(s)");
    if errors > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn decodes_hex_with_separators() {
        assert_eq!(
            decode_hex("05 64:13-44"),
            Some(vec![0x05, 0x64, 0x13, 0x44])
        );
    }

    #[test]
    fn rejects_odd_length() {
        assert_eq!(decode_hex("056"), None);
    }

    #[test]
    fn rejects_non_ascii_without_panicking() {
        // Multi-byte UTF-8 previously broke a char-boundary slice.
        assert_eq!(decode_hex("€a"), None);
        assert_eq!(decode_hex("😀"), None);
    }
}
