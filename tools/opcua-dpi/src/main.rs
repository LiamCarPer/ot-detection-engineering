//! Command-line front end for the OPC UA DPI decoder.
//!
//! Reads hex-encoded OPC UA messages (one per line, whitespace tolerated, `#`
//! comments ignored) from a file or standard input and writes one normalized
//! JSON event per message to standard output.

use std::io::{self, Read, Write};

use opcua_dpi::parse_stream;

fn decode_hex(line: &str) -> Option<Vec<u8>> {
    let cleaned: String = line
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
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
