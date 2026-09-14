# dnp3-dpi

A dependency-free Rust decoder for DNP3 that emits normalized OT detection
events. It exists because the DNP3 application layer — function codes, control
objects and internal indications — cannot be expressed in Sigma, so the
protocol is decoded natively and the detection rules run on the resulting
events.

## What it decodes

- **Link layer:** start octets, length, control (DIR/PRM/FCB/FCV and function),
  source and destination addresses, with CRC-16/DNP validation of the header and
  every user-data block.
- **Transport layer:** FIR/FIN and sequence.
- **Application layer:** application control (FIR/FIN/CON/UNS/SEQ), function
  code, internal indications on responses, and the first object header
  (group, variation, qualifier, count).
- **Control code** for binary-output control objects (group 12).

## Why the first object header only

Continuing past the first object header requires variation-specific object
sizes. For DPI telemetry the first header is enough to distinguish a control
operation (group 12/41) from monitoring data, so the decoder stops there and
documents the limitation rather than guessing.

## Usage

```bash
cargo test
cargo run -- examples/frames.hex
cat capture.hex | cargo run
```

Input is hex-encoded link frames, one per line; `#` comments and whitespace are
ignored. Output is one JSON event per decoded application message:

```json
{"direction":"request","function_code":5,"function_name":"Direct Operate","link_source":3,"link_destination":1,"link_function":4,"link_function_name":"Operate","transport_sequence":0,"application_sequence":0,"object_group":12,"object_variation":1,"object_count":1,"control_code":3}
```

## Design notes

- **No dependencies and `#![forbid(unsafe_code)]`** keep the trust surface small
  for an edge deployment.
- **CRC-16/DNP** is pinned to the standard check value `crc16(b"123456789") == 0xEA82`.
- The crate is a library plus a thin CLI, so the parser can be embedded in a
  collector that forwards events to the SIEM.
