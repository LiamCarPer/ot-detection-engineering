# opcua-dpi

A dependency-free Rust decoder for OPC UA that emits normalized OT detection
events. Suricata has no OPC UA application-layer parser and Sigma cannot express
the service layer, so the protocol is decoded natively and the detection rules
run on the resulting events.

## What it decodes

- **TCP message header:** message type (HEL, ACK, ERR, RHE, OPN, MSG, CLO),
  chunk type and message size.
- **Secure conversation header:** secure channel id, the OPN security policy URI,
  the MSG/CLO token id, and the sequence and request ids.
- **Service NodeId:** the first NodeId in a message body, resolved to a standard
  service name (WriteRequest 673, CallRequest 712, BrowseRequest 527, …).

## The encryption limit

The service NodeId is only readable when the body is not encrypted. A channel
using `Sign` keeps the body in clear text, but `SignAndEncrypt` does not, so those
messages yield the message and conversation metadata with no service. This is a
documented limit of passive inspection, not a parser failure.

## Usage

```bash
cargo test
cargo run -- examples/frames.hex
cat capture.hex | cargo run
```

Input is hex-encoded messages, one per line. Output is one JSON event per
message:

```json
{"message_type":"MSG","chunk_type":"F","secure_channel_id":1,"token_id":1,"sequence_number":2,"request_id":2,"service_id":673,"opcua_service":"WriteRequest","direction":"request"}
```

## Design notes

- **No dependencies and `#![forbid(unsafe_code)]`** keep the trust surface small
  for an edge deployment.
- **Identifiers are the `..._Encoding_DefaultBinary` NodeIds** from OPC UA Part 6,
  Annex A, which is what appears on the wire.
- Part of the `tools/` Cargo workspace alongside `dnp3-dpi` and `s7comm-dpi`.
