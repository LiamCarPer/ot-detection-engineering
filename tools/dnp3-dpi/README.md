# dnp3-dpi

A dependency-free Rust decoder for DNP3 that emits normalized OT detection
events. It exists because the DNP3 application layer — function codes, control
objects and internal indications — cannot be expressed in Sigma, so the
protocol is decoded natively and the detection rules run on the resulting
events.

## What it decodes

- **Link layer:** start octets, length, control (DIR/PRM/FCB/FCV and function),
  source and destination addresses, with CRC-16/DNP validation of the header and
  every user-data block. User data is reassembled block by block with each
  2-octet block CRC validated and stripped before the transport and application
  layers see it.
- **Link functions:** the IEEE 1815 link function codes, named independently of
  the application layer. Function 3 is `CONFIRMED_USER_DATA`, function 4 is
  `UNCONFIRMED_USER_DATA` (not "Operate"), function 9 is
  `REQUEST_LINK_STATUS`, and function 11 is `LINK_STATUS`. Secondary functions
  0/1 are `ACK`/`NACK`; codes 5 and 6 are reserved.
- **Direction:** derived from the link control DIR bit, not from the application
  function code. `DIR=0` is a master-to-outstation request and `DIR=1` is an
  outstation-to-master response. An application Confirm (function 0) sent by a
  master is therefore a request, and a Direct Operate sent by an outstation
  would be a response.
- **Transport layer:** FIR/FIN and sequence.
- **Application layer:** application control (FIR/FIN/CON/UNS/SEQ), function
  code, internal indications on responses, and object headers. Each header
  exposes group, variation, raw qualifier, range-derived count and — when the
  qualifier carries one — the first object index/point.
- **Control code** for binary-output control objects (group 12, variation 1).

## Object headers

The first object header is always exposed. Further headers are decoded only
when the size of the preceding object bodies is known, which currently covers
binary-output control (group 12), analog-output control (group 41), the common
fixed-size binary, double-bit, analog and status groups, and class-data headers
(group 60) that carry no object bodies. For packed-bit or vendor-specific
variations the decoder stops after the header it can interpret rather than
guessing object sizes.

Qualifier range codes 0–9 and 0xB and index-prefix codes 0–3 are decoded.
Object-size/free-format prefixes are reported on the first header but stop
further walking. A truncated range or object header produces a structured
`ApplicationError`; a truncated object body keeps the already-decoded header
observable and stops without reading past the PDU. An application PDU with no
objects, such as Cold Restart, produces no object header at all.

Link CRC failures are rejected loudly as `LinkError::HeaderCrc` or
`LinkError::DataCrc { block }`.

## Remaining limits

- **No Secure Authentication (SAv5/SAv6):** authentication objects and
  challenge/response state are not decoded.
- **No full Select/Operate pairing:** the decoder is stateless per frame, so it
  does not expose `select_operate_paired` or `sbo_mismatch`.
- **IIN is raw:** responses expose the 16-bit internal-indications word, but the
  individual named bits are not expanded into separate fields.
- **No transport addresses:** the decoder works from link frames, so events
  carry `link_source`/`link_destination` and no `src_ip`/`dst_ip`.
- **Best-effort later headers:** the first object header is the
  detection-relevant one; later headers are decoded only for known fixed-size
  variations.

## Usage

```bash
cargo test
cargo run -- examples/frames.hex
cat capture.hex | cargo run
```

Input is hex-encoded link frames, one per line; `#` comments and whitespace are
ignored. Output is one JSON event per decoded application message:

```json
{"direction":"request","function_code":5,"function_name":"Direct Operate","link_source":3,"link_destination":1,"link_function":3,"link_function_name":"CONFIRMED_USER_DATA","transport_sequence":0,"application_sequence":0,"object_group":12,"object_variation":1,"object_qualifier":23,"object_count":1,"object_index":7,"control_code":3}
```

Frames with no application layer, such as a link-status exchange, are decoded
but produce no JSON event. Malformed link CRCs and truncated application
headers are reported on standard error and make the CLI exit non-zero.

## Design notes

- **No dependencies and `#![forbid(unsafe_code)]`** keep the trust surface small
  for an edge deployment.
- **CRC-16/DNP** is pinned to the standard check value `crc16(b"123456789") == 0xEA82`.
- The crate is a library plus a thin CLI, so the parser can be embedded in a
  collector that forwards events to the SIEM.
- Part of the `tools/` Cargo workspace alongside `s7comm-dpi`.
