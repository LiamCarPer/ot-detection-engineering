# modbus-dpi

A dependency-free Rust decoder for Modbus/TCP that emits normalized OT
detection events. It exists because the Modbus application layer — function
codes, register addresses and exception codes — cannot be expressed in Sigma,
so the protocol is decoded natively and the detection rules run on the
resulting events.

## What it decodes

- **MBAP framing:** transaction identifier, protocol identifier, length and unit
  identifier, with a strict check that the declared length fits the buffer.
- **Function codes used by the detection content:**
  - FC1 Read Coils and FC2 Read Discrete Inputs (request address/quantity,
    response coil bits)
  - FC3 Read Holding Registers and FC4 Read Input Registers (address/quantity,
    response register values)
  - FC5 Write Single Coil (address and ON/OFF value)
  - FC6 Write Single Register (address and value)
  - FC15 Write Multiple Coils (address, quantity and coil bits)
  - FC16 Write Multiple Registers (address, quantity and values)
  - FC22 Mask Write Register (address, AND mask and OR mask)
  - FC23 Read/Write Multiple Registers (read and write addresses/quantities,
    written values)
  - FC43 / MEI type 14 Read Device Identification (read code, conformity level,
    more-follows, next object id and device ID objects)
- **Exception responses:** function code with `0x80` set, reported as a
  `response` with `exception_code`.
- **Unknown or reserved function codes:** surfaced as
  `"function_name":"Unsupported"` with a `decode_error`, never dropped.

One JSON object is written per request or response. Fields are omitted when
they do not apply, matching the repository rule that a field the source cannot
see is never guessed. Example:

```json
{"direction":"request","function_code":16,"function_name":"Write Multiple Registers","transaction_id":8,"protocol_id":0,"unit_id":1,"pdu_length":26,"register":3999,"quantity":10,"byte_count":20,"value":0,"values":[0,1,2,3,4,5,6,7,8,9]}
```

An exception response looks like:

```json
{"direction":"response","function_code":3,"function_name":"Read Holding Registers","transaction_id":13,"protocol_id":0,"unit_id":1,"pdu_length":2,"raw_function_code":131,"exception_code":2}
```

The exception-bit set octet is retained in `raw_function_code` (131 = `0x83`),
while `function_code` is the base function the exception refers to.

## Usage

```bash
cargo test
cargo run -- examples/frames.hex
cat capture.hex | cargo run
```

Input is hex-encoded MBAP frames, one per line; `#` comments and whitespace are
ignored. A line can also contain several concatenated frames. The binary writes
events to standard output and exits non-zero when a frame is malformed or a PDU
has a structured decode error (the error event is still printed).

## Direction inference

Modbus has no direction bit. The decoder infers direction from the PDU shape:
read requests carry a fixed five-octet address/quantity body, read responses
carry a byte count that matches the payload, multi-write responses are the
five-octet echo, and the exception bit forces a response. FC5, FC6 and FC22
requests and responses are byte-identical, so those events default to
`"direction":"request"`. A collector that observes both TCP endpoints can
override the direction authoritatively.

A read-coils or read-discrete-inputs response does not echo the requested
count, so its `quantity` is the number of coil bits the byte count covers
(including unused padding bits); the request carries the exact requested
quantity. Register responses determine the quantity exactly from the byte
count.

## What it deliberately does not do

- **No TCP reassembly.** The decoder consumes MBAP frames from a buffer; it has
  no sequence tracking, retransmission handling or stream reassembly. A
  pipeline that sees raw TCP must reassemble before calling this crate.
- **No IP endpoints from hex.** Frames carry no addresses, so `src_ip`,
  `dst_ip`, `src_port` and `dst_port` are omitted; the collector or NDR
  pipeline attaches them.
- **No per-unit register map.** `register` is the raw 0-based protocol address
  from the PDU. It is not translated to a 4xxxx convention and no device map is
  consulted, so rules must be tuned to the site's addressing.
- **No masked-write result.** For FC22 the resulting register value depends on
  the register's current contents, which the frame does not carry, so only the
  AND and OR masks are emitted and `value` is omitted.
- **No RTU framing.** This is Modbus/TCP only: no CRC, no serial line framing.
- **Only MEI type 14.** Other Modbus encapsulation interface types, and
  function codes outside the list above, produce an `Unsupported` event with a
  `decode_error`.

## Design notes

- **No dependencies and `#![forbid(unsafe_code)]`** keep the trust surface small
  for an edge deployment.
- Every length is bounds-checked before use. Quantities are limited to the
  protocol maxima (2000 coils, 125 registers, 1968 written coils, 123 written
  registers), zero is rejected, and `register + quantity` must stay inside the
  16-bit address space. A block write at register 3999 with quantity 10 is valid;
  the check uses the last addressed register, not the starting address alone.
- Malformed PDUs after a valid MBAP header become error events with
  `decode_error`; malformed MBAP framing is a `ParseError` from `parse_frame`.
- Device identification values are attacker-controlled, so JSON output escapes
  quotes, backslashes and control characters.
- Part of the `tools/` Cargo workspace alongside `dnp3-dpi`, `s7comm-dpi` and
  `opcua-dpi`.
