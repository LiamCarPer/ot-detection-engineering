# s7comm-dpi

A dependency-free Rust decoder for classic S7comm (Siemens) that emits
normalized OT detection events. It exists because Suricata has no S7comm
application-layer parser and Sigma cannot express protocol semantics, so the
protocol is decoded natively and the detection rules run on the resulting
events.

## What it decodes

- **TPKT (RFC 1006):** version and length framing.
- **COTP (ISO 8073):** length indicator and PDU type, so the S7 header is found
  correctly for data PDUs and skipped for connection setup.
- **S7comm:** protocol id (`0x32`), ROSCTR, PDU reference, parameter and data
  lengths, and the function code (Read/Write Var, download, upload, PLC
  control/stop, setup communication).

## Usage

```bash
cargo test
cargo run -- examples/read_var.hex
cat capture.hex | cargo run
```

Input is hex-encoded TPKT frames, one per line. Output is one JSON event per
decoded S7 job or response:

```json
{"direction":"request","function_code":4,"function_name":"Read Var","rosctr":1,"pdu_reference":619,"parameter_length":14,"data_length":0,"cotp_type":240}
```

## Design notes

- **No dependencies and `#![forbid(unsafe_code)]`** keep the trust surface small
  for an edge deployment.
- **COTP length indicator** drives the S7 offset, so connection request/confirm
  PDUs (which carry no S7 header) produce no event.
- **Classic S7comm only.** S7comm Plus (`0x72`) is not decoded; requests using
  it are ignored rather than mis-parsed.
- Part of the `tools/` Cargo workspace alongside `dnp3-dpi`.
