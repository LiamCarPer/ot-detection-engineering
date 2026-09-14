# Native protocol rules

Detection content that cannot be expressed as Sigma lives here. Sigma is a
log-event format; it has no vocabulary for industrial protocol semantics such as
a Modbus function code, an exception response, or a register range. Rather than
force those detections into Sigma and lose fidelity, they are authored natively
for the platform that understands the protocol.

## Suricata

The `suricata/` directory contains deep packet inspection rules per protocol:

| File | Protocol | Technique |
| :--- | :--- | :--- |
| `modbus_dpi.rules` | Modbus/TCP | Function-code DPI (write, scan, exception bursts) |
| `dnp3_dpi.rules` | DNP3 | Function-code and object-header DPI (control, write, device scan) |
| `opcua_dpi.rules` | OPC UA (`tcp/4840`) | Message-header DPI (Hello, OpenSecureChannel) |

DNP3 control operations are also detected at the application layer:
[tools/dnp3-dpi](../../tools/dnp3-dpi) decodes frames into normalized events and
the `ot_dnp3_*` Sigma rules apply the master allowlist on top.

They are governed by the same conventions as the Sigma rules:

- **Technique tagging.** Every rule carries `metadata: attack_ics <technique>`,
  parsed by `tests/test_native_rules.py` and folded into the same coverage map
  as the Sigma tags.
- **Reserved identifiers.** `sid` values fall in `1000000-1000999`, which this
  repository reserves. `tests/test_native_rules.py` enforces uniqueness and
  range.
- **Required fields.** `msg`, `classtype`, `sid` and `rev` are required.

## Validation scope

CI validates these rules structurally: required fields, technique tags against
the pinned catalog, and unique SIDs. It does not execute Suricata, because the
repository is intentionally self-contained. Functional validation against live
traffic happens in the NDR pipeline that consumes these rules
([OT-NDR-Malcolm-Pipeline](https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline)).
