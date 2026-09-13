# Native protocol rules

Detection content that cannot be expressed as Sigma lives here. Sigma is a
log-event format; it has no vocabulary for industrial protocol semantics such as
a Modbus function code, an exception response, or a register range. Rather than
force those detections into Sigma and lose fidelity, they are authored natively
for the platform that understands the protocol.

## Suricata

`suricata/modbus_dpi.rules` contains Modbus/TCP deep packet inspection rules.
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
