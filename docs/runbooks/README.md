# Runbooks

Operational runbooks for the rules the detection catalogue marks `stable`.
Every stable rule must have one; `tools/detection_health.py` refuses a stable rule
without a runbook.

| Runbook | Rule | Technique | Severity |
| :-- | :-- | :-- | :-- |
| [Cross-zone violation](cross-zone-violation.md) | `ot_firewall_cross_zone_violation` | T0886 | high |
| [Modbus unauthorized write](modbus-unauthorized-write.md) | `ot_modbus_unauthorized_write` | T1692.001 | high |
| [Process safety violation](process-safety-violation.md) | `ot_process_safety_violation` | T0831 | critical |
| [DNP3 unauthorized control](dnp3-unauthorized-control.md) | `ot_dnp3_unauthorized_control` | T1692.001 | high |
| [S7comm program download](s7comm-program-download.md) | `ot_s7comm_program_download` | T0843 | high |
| [OPC UA address-space browse](opcua-browse-request.md) | `ot_opcua_browse_request` | T0888 | medium |

Each runbook follows the same shape: what the alert means, first five minutes,
validation, OT-safe containment, false positives and tuning, close-out, related
rules, and the last validation date.
