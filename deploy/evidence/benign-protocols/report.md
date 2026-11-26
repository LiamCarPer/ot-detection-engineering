# Lab benign capture

Capture: `/media/liamcarvajal/Storage/code/ot-security-lab/detection/logs/benign-protocols-30m.pcap`  
SHA-256: `4ca4ad9f417b54f261901c80c7b0b093a330d3b16721d7f289dcec8d87b1dcbd`  
Size: 49,542,040 bytes  
Window: 2026-11-26T10:06:20.767522+00:00 to 2026-11-26T10:36:20.352834+00:00 (0.50 h)  
Normalized events: 52,811 (105646.34 / h)

| Family | Result | Input |
| :-- | :-- | :-- |
| Sigma single-event | 0 / 52811 events | 22 / 30 rules |
| Sigma correlation | 0 fired | 4 / 7 rules |
| Committed baseline (domain shift) | 13046 events | yes |
| Lab-trained baseline | 0 / 38276 test events | train 14535 |
| Conduit | 0 events | no firewall events |
| Stateful | 0 fired | 3 / 5 rules |
| Native Suricata | 0 alerts | protocols present |
| Host/auth/PLC/health | not observed in a network capture | n/a |

## Input coverage

| Service | Events |
| :-- | --: |
| ot_flow/flow | 35,382 |
| ot_ndr/modbus | 15,525 |
| ot_ndr/opcua | 1,170 |
| ot_ndr/s7comm | 520 |
| ot_ndr/dnp3 | 130 |
| ot_snmp/snmp | 83 |
| ot_ndr/port_scan | 1 |

Sigma single-event: **22 / 30** rules had events from their own logsource.

Not exercised (zero events from their logsource, so a zero is not a measurement):
- `rules/sigma/ot/ot_detection_service_down.yml`
- `rules/sigma/ot/ot_firewall_control_zone_egress.yml`
- `rules/sigma/ot/ot_firewall_cross_zone_violation.yml`
- `rules/sigma/ot/ot_firewall_enterprise_control_service.yml`
- `rules/sigma/ot/ot_hmi_login_failure.yml`
- `rules/sigma/ot/ot_host_suspicious_modbus_client.yml`
- `rules/sigma/ot/ot_plc_logic_tampered.yml`
- `rules/sigma/ot/ot_process_safety_violation.yml`

Correlation rules without referenced-service input: `ot_firewall_control_port_scan`, `ot_hmi_login_failure_burst`, `ot_firewall_control_zone_proxy`

## Baseline

The committed baseline flags 13,046 events: it was learned from the generated seed and the lab's assets and pairs are new to it. That is a domain shift, not a false-positive rate.

A baseline learned on the first 6 minutes (14,535 events) and tested on the remaining 38,276 flags **0** events.

Conduit and firewall families are **not exercised**: the capture has packets, not the gateway's iptables log records.

## Native alerts

- none

## Rules with any match

- `New OT Communication Pair`: 13046
- `New OT Source Asset Not In The Behaviour Baseline`: 6328

This is real lab background traffic, not a plant. Host, auth, PLC, health
and firewall families are measured on their own committed samples, not here.
