# Lab benign capture

Capture: `/media/liamcarvajal/Storage/code/ot-security-lab/detection/logs/benign-24h.pcap`  
SHA-256: `42dbea21d4550937f5a65b7032a5a973143e32d8660133fc2e7b726773bd12bc`  
Size: 1,099,348,789 bytes  
Window: 2026-11-25T03:45:31.738057+00:00 to 2026-11-26T05:12:39.622770+00:00 (25.45 h)  
Normalized events: 1,136,470 (44651.17 / h)

| Family | Result | Input |
| :-- | :-- | :-- |
| Sigma single-event | 0 / 1136470 events | 9 / 30 rules |
| Sigma correlation | 0 fired | 3 / 7 rules |
| Committed baseline (domain shift) | 159785 events | yes |
| Lab-trained baseline | 0 / 1041580 test events | train 94890 |
| Conduit | 0 events | no firewall events |
| Stateful | 0 fired | 2 / 5 rules |
| Native Suricata | 0 alerts | protocols present |
| Host/auth/PLC/health | not observed in a network capture | n/a |

## Input coverage

| Service | Events |
| :-- | --: |
| ot_flow/flow | 890,723 |
| ot_ndr/modbus | 245,747 |

Sigma single-event: **9 / 30** rules had events from their own logsource.

Not exercised (zero events from their logsource, so a zero is not a measurement):
- `rules/sigma/ot/ot_detection_service_down.yml`
- `rules/sigma/ot/ot_dnp3_request_from_unapproved_master.yml`
- `rules/sigma/ot/ot_dnp3_restart_command.yml`
- `rules/sigma/ot/ot_dnp3_unauthorized_control.yml`
- `rules/sigma/ot/ot_dnp3_unsolicited_disabled.yml`
- `rules/sigma/ot/ot_firewall_control_zone_egress.yml`
- `rules/sigma/ot/ot_firewall_cross_zone_violation.yml`
- `rules/sigma/ot/ot_firewall_enterprise_control_service.yml`
- `rules/sigma/ot/ot_hmi_login_failure.yml`
- `rules/sigma/ot/ot_host_suspicious_modbus_client.yml`
- `rules/sigma/ot/ot_opcua_browse_request.yml`
- `rules/sigma/ot/ot_opcua_method_call.yml`
- `rules/sigma/ot/ot_opcua_write_request.yml`
- `rules/sigma/ot/ot_plc_logic_tampered.yml`
- `rules/sigma/ot/ot_process_safety_violation.yml`
- `rules/sigma/ot/ot_s7comm_change_operating_mode.yml`
- `rules/sigma/ot/ot_s7comm_program_download.yml`
- `rules/sigma/ot/ot_s7comm_program_upload.yml`
- `rules/sigma/ot/ot_snmp_config_change.yml`
- `rules/sigma/ot/ot_snmp_device_restart.yml`
- `rules/sigma/ot/ot_snmp_interface_down.yml`

Correlation rules without referenced-service input: `ot_firewall_control_port_scan`, `ot_opcua_node_enumeration`, `ot_hmi_login_failure_burst`, `ot_firewall_control_zone_proxy`

## Baseline

The committed baseline flags 159,785 events: it was learned from the generated seed and the lab's assets and pairs are new to it. That is a domain shift, not a false-positive rate.

A baseline learned on the first 120 minutes (94,890 events) and tested on the remaining 1,041,580 flags **0** events.

Conduit and firewall families are **not exercised**: the capture has packets, not the gateway's iptables log records.

## Native alerts

- none

## Rules with any match

- `New OT Communication Pair`: 159785
- `New OT Source Asset Not In The Behaviour Baseline`: 73800

This is real lab background traffic, not a plant. Host, auth, PLC, health
and firewall families are measured on their own committed samples, not here.
