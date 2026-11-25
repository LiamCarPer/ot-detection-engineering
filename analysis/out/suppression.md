# Suppression result

Source: `analysis/data/lab-2026-11-24/alerts.jsonl`  
Policy: `deploy/alertmanager/ot-inhibit.yml`

| View | Count |
| :-- | --: |
| Raw alerts | 151 |
| Notifications under the group key | 21 |
| Reduction | 86.09% |

## Preserved signals

| Signal | Alerts |
| :-- | --: |
| C2_hmi_login | 3 |
| C3_protocol_chain | 34 |
| C4_operator_write | 4 |
| C5_sensor_health | 1 |

The grouping key is `(alert_type, source, destination)`, the same key as
the case study's 60-second episode. A new source or destination is a new
group; the sensor-health and process-safety events are not in an inhibit
rule.
