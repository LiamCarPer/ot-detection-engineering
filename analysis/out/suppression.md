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

The grouping key is the policy's `group_by` list: `alertname`, `severity`, `src_ip`, `dst_ip`, `dst_zone`.

The snapshot has no `severity` label or `dst_zone`; severity is resolved
from the detection catalogue (unknown stays unknown) and zone from the
asset inventory. This is a grouping model, not an Alertmanager replay:
`group_wait`, repeat intervals and inhibit rules are not simulated.
