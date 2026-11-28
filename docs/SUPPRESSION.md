# Suppression

The generated rules are intentionally fine-grained. This page describes the
queue layer that turns them into decisions, and what the policy does not prove.

## Policy

The policy is [`metadata/alertmanager-ot-inhibit.yml`](../metadata/alertmanager-ot-inhibit.yml),
installed as the lab's Alertmanager configuration.

- **Group by** `alertname`, `severity`, `src_ip`, `dst_ip`, `dst_zone`. A repeat
  from the same entity is one notification; a new source or destination is a new
  group.
- **Critical events** (safety, sensor health) bypass the normal wait with
  `group_wait: 0s`.
- **Repeat interval** is four hours for normal groups, one hour for critical.
- **Inhibit rules** collapse repeated `CROSS_ZONE_VIOLATION` by source and
  destination, and repeated `UNAUTHORIZED_MODBUS_WRITE` by source. The
  sensor-health and process-safety events are deliberately not inhibited.

## Result on the case-study snapshot

| View | Count |
| :-- | --: |
| Raw alerts | 151 |
| Notifications under the group key | 21 |
| Reduction | 86.09% |

The case study's 24 episodes are a 60-second time-window rollup. The 21 are the
unique groups under the policy's five-label key (`alertname`, `severity`,
`src_ip`, `dst_ip`, `dst_zone`). The snapshot has no severity or zone labels, so
severity is resolved from the detection catalogue (unknown stays unknown) and
zone from the asset inventory. The five operational events remain the analyst's
campaign rollup.

## Preserved signals

| Signal | Alerts |
| :-- | --: |
| C2 HMI login failures | 3 |
| C3 protocol chain from `172.23.0.20` | 34 |
| C4 operator-workstation writes from `172.22.0.30` | 4 |
| C5 sensor health | 1 |

C4 is the test that matters: it is the same alert type as the C1 writes but a
different source, so a suppression rule that keyed on alert type alone would hide
it. The group key includes the source.

## Reproduce

```bash
python analysis/suppression.py   # writes analysis/out/suppression.json and .md
make suppression
```

## What this does not prove

- It is an **offline grouping model** of the declared key, not a replay through
  a live Alertmanager instance. `group_wait`, repeat intervals and inhibit rules
  are not simulated; the policy is validated with `amtool check-config`, but the
  notification counts are a model.
- The lab's alert names and the generated rule names differ; the inhibit
  matchers cover both, but a new rule name must be added to the policy.
- The group key does not include the register. The first alert in a group carries
  the register in its annotations; a new register from the same source inside the
  group interval is collapsed. The runbook tells the analyst to inspect the
  group's annotations.
- Suppression reduces notifications, not the need to triage. The five
  operational events are still five decisions.
