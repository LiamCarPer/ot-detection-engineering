# Case study: 151 alerts in 160 seconds

**What this is.** A reproducible triage analysis of a real lab run: 151 alerts
across 17 types from four sources in 160 seconds. The raw queue is not 151
incidents. It is **24 timed episodes** and **five operational events** — four
adversary campaigns and one sensor-health event. This document explains how that
reduction was computed, what I would suppress, what I would keep, and what the
analysis does not prove.

- **Data:** [`analysis/data/lab-2026-11-24/`](../analysis/data/lab-2026-11-24/)
- **Generated analysis:** [`analysis/out/report.md`](../analysis/out/report.md)
- **Reproduce:** `make case-study`
- **Lab:** [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab)
  at `df9fae4`, captured 2026-11-24 01:49:40–01:52:20 UTC.

## The raw queue

| Metric | Value |
| :-- | --: |
| Raw alerts | **151** |
| Alert types | 17 |
| Sources | 4 |
| Window | 160.3 s |
| Alerts per source | 109, 34, 4, 3 (plus 1 source-less health alert) |
| Alerts per alert type | 74 max (`CROSS_ZONE_VIOLATION`) |

The top of the queue is dominated by one source:

| Alert type | Raw | Episodes (60 s) | Duplicate ratio |
| :-- | --: | --: | --: |
| `CROSS_ZONE_VIOLATION` | 74 | 6 | 0.9189 |
| `UNAUTHORIZED_MODBUS_WRITE` | 27 | 2 | 0.9259 |
| `PROCESS_SAFETY_VIOLATION` | 7 | 1 | 0.8571 |
| `DNP3_UNAUTHORIZED_CONTROL` | 6 | 1 | 0.8333 |
| `S7COMM_PROGRAM_DOWNLOAD` | 6 | 1 | 0.8333 |
| `S7COMM_PROGRAM_UPLOAD` | 6 | 1 | 0.8333 |

**84.1% of the 151 alerts are repeats of a signal already seen inside a
one-minute window.** That is the problem this case study addresses: not a lack
of detections, but a queue that hides the four distinct campaigns inside one
source's noise.

## Method

The analysis is deliberately simple and documented:

1. **Normalize.** `alerts.jsonl` uses `alert_type`; the secondary SIEM log uses
   `alertname`. Both become `(timestamp, alert_type, source, destination,
   technique)`.
2. **Episode.** Collapse identical `(alert_type, source, destination)` alerts
   within **60 seconds** into one episode, keeping first/last and a raw count. A
   repeat after 60 seconds is a new episode; this is not a permanent dedupe.
3. **Campaign.** Group episodes by source, with a **10-minute** maximum gap. A
   campaign is an operational cluster, not a formal incident.
4. **Health event.** An alert with no source that reports a detection producer
   down (`DETECTION_SERVICE_DOWN`) becomes its own operational event.

The constants are in `analysis/lab_case_study.py`. They are a judgment call, and
the failure mode is listed below.

## The five operational events

| ID | Source | What it is | Raw | Episodes | Techniques |
| :-- | :-- | :-- | --: | --: | :-- |
| C1 | `172.24.0.10` | Enterprise pivot: cross-zone, unauthorized Modbus write, brute force, safety violation | 109 | 10 | T0831, T0836, T0846, T0886 |
| C2 | `172.24.0.30` | HMI credential attack | 3 | 1 | T0859 |
| C3 | `172.23.0.20` | Compromised EWS: DNP3, S7comm, OPC UA, port scan, C2 beacon | 34 | 11 | T0816, T0843, T0845, T0846, T0858, T0869, T0871, T0878, T0888, T1692.001 |
| C4 | `172.22.0.30` | Operator-workstation PowerShell Modbus write | 4 | 1 | T0831 |
| C5 | — | Detection producer down | 1 | 1 | T0881 |

**C1 and C3 are the important ones.** C1 is 72% of the raw queue but only 10
distinct signals. C3 is smaller in raw volume but carries **ten techniques in 64
seconds** — a multi-protocol campaign that a source-level or alert-type-level
rollup would flatten into a single "protocol alert."

## What the policy suppresses

The grouping policy is implemented in
[`deploy/alertmanager/ot-inhibit.yml`](../deploy/alertmanager/ot-inhibit.yml) and
measured in [`docs/SUPPRESSION.md`](SUPPRESSION.md). On this snapshot it produces
**21 notifications from 151 alerts (86.09% reduction)** and preserves C2, C3, C4
and C5. The table below is the judgment behind that policy.

| Proposal | Why | What I would keep |
| :-- | :-- | :-- |
| Collapse repeated `CROSS_ZONE_VIOLATION` from the same source/destination inside 60 s to one episode | 74 → 6 episodes (92% reduction); the repeats add no new decision | First episode, and any new destination or zone pair |
| Collapse repeated `UNAUTHORIZED_MODBUS_WRITE` from the same source inside 60 s | 23 C1 writes → 1 episode; 92.6% duplicate | First write, the target register, and the **C4 writes from a different source** |
| Collapse repeated `PROCESS_SAFETY_VIOLATION` with the same command and state | 7 → 1 episode; 85.7% duplicate | First violation, and any change in tank level, register or command |
| Collapse repeated per-protocol alerts from one source inside 60 s | DNP3/S7/OPC UA each collapse to one episode per type | The **sequence**: DNP3 control/restart/unsolicited → S7 download/upload/mode → OPC UA browse/write/call → C2 beacon |

## What I would not suppress

- **C4's four Modbus writes.** They look like the 23 writes from C1 by alert type,
  but the source is different. Suppressing by alert type alone would hide an
  approved-looking operator workstation making unauthorized writes.
- **C3's technique chain.** The individual alerts are low-volume (2–6 each), and
  the value is the sequence, not the count. A single "protocol anomaly" rollup
  would lose the progression from discovery to control to collection.
- **C2's three HMI login failures.** Low volume, but the only credential signal in
  the window.
- **C5's sensor-down event.** It has no source and no attack technique in the
  usual sense, but a stopped detection producer is an inhibit-response event: the
  queue is now blind. Suppressing it because it is "just one alert" is the worst
  possible choice.
- **The first occurrence of every campaign.** Dedupe must reduce repeats, not
  erase the signal that starts the investigation.

## Before and after

| View | Count | Reduction |
| :-- | --: | --: |
| Raw alerts | 151 | — |
| Episodes (60 s) | 24 | **84.1%** |
| Operational events (campaigns + health) | 5 | **96.7%** |

The 5 is the number an analyst would work. The 24 is the number a reviewer should
use to check that the 5 did not hide a distinct signal. The report keeps both, so
the reduction is auditable.

## What the analyst does next

The analysis maps cleanly onto the lab's
[incident-response playbook](https://github.com/LiamCarPer/OT-Security-Lab/blob/main/incident-response/ir-playbook-unauthorised-plc-change.md):

| Event | First action |
| :-- | :-- |
| C1 | Isolate `172.24.0.10` at the gateway; verify the PLC register and tank state; check the safety violation. |
| C2 | Lock the HMI account; review the source `172.24.0.30`; check for successful logins after the failures. |
| C3 | Isolate `172.23.0.20`; verify PLC logic against the golden baseline after the S7 download; block the C2 destination. |
| C4 | Isolate `172.22.0.30`; verify the written register; check the workstation for the PowerShell script. |
| C5 | Restart the detection producer; confirm the sensor is healthy before trusting the queue again. |

This is the part a per-alert queue loses: the actions are campaign-level, not
alert-level.

## What this does not prove

- It is **lab data**, not plant traffic. The lab is a Dockerised water-treatment
  range.
- There are **no analyst action timestamps**, so this does not compute MTTA or
  "time saved." It computes queue reduction, not human performance.
- The 60-second episode window is a **judgment call**. A low-and-slow attacker
  who repeats one signal every 61 seconds would not be collapsed; that is
  intentional, and it is why the raw counts remain in the report.
- The campaign labels are **human interpretations** of the lab's scenarios, not
  fields the lab emits.
- The SIEM lifecycle section is a separate, months-long log of **364 rows**
  (305 firing, 59 resolved). It is not the 160-second burst and is not used for
  the campaign count.
- The runtime aggregate (581 alerts, 2026-10-25) is a different run and is cited
  only as corroboration of scale.

## What Phase 2 uses

`analysis/out/rule_health.json` is the seed for the detection catalogue:

- per-rule raw volume;
- episodes and duplicate ratio;
- unique sources;
- first/last seen.

Phase 2 will add owner, severity, data dependency, runbook and expected volume,
and use this file to flag rules that are noisy, silent or stale.

## Reproduce

```bash
make case-study
python analysis/lab_case_study.py --check
```

`--check` fails when the committed report, summary or rule-health seed differs
from a fresh run. The snapshot hashes are verified before analysis.
