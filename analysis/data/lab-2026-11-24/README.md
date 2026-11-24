# Lab snapshot: 2026-11-24

This directory is a pinned copy of the alert logs from
[OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab), taken after a
compliance/attack simulation run. It exists so the alert-flood case study is
reproducible without the lab running.

| Field | Value |
| :--- | :--- |
| Source repository | `https://github.com/LiamCarPer/OT-Security-Lab` |
| Source commit | `df9fae4799b56a7aad7338967421ee4b0430cdda` |
| Captured | 2026-11-24 01:49:40 → 01:52:20 UTC |
| Timezone | UTC; the lab containers emit naive timestamps |
| Scenario | Enterprise pivot, compromised EWS, PowerShell operator write, HMI login failures, detection-service stop |
| Transformations | None; the files are copied as emitted |

## Files

| File | Rows | Use |
| :--- | --: | :--- |
| `alerts.jsonl` | 151 | Primary dataset: one contiguous 160-second burst. |
| `siem_alerts.jsonl` | 364 | Secondary: firing/resolved lifecycle, a different and much longer period. |
| `runtime_evidence.json` | aggregate | Secondary: an earlier run’s totals, used only as corroboration of scale. |
| `manifest.json` | — | SHA-256, byte sizes, line counts and provenance. |

The analysis verifies every file against `manifest.json` before it runs.

## What this is not

- Not production traffic.
- Not a complete lab history; `alerts.jsonl` is one run.
- Not an analyst queue: there are no acknowledgement or resolution timestamps.
- The runtime aggregate is from 2026-10-25, not the 2026-11-24 burst. Do not mix
  the two in one count.

See [`docs/CASE_STUDY_ALERT_FLOOD.md`](../../../docs/CASE_STUDY_ALERT_FLOOD.md)
for the narrative and [`analysis/out/report.md`](../../out/report.md) for the
generated tables.
