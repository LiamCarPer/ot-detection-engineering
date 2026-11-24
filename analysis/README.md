# Analysis

This directory contains reproducible analyses over pinned lab data. The first is
the alert-flood case study.

## Run

```bash
make case-study
python analysis/lab_case_study.py --check
```

`make case-study` regenerates the committed outputs; `--check` fails if they
drift from a fresh run.

## Outputs

| Path | What it is |
| :--- | :--- |
| `analysis/out/summary.json` | Machine-readable counts, episodes, campaigns, secondary datasets. |
| `analysis/out/report.md` | Generated tables and timeline. |
| `analysis/out/rule_health.json` | Per-alert-type volume and duplicate ratio; the seed for the Phase 2 detection catalogue. |

## Design

- **Episode:** identical `(alert_type, source, destination)` within 60 seconds.
  A repeat after the window is a new episode.
- **Campaign:** episodes grouped by source with a 10-minute maximum gap.
- **Health event:** an alert with no source that reports a detection producer
  down.
- **No current-time stamps.** The output is deterministic from the snapshot, so
  `--check` is meaningful.

The constants are judgment calls. The case study lists the failure modes,
including the low-and-slow attacker who repeats a signal just outside the
window.

## Data

[`data/lab-2026-11-24/`](data/lab-2026-11-24/) is a pinned snapshot with SHA-256
provenance. It is verified before analysis; a changed input fails before any
count is produced.

See [`docs/CASE_STUDY_ALERT_FLOOD.md`](../docs/CASE_STUDY_ALERT_FLOOD.md).
