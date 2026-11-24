# Purple team

The repository runs two complementary purple-team exercises:

| Run | Purpose | Result |
| :-- | :-- | :-- |
| 2026-11-24 | Multi-step detection coverage | **14 / 14 expectations across 8 steps**; 0 unexpected alerts; benign window passed |
| 2026-09-13 | MTTD measurement | **4 / 4 expectations**; mean MTTD 2.45 s, max 4.761 s |

They are separate because the 2026-11-24 snapshot has alert timestamps but not
action start timestamps, and the 2026-09-13 run has both. The full method and
per-step tables are in
[`purple/emulation/lab-run.md`](../purple/emulation/lab-run.md).

## What the 2026-11-24 run covers

| Step | What the adversary does | Expected repo rule |
| :-- | :-- | :-- |
| `enterprise-cross-zone` | Enterprise host reaches the control zone | `ot_firewall_cross_zone_violation` |
| `enterprise-modbus-write` | Unauthorized Modbus write | `ot_modbus_unauthorized_write` |
| `enterprise-brute-force` | Modbus exception burst | native `modbus_dpi.rules` |
| `process-safety-violation` | Valid command that violates the process envelope | `ot_process_safety_violation` |
| `dnp3-control-campaign` | DNP3 control, restart, disable unsolicited | `ot_dnp3_*` |
| `opcua-discovery-campaign` | Browse, write, method call | `ot_opcua_*` |
| `s7-program-campaign` | Download, upload, mode change | `ot_s7comm_*` |
| `operator-workstation-write` | PowerShell Modbus write from the operator workstation | `ot_modbus_unauthorized_write` |

## What is measured

- **Detection rate** — expected signals that fired divided by all expectations.
- **Unexpected alerts** — any alert in a step window whose type is not expected
  anywhere in the plan. The current run has zero.
- **Benign window** — 30 seconds after the attack run with no expected alerts.
  The current run has zero and passes.
- **MTTD** — only from the 2026-09-13 run, because it has action start times.

The runner checks the lab's `mitre_id` against the plan's `lab_technique` and
fails on an undeclared mismatch. The rule mapping and the lab label are recorded
separately; see the mapping table in the lab-run notes.

## What is not covered

- **HMI login failures, C2 beacon and OT port scan** appear in the lab snapshot,
  but there is no matching repository rule. They are lab-only detections and are
  deliberately not scored here.
- **No 24/7 SOC or analyst queue.** The run measures detection coverage and
  latency, not triage time.
- **The 2026-11-24 windows are derived from alert timestamps.** They prove the
  signals were present in the snapshot; they do not prove the MTTD.
- **The lab is a Dockerised plant.** There is no physical PLC, sensor or
  actuator.

## Reproduce

```bash
make purple          # regenerate the 2026-11-24 coverage evidence
make purple-check    # fail if deploy/evidence/purple is stale
make emulate-validate
make metrics         # replays both runs and writes the metrics report
```

The 2026-11-24 coverage evidence is committed under
[`deploy/evidence/purple/`](../deploy/evidence/purple/). The 2026-09-13 MTTD
evidence is the recorded observation file and the historical result in
[`purple/emulation/lab-run.md`](../purple/emulation/lab-run.md).
