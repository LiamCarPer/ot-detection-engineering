# Purple team

The repository runs two complementary purple-team exercises:

| Run | Purpose | Result |
| :-- | :-- | :-- |
| 2026-11-24 | Lab alert-signal replay | **14 / 14 expected signals across 8 steps**; 0 unexpected alerts; benign window passed |
| 2026-09-13 | MTTD measurement | **4 / 4 expectations**; mean MTTD 2.45 s, max 4.761 s |

They are separate because the 2026-11-24 snapshot has alert timestamps but not
action start timestamps, and the 2026-09-13 run has both. The full method and
per-step tables are in
[`purple/emulation/lab-run.md`](../purple/emulation/lab-run.md).

## What the 2026-11-24 run actually proves

It is a **replay of the lab's recorded alert snapshot**. The runner matches the
lab's `alert_type` labels against the plan and checks the lab's `mitre_id`
against the plan's `lab_technique`. It does **not** execute this repository's
Sigma, native or stateful rules.

What that establishes:

- the eight steps happened in the lab and emitted the expected signal types;
- the plan's rule names and technique tags are consistent with the lab labels;
- no signal type outside the plan appeared inside the derived step windows.

What it does **not** establish:

- that this repository's rules fire on the same traffic;
- the repository's detection rate or MTTD;
- that a rule would stay quiet on new benign traffic.

Those are separate proofs: the decoder/collector evidence runs the repository's
matcher over real decoder and sensor output, and the 2026-09-13 run is the only
one with action start timestamps. The headline should be read as **"14 / 14 lab
alert signals replayed"**, not "14 / 14 rules detected the attack".

### Why the replay is weak as a coverage metric

- Five of the eight step windows are 0.1 seconds wide, and every window is
  derived from the expected alert timestamps. A hit is nearly guaranteed.
- The benign window starts after the capture ends, so it is empty by
  construction.
- "Unexpected" compares against the union of expected types for the whole plan,
  so an expected type firing in the wrong step is not counted as unexpected.
- The matched names are lab `alert_type` values, not repository rule titles.

The replay is kept as a regression fixture and as evidence that the lab run
happened. It is not used as a rule-coverage benchmark.

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

- **Expected signals replayed** — lab alert types in the derived window divided
  by all expectations. The current run is 14 / 14.
- **Unexpected alerts** — any alert in a step window whose type is not expected
  anywhere in the plan. The current run has zero.
- **Benign window** — 30 seconds after the attack run with no expected alerts.
  The current run has zero and passes; the window is not independent of the
  attack, so this is a weak false-positive check.
- **MTTD** — only from the 2026-09-13 run, because it has action start times.

The runner checks the lab's `mitre_id` against the plan's `lab_technique` and
fails on an undeclared mismatch. The rule mapping and the lab label are recorded
separately; see the mapping table in the lab-run notes.

## What is not covered

- **HMI login failures, C2 beacon and OT port scan** appear in the lab snapshot,
  but there is no matching repository rule. They are lab-only detections and are
  deliberately not scored here.
- **No 24/7 SOC or analyst queue.** The run measures signal presence and
  latency, not triage time.
- **The 2026-11-24 windows are derived from alert timestamps.** They prove the
  signals were present in the snapshot; they do not prove the MTTD.
- **The lab is a Dockerised plant.** There is no physical PLC, sensor or
  actuator.
- **The repository rules are not in the loop.** A live run that executes the
  generated rules and measures their detection rate is the next step.

## Reproduce

```bash
make purple          # regenerate the 2026-11-24 replay evidence
make purple-check    # fail if deploy/evidence/purple is stale
make emulate-validate
make metrics         # replays both runs and writes the metrics report
```

The 2026-11-24 replay evidence is committed under
[`deploy/evidence/purple/`](../deploy/evidence/purple/). The 2026-09-13 MTTD
evidence is the recorded observation file and the historical result in
[`purple/emulation/lab-run.md`](../purple/emulation/lab-run.md).
