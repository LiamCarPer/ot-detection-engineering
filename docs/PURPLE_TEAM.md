# Purple team

The repository runs three complementary exercises:

| Run | Purpose | Result |
| :-- | :-- | :-- |
| 2026-11-25 | **Live repository rules** | **11 / 12 Sigma expectations across 7 steps, 3 runs**; 0 unexpected; benign windows clean; mean MTTD 2.43 s |
| 2026-11-24 | Lab alert-signal replay | **14 / 14 expected signals across 8 steps**; 0 unexpected alerts; benign window passed |
| 2026-09-13 | MTTD measurement | **4 / 4 expectations**; mean MTTD 2.45 s, max 4.761 s |

The live run is the strongest evidence: the lab's Loki ruler evaluates the
repository's generated rules, and the runner records action start/stop times.
The replay is retained as a regression fixture and is explicitly not a
rule-coverage result. The 2026-09-13 run is the historical MTTD run.

## What the 2026-11-25 live run proves

The runner is [`purple/runner/live_lab.py`](../purple/runner/live_lab.py). It
syncs the generated Loki rules into the lab, clears the ruler lookback state,
runs each step, polls the ruler, and records the first firing time of the
repository's rules.

| Step | Expectations | Detected (3 runs) |
| :-- | --: | --: |
| Enterprise cross-zone read | 1 | 3 / 3 |
| Enterprise Modbus write | 1 | 3 / 3 |
| Process safety violation | 1 | **0 / 3** (untimed stimulus; fixed below) |
| DNP3 control campaign | 3 | 3 / 3 |
| OPC UA discovery campaign | 3 | 3 / 3 |
| S7comm program campaign | 3 | 3 / 3 |
| Operator-workstation write | 1 | 3 / 3 |

- The process-safety miss was timing, not a process-model limitation: the write
  was sent at an arbitrary point in the fill/drain cycle, so the tank was often
  below the envelope. The live stimulus now reads the level and waits for the
  danger band before writing
  (`powershell/Simulate-UnsafeOverflow.ps1` in the lab). It was validated against
  a mock Modbus server, with no lab write; the re-run waits for the 24-hour
  benign capture to avoid contaminating it.
- **No unexpected repository rules** fired in any step.
- The benign-after window was empty in all three runs. The runner restarts Loki
  and clears its data before each run so the five-minute lookback cannot leak
  the previous attack into the benign window.
- Mean MTTD was **2.43 s** (max 3.52 s) at a 1-second ruler evaluation interval.
- **The process-safety miss is real and visible.** The lab's process model is a
  counter with an in-PLC interlock; the simulated attack is dropped at the
  firewall, and the tank level did not reach the repository rule's 90% envelope
  in these runs. P2-08 replaces that model with a mass balance and an
  independent SIS. The step is reported as a miss, not removed from the plan.
- The native Modbus brute-force rule is capture-proven, not Loki-backed, and is
  absent from the live Sigma plan. It remains in the capture evidence.

## What the 2026-11-24 replay actually proves

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
- **One lab, three runs.** The live run executes the generated rules, but one
  Dockerised plant and three repetitions are not a field trial. Wire, wireless
  and vendor-specific protocol variants are not present.

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
