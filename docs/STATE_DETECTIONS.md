# Stateful detections

Five detections need more than a single event or a simple count. They live in
`rules/stateful/` and are evaluated by `tools/otde/stateful.py`:

| Rule | What it needs | Technique |
| :-- | :-- | :-- |
| Process Value Drift From Learned Baseline | Mean/std per asset and consecutive samples | T0831 |
| Engineering Change Outside Approved Window | `metadata/change-calendar.yaml` | T0843 |
| New Protocol Service Or Function On A Known Asset | Per-asset service/function profile | T0846 |
| DNP3 Select Then Operate Pair | Two application functions in one window | T1692.001 |
| Process Safety Envelope | Estimated level and valve state | T0831 |

The family is separate from Sigma because the conditions are not expressible as
`value_count` or `event_count`. Forcing them into a correlation rule would make
the rule look portable while the evaluator silently did something else.

## 1. Process value drift

**Rule:** `rules/stateful/stateful_process_value_drift.yml`

The baseline (`baseline/process-values.json`) records the mean and population
standard deviation of `tank_level_pct` per asset, built from the benign corpus.
The detection fires when a value is at least **3 standard deviations** from the
mean for **3 consecutive samples**.

Why consecutive: a single high reading is a sensor spike; a sustained shift is a
setpoint change, a stuck sensor or a process leaving its envelope.

**Failure modes**

- A real process upset can look exactly like this. The rule is a signal, not a
  substitute for operations.
- A sensor calibration change moves the reading without moving the process.
- A slow drift that stays inside the envelope is out of scope.
- The baseline is from the generated benign corpus, not a plant. It is a
  modelled envelope, not a field baseline.

**Tuning:** `z_threshold`, `consecutive`, `direction`, and the baseline file.
Change them with process engineering, not to clear a ticket.

## 2. Engineering change outside an approved window

**Rule:** `rules/stateful/stateful_engineering_change_window.yml`

`metadata/change-calendar.yaml` is policy as code. A write (Modbus FC 6/16,
S7comm 26/27/28) is approved only when a window matches its source, destination,
service and time. Anything else fires.

This is the detection-engineering counterpart to a change ticket: it does not
try to infer intent from the write, it checks the write against the window the
plant already agreed to.

**Failure modes**

- An emergency change that was not recorded in the calendar.
- A time-zone mistake in the calendar.
- A new engineering workstation not yet named in a window.
- A calendar with no windows will flag every write; that is intentional.

**Tuning:** add a window for an approved change; do not suppress the rule. The
calendar is schema-validated and reviewed like code.

## 3. New protocol service or function on a known asset

**Rule:** `rules/stateful/stateful_asset_protocol_baseline.yml`

`baseline/asset-behaviour.json` records, per destination asset, the services and
function codes seen in benign Suricata samples. A known asset that receives a
new service or a new function code fires.

This is deliberately **per asset**, not per service: a function code that is
normal on one PLC can be new on another. An unknown asset is a different
detection (`rules/baseline/baseline_new_source_asset.yml`).

**Failure modes**

- A firmware or logic update adds a legitimate service.
- A maintenance tool uses a function code outside the baseline period.
- A newly commissioned asset is not in the baseline yet.
- The baseline is built from the small committed benign samples, not a plant.

**Tuning:** regenerate the baseline after an approved protocol change, and review
the diff.

## 4. DNP3 select then operate

**Rule:** `rules/stateful/stateful_dnp3_select_operate.yml`

A DNP3 Select followed by an Operate against the same outstation inside the
declared window is the normal two-step control sequence. The rule pairs the two
functions, so a stray Select or a bare Operate is judged differently from a
complete control operation.

## 5. Process safety envelope

**Rule:** `rules/stateful/stateful_process_safety_envelope.yml`

The mass-balance estimator emits `process_update` samples with the estimated
level, the reported level and the inlet valve state. The rule fires when the
estimate is outside the envelope while the inlet is open, independently of the
PLC's reported level.

## Evidence and reproduction

```bash
python tools/stateful_check.py          # prove every window, rebuild baselines
python tools/stateful_check.py --check  # fail if the committed evidence is stale
make stateful-check                     # the CI gate
```

The evidence is committed at `deploy/evidence/stateful/summary.json`. It records
the five rules, 31 labeled windows, the two change windows, and whether both
baselines are current.

## What this proves and does not

- **Proves:** each rule fires on a labeled positive and stays silent on its
  negatives; the baselines are reproducible from committed benign data; the
  calendar validates.
- **Does not prove:** production accuracy, a real process baseline, or that the
  calendar matches the plant's change-management system.
- **Coverage:** the three techniques are already covered by other rules, so the
  raw ATT&CK count does not move. This is a depth release, not a coverage one.
