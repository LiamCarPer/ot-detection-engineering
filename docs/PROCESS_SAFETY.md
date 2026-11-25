# Process safety without trusting the sensor

The repository's process-safety rule classifies an unsafe command: the inlet
valve opened while the tank is at or above its envelope. The rule is only as good
as the level it is given.

## The problem with a shadow

The lab's first monitor shadowed the level that the PLC reports. That is cheap
and it works until the reported value is wrong. A stuck transmitter, a
mis-calibrated sensor or an insider who pins the holding register makes the
monitor quiet exactly when the process is dangerous. The lab's process-safety
step was a consistent live miss for a related reason: the write was not timed
against the level.

## The estimator

`services/process/mass_balance.py` estimates the level from the measured flows:

```
level(t + dt) = level(t) + (inlet_flow - outlet_flow) / capacity * dt
```

It never reads the reported level. Each event carries both values and their
difference, so an operator can see a divergence, and the existing safety rule
evaluates the envelope on the estimate.

## Model result

Three simulated scenarios, run through the committed
`ot_process_safety_violation` rule:

| Scenario | Rule detections | Shadow would detect | Max divergence |
| :-- | --: | :--: | --: |
| Normal fill/drain cycle | 0 | no | 0.0% |
| External open at a high level | 1 | yes | 0.0% |
| External open with a spoofed level | 1 | **no** | 60.0% |

In the spoof scenario the reported level is pinned near 40%. A shadow monitor
sees a safe tank and stays quiet. The mass balance reaches 94% and the rule
fires, with the reported value recorded on the alert.

## What this is not

- A two-flow tank model, not a plant. Capacity, density and geometry are
  simplified; the constants must be calibrated per tank.
- Offline evidence. The live lab run is separate.
- A replacement for the PLC's independent safety instrumented system. It is a
  detection-layer estimate, not a certified trip; the controller's own interlock
  still owns the physical trip.

## Reproduce

```bash
make process-model        # rewrite deploy/evidence/process-model/
make process-model-check  # fail if the evidence drifts
```
