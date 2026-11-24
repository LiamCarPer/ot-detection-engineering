# Runbook: Process Safety Violation

| Field | Value |
| :-- | :-- |
| Rule | `ot_process_safety_violation` |
| Technique | T0831 — Manipulation of Control |
| Severity | critical |
| Data source | `ot_process/safety_monitor` |
| Catalogue | `metadata/detection-catalog.yaml` |
| Status | stable |

## What it means

A command was protocol-valid and came from an authorized writer, but it violates
the physical safety envelope of the process — for example, opening an inlet valve
while the tank is at overflow capacity. Every individual field is legitimate, so
IP allowlists and protocol validation cannot catch this class of event.

This is a safety alert first and a cyber alert second. The physical process takes
priority over evidence collection.

## First 5 minutes

1. Read `asset`, `register`, `value`, `tank_level_pct`, `actor` and `response`.
2. Confirm whether the process is still in the unsafe state or the monitor
   auto-mitigated it.
3. Call plant operations. Ask for a physical verification of the valve, pump and
   tank level; do not trust the HMI alone.
4. If the process is out of control, follow the site's emergency manual shutdown
   procedure using the physical controls.
5. Preserve the event, the process values and the operator's screen.

## Validate before escalating

- Confirm the monitor is reading live PLC data, not a stale shadow.
- Check the historian for the same time window: does the trend match the alert?
- Check whether a human override or maintenance procedure explains the command.
- Check whether the actor wrote other registers or changed the PLC program.

## Containment (OT-safe)

1. **Do not power off the PLC.** Sudden loss of logic can cause water hammer, pipe
   bursts or a spill.
2. Shift control to manual/local where the process allows it.
3. Isolate the actor at the gateway, not at the controller.
4. Keep the physical safety system in control until operations confirms the
   process is stable.
5. Preserve a packet capture and the historian window.

## False positives and tuning

- A sensor that is drifting or stuck will look like a real unsafe state. Compare
  against a second measurement if one exists.
- A deliberate override during a documented emergency is a valid exception, but
  it still needs a ticket and a post-incident review.
- Tune the safety envelope with process engineering, not with the detection team
  alone.

## Close out

- Record the physical state, the command, the actor and the response.
- If the actor was unauthorized, follow the unauthorized-write runbook.
- If the monitor missed a later state change, record it as a detection gap.
- Update the baseline only after the process is stable and the change is approved.

## Related rules

- `ot_modbus_unauthorized_write` — the same write from an unauthorized source.
- `ot_modbus_parameter_write` — a write to the safety parameter band.
- `ot_dnp3_unauthorized_control` / `ot_s7comm_change_operating_mode` — other
  control-path changes.

## Last validated

2026-11-24.
