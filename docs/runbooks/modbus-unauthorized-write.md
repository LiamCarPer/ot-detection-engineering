# Runbook: Modbus Unauthorized Write

| Field | Value |
| :-- | :-- |
| Rule | `ot_modbus_unauthorized_write` |
| Technique | T1692.001 — Unauthorized Command Message |
| Severity | high |
| Data source | `ot_ndr/modbus` |
| Catalogue | `metadata/detection-catalog.yaml` |
| Status | stable |

## What it means

A Modbus write (function code 6 or 16) reached a PLC from a host that is not an
approved control writer. In a segmented plant, writes should come only from the
HMI or the engineering workstation. Any other source is either a compromised
host or an unauthorized engineering change.

The register and value matter more than the count. A write to a coil may toggle a
pump; a write to a holding register may change a setpoint or a safety parameter.

## First 5 minutes

1. Read `src_ip`, `dst_ip`, `function_code`, `register`, `value` and `unit_id`.
2. Check the source against the approved writer list in the rule. A new
   engineering workstation is a legitimate explanation until the change is
   confirmed.
3. Check the change calendar for a write to that PLC in that window.
4. If the register is in the safety band (>= 4000), treat it as critical and
   follow the process-safety runbook in parallel.
5. Check whether the same source also read registers or enumerated assets first.

## Validate before escalating

- Confirm this is a request, not a response.
- Confirm the source is not a NAT or proxy that hides the real writer.
- Compare the written value with the last known good value and the process state.
- Look for a matching `ot_process` event. A write that violates the physical
  envelope is more urgent than the protocol alert alone.

## Containment (OT-safe)

1. Do not power off the PLC.
2. Block the source at the gateway; leave the controller running.
3. Ask plant operations to verify the physical state of the affected valve,
   pump or setpoint.
4. If the write changed a safety parameter, follow the process-safety escalation.
5. Preserve the transaction, the register value and the operator's screen.

## False positives and tuning

- A newly commissioned workstation that is not yet in the writer allowlist.
- An asset migration that changes the HMI's source address.
- A legitimate engineering change outside the rule's visibility; the change
  calendar is the control, not a permanent suppression.
- Tune the allowlist per site, not per alert. Never add a source just to clear a
  ticket.

## Close out

- Record the source, register, old value, new value and authorization.
- If unauthorized, rotate the source's credentials and review the EWS/HMI.
- If authorized, add the change reference to the ticket and update the allowlist
  only if the source is a permanent writer.

## Related rules

- `ot_modbus_parameter_write` — a write to the safety band from any writer.
- `ot_modbus_register_enumeration` — the reads that often precede a write.
- `ot_process_safety_violation` — the physical consequence.

## Last validated

2026-11-24.
