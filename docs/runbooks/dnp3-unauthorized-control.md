# Runbook: DNP3 Unauthorized Control

| Field | Value |
| :-- | :-- |
| Rule | `ot_dnp3_unauthorized_control` |
| Technique | T1692.001 — Unauthorized Command Message |
| Severity | high |
| Data source | `ot_ndr/dnp3` |
| Catalogue | `metadata/detection-catalog.yaml` |
| Status | stable |

## What it means

A DNP3 Select, Operate, Direct Operate or Direct Operate No Ack came from a link
address outside the approved master set. DNP3 control functions change physical
outputs; an unexpected master is either a compromised host or an unauthorized
engineering change.

The link address is not the whole identity. A rogue master can reuse an approved
link address from a different transport address, which is why the catalogue also
contains the transport-level T0848 rule.

## First 5 minutes

1. Read `link_source`, `link_destination`, `function_code`, `object_group`,
   `control_code` and, when present, `src_ip`.
2. Check `link_source` against the approved master set.
3. Check the transport source against the approved master hosts.
4. Identify the outstation and the physical point the control code targets.
5. Check whether the same source also issued a restart or disabled unsolicited
   responses.

## Validate before escalating

- Confirm this is a request, not an outstation response.
- Confirm the source is not a newly commissioned master.
- Check the change calendar for a control operation at that outstation.
- Check the outstation state and the physical output; a Select alone does not
  change the output, an Operate does.

## Containment (OT-safe)

1. Do not power off the outstation.
2. Block the source at the gateway.
3. Ask operations to verify the physical output state.
4. If the operation succeeded, follow the site's process-safety procedure.
5. Preserve the DNP3 frames and the transport flow.

## False positives and tuning

- A newly commissioned master not yet added to the allowlist.
- A master that changes its link or transport address during a migration.
- A test harness that uses a documented control address during commissioning.
- Keep the link-address and transport-address allowlists separate; a single
  allowlist hides the rogue-master case.

## Close out

- Record the master, outstation, function, object and physical result.
- If unauthorized, rotate the master's credentials and review the host.
- If authorized, update the allowlist and the change record together.

## Related rules

- `ot_dnp3_request_from_unapproved_master` — the transport-identity counterpart.
- `ot_dnp3_restart_command` — a disruptive follow-on.
- `ot_dnp3_unsolicited_disabled` — a visibility-reduction follow-on.

## Last validated

2026-11-24.
