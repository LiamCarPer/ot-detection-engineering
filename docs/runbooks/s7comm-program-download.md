# Runbook: S7comm Program Download

| Field | Value |
| :-- | :-- |
| Rule | `ot_s7comm_program_download` |
| Technique | T0843 — Program Download |
| Severity | high |
| Data source | `ot_ndr/s7comm` |
| Catalogue | `metadata/detection-catalog.yaml` |
| Status | stable |

## What it means

A program block download reached a Siemens controller (Request Download,
Download Block or Download Ended). Downloading logic is how an attacker persists
on the PLC and changes process behaviour. Outside an engineering change window,
this is a high-severity event.

A download can also be a legitimate firmware or logic update. The change calendar
and the PLC's golden baseline are the deciding evidence, not the alert alone.

## First 5 minutes

1. Read `src_ip`, `function_code`, `pdu_reference` and `parameter_length`.
2. Identify the engineering workstation and the controller.
3. Check the change calendar for a download to that controller.
4. Ask the controls engineer whether a download is in progress.
5. If the download completed, compare the running logic with the golden baseline.

## Validate before escalating

- Confirm the source is the approved engineering workstation.
- Confirm the download has an approved change record.
- Check for a preceding upload or a burst of reads; that is the reconnaissance
  step before a targeted change.
- Check whether the controller changed operating mode or stopped afterwards.

## Containment (OT-safe)

1. Do not power off the controller.
2. If the download is unauthorized, block the source at the gateway and stop
   further downloads.
3. Preserve the S7comm frames, the PDU references and the controller's diagnostic
   buffer.
4. Compare the running program with the offline golden copy.
5. If the logic changed, restore from the verified bundle only with the controls
   engineer's approval.

## False positives and tuning

- A planned engineering change or firmware update.
- A commissioning download to a new controller.
- A backup tool that reads blocks is an upload, not a download; check the
  direction and function code.
- Do not suppress the rule for a source; require a change record instead.

## Close out

- Record the source, controller, PDU references and change reference.
- If unauthorized, treat the controller as compromised until the logic is
  verified.
- If authorized, attach the change record and update the baseline if the change
  is permanent.

## Related rules

- `ot_s7comm_program_upload` — the collection step that often precedes a change.
- `ot_s7comm_change_operating_mode` — a stop or mode change after the download.
- `ot_opcua_method_call` — an alternate execution path on an OPC UA server.

## Last validated

2026-11-24.
