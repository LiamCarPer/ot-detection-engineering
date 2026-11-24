# Operations: one rule end to end

This is the operational path for a stable rule, not a tour of every rule. The
example is `ot_modbus_unauthorized_write` (T1692.001), the highest-volume
unauthorized control write in the lab.

## 1. Catalogue record

From `metadata/detection-catalog.yaml`:

| Field | Value |
| :-- | :-- |
| Rule | `rules/sigma/ot/ot_modbus_unauthorized_write.yml` |
| Title | Modbus Write From Unauthorized Control Writer |
| Severity | high |
| Data source | `ot_ndr/modbus` |
| Owner | Liam Carvajal |
| Status | stable |
| Expected volume | 27 raw / 2 episodes in the 2026-11-24 lab burst |
| Lab alert types | `UNAUTHORIZED_MODBUS_WRITE` |
| Runbook | `docs/runbooks/modbus-unauthorized-write.md` |
| Last validated | 2026-11-24 |

`make health-check` refuses a stable rule without a runbook, observed volume or a
recent validation date.

## 2. What fires

A Modbus request (function code 6 or 16) whose source is not the approved HMI or
engineering workstation. The register and value matter more than the count; a
write to a safety parameter is escalated through the process-safety runbook.

## 3. Triage

1. Read `src_ip`, `dst_ip`, `function_code`, `register`, `value`, `unit_id`.
2. Check the source against the approved writer list.
3. Check the change calendar for a write to that PLC in that window.
4. If the register is in the safety band (≥ 4000), run the process-safety runbook
   in parallel.
5. Check whether the source also enumerated registers or read process state
   first.

The full steps, containment and false-positive guidance are in
[`docs/runbooks/modbus-unauthorized-write.md`](runbooks/modbus-unauthorized-write.md).

## 4. What the lab showed

In the 2026-11-24 burst this alert fired **27 times from two sources**: 23 from
the enterprise pivot and 4 from the operator workstation. The case study collapses
those into **2 episodes**; the important judgment is that the operator-workstation
writes are not suppressed just because they share an alert type with the
enterprise writes.

See [`docs/CASE_STUDY_ALERT_FLOOD.md`](CASE_STUDY_ALERT_FLOOD.md).

## 5. Purple-team validation

The write is covered by the `enterprise-modbus-write` and
`operator-workstation-write` steps in `purple/emulation/emulation-plan.yaml`. The
2026-11-24 run detects both signals; the 2026-09-13 run measured the original
2.45 s MTTD.

```bash
make purple-check
```

## 6. Tuning

| Change | Action |
| :-- | :-- |
| New permanent engineering workstation | Add it to the writer allowlist and the catalogue note; test the change against the purple step. |
| New safety register band | Update the parameter-write rule and the runbook, not this rule. |
| A noisy source | Do not add a blanket suppression; check whether the source is a legitimate writer or a compromised host. |
| A change in architecture | Update the runbook and `last_validated`; re-run `make health`. |

## 7. Rollback

If the rule is causing unacceptable noise:

1. Set `status: deprecated` in the catalogue with a reason.
2. Remove it from the deployed bundle (`make deploy`).
3. Keep the evidence and the runbook for the post-incident review.
4. Add a replacement rule or a narrowed allowlist before re-enabling.

Do not silently delete the rule: the catalogue is the record of what was
deployed.

## 8. Evidence commands

```bash
make health-check
make purple-check
make metrics
```

The rule's operating context is in `deploy/evidence/health/report.md`; its lab
coverage is in `deploy/evidence/purple/`; its volume is in
`analysis/out/rule_health.json`.
