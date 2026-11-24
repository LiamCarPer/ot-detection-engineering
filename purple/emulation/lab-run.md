# Reference lab runs

Two runs are committed:

- **2026-11-24 — coverage run.** Eight steps, fourteen expectations, zero
  unexpected alerts, benign window passed. This is the current plan. It is a
  replay of the lab's 2026-11-24 alert snapshot; the snapshot has alert times but
  not action start times, so it does **not** measure MTTD.
- **2026-09-13 — MTTD run.** Two steps, four expectations, 4/4, mean MTTD
  2.45 s. This is the historical run that supplies the MTTD figure.

Keeping them separate is deliberate: the 2026-11-24 data is better for
multi-step coverage, and the 2026-09-13 data is the only run with action start
timestamps.

## 2026-11-24 coverage run

| Field | Value |
| :--- | :--- |
| Date | 2026-11-24, 01:49:40–01:52:20 UTC |
| Lab | [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) `df9fae4` |
| Plan | `purple/emulation/emulation-plan.yaml` (version 2) |
| Observations | `purple/emulation/lab-observations.json` |
| Evidence | `deploy/evidence/purple/` |
| Result | **14 / 14 expectations, 8 steps** |
| Unexpected alerts in step windows | 0 |
| Benign window | 30 s, 0 alerts, passed |
| MTTD | not measured (no action start timestamps) |

### Method

The lab's compliance suite ran the attack scenarios and the gateway wrote
`detection/logs/alerts.json`. The alert snapshot was pinned under
`analysis/data/lab-2026-11-24/` with SHA-256 provenance. For each plan step, a
window was derived from the first and last alert of that scenario. The runner
matches the expected signal, checks the lab's `mitre_id` against the plan's
`lab_technique`, and counts any other alert type inside the window as
unexpected.

### Result

| Step | Expectations | Detected |
| :-- | --: | --: |
| Enterprise cross-zone | 1 | 1 |
| Enterprise Modbus write | 1 | 1 |
| Enterprise brute force | 1 | 1 |
| Process safety violation | 1 | 1 |
| DNP3 control campaign | 3 | 3 |
| OPC UA discovery campaign | 3 | 3 |
| S7comm program campaign | 3 | 3 |
| Operator-workstation write | 1 | 1 |

The lab also emitted HMI-login, C2-beacon and OT-port-scan alerts. Those are
lab-only detections with no matching repository rule, so they are not scored in
this plan. They are visible in the source snapshot and are a deliberate,
documented gap.

### Notes

- **Do not report this run's MTTD.** The snapshot has alert timestamps, not the
  time the adversary action started. The runner correctly returns `null`.
- The step windows are narrow and derived from the alert data, so the coverage
  result is a statement about whether the plan's signals were present, not about
  how quickly they fired.
- The lab's ground-truth `mitre_id` can differ from the repository rule mapping;
  the plan records both and the runner fails on an undeclared mismatch.

## 2026-09-13 MTTD run

| Field | Value |
| :--- | :--- |
| Date | 2026-09-13, 20:47 UTC |
| Lab | OT-Security-Lab `6d68b6f` |
| Plan | `purple/emulation/emulation-plan-2026-09-13.yaml` |
| Observations | `purple/emulation/lab-observations-2026-09-13.json` |
| Result | **4 / 4 expectations** |
| Mean MTTD | **2.45 s** |
| Max MTTD | 4.761 s |

### Method

1. `docker compose up -d` in `ot-security-lab/lab-environment`; wait until Scapy
   is importable in `ot_gateway` and `ot_attacker`.
2. Apply `network-config/firewall-rules.sh` and add the attacker pivot routes.
3. Truncate `detection/logs/alerts.json` and start the four detectors detached
   in the gateway: `cross_zone_traffic`, `modbus_anomaly`, `ot_brute_force`,
   `process_safety_violation`.
4. Run:

   ```bash
   python purple/runner/run_emulation.py --execute \
     --alerts <lab>/detection/logs/alerts.json --settle-seconds 5
   ```

### Result

| Step | Technique | Signal | Detected | MTTD (s) |
| :--- | :--- | :--- | :--- | ---: |
| Enterprise pivot, unauthorized Modbus write and I/O brute force | T0886 | CROSS_ZONE_VIOLATION | yes | 0.654 |
| Enterprise pivot, unauthorized Modbus write and I/O brute force | T1692.001 | UNAUTHORIZED_MODBUS_WRITE | yes | 1.677 |
| Enterprise pivot, unauthorized Modbus write and I/O brute force | T0806 | OT_BRUTE_FORCE_SCAN | yes | 4.761 |
| Unsafe command while the process is in a dangerous state | T0831 | PROCESS_SAFETY_VIOLATION | yes | 2.707 |

Detection rate 4/4 (100%), mean MTTD 2.45 s, max 4.761 s.

### Technique mapping

The plan records two techniques per expectation:

- `technique` is the ATT&CK mapping of the **repository rule**, validated by
  `validate_plan` against the rule's own tags.
- `lab_technique` is the label on the **lab's ground-truth alert**, checked
  against the alert's `mitre_id` at evaluation time.

| Signal | Rule mapping | Lab `mitre_id` | Why they differ |
| :-- | :-- | :-- | :-- |
| `CROSS_ZONE_VIOLATION` | T0886 | T0886 | Same framing: lateral movement. |
| `UNAUTHORIZED_MODBUS_WRITE` | T1692.001 | T0831 | The rule detects the unauthorized command; the lab labels the manipulation of control. |
| `OT_BRUTE_FORCE_SCAN` | T0806 | T0846 | The native rule treats the exception burst as brute force; the lab labels the reconnaissance. |
| `PROCESS_SAFETY_VIOLATION` | T0831 | T0836 | The rule classifies the manipulation; the lab labels the impact on process control. |

## Notes from the 2026-09-13 run

- The lab detectors run with all capabilities dropped, so the gateway cannot
  write a file owned by the host user. The alert log must be world-writable
  (`chmod 666`) or created by the container.
- The lab containers run in UTC and the detectors emit naive timestamps from
  `datetime.now()`. The runner interprets naive timestamps as UTC, which is why
  MTTD is measured correctly.
