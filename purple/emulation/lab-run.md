# Reference lab run

This records the genuine emulation run the committed observations were captured
from. `lab-observations.json` is the raw output of this run; `make metrics`
replays it, so the published detection rate and MTTD come from real lab
telemetry rather than a synthetic fixture.

| Field | Value |
| :--- | :--- |
| Date | 2026-09-13, 20:47 UTC |
| Lab | [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) `6d68b6f` |
| Host | Linux, Europe/Madrid (CEST, +0200) |
| Lab containers | Docker Compose, UTC |
| Plan | `purple/emulation/emulation-plan.yaml` |

## Method

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

## Result

| Step | Technique | Signal | Detected | MTTD (s) |
| :--- | :--- | :--- | :--- | ---: |
| Enterprise pivot, unauthorized Modbus write and I/O brute force | T0886 | CROSS_ZONE_VIOLATION | yes | 0.654 |
| Enterprise pivot, unauthorized Modbus write and I/O brute force | T1692.001 | UNAUTHORIZED_MODBUS_WRITE | yes | 1.677 |
| Enterprise pivot, unauthorized Modbus write and I/O brute force | T0806 | OT_BRUTE_FORCE_SCAN | yes | 4.761 |
| Unsafe command while the process is in a danger state | T0831 | PROCESS_SAFETY_VIOLATION | yes | 2.707 |

Detection rate 4/4 (100%), mean MTTD 2.45 s, max 4.761 s.

## Notes from the run

- The lab detectors run with all capabilities dropped, so the gateway cannot
  write a file owned by the host user. The alert log must be world-writable
  (`chmod 666`) or created by the container.
- The lab containers run in UTC and the detectors emit naive timestamps from
  `datetime.now()`. The runner interprets naive timestamps as UTC, which is why
  MTTD is measured correctly.
