# Lab benign capture

The generated corpus is a model. This is the real-traffic counterpart: a PCAP
captured at the lab gateway, with no adversary traffic, normalized through the
collector and run through every network detection family.

## Method

- Capture on every non-loopback gateway interface with a Scapy `PcapWriter`
  (`ot-security-lab/lab-environment/scripts/benign_capture.py`). The gateway is
  the only multi-homed container, so it sees every inter-zone flow. A routed
  frame is recorded twice, on the ingress and the egress interface; the raw
  packet count is therefore roughly doubled. Suricata and Zeek normalize per
  flow, so the family measurements count flows, not frames.
- No attack scenario is run during the capture. The lab's normal HMI, historian
  and simulator polling is the background traffic.
- Run Suricata with the repository's rules and Zeek over the capture; normalize
  both through `collector/`.
- Apply the same all-family FPR functions as `metrics/fpr.py`.
- Host, auth, PLC-diagnostic and sensor-health events are not present in a
  network capture; the report labels them **not observed**, not clean.

## Pilot result

The pilot is 9.5 minutes of background traffic (7.37 MB, 13,949 normalized
events, 88,305 events/hour):

| Family | Result |
| :-- | --: |
| Sigma single-event | 0 / 13,949 events |
| Sigma correlation | 0 fired |
| Behaviour baseline | 0 events |
| Conduit | 0 events |
| Stateful | 0 fired |
| Native Suricata | 0 alerts |

The committed evidence under `deploy/evidence/benign-lab/` is the last completed
capture: the report records its observed span, so the pilot and the 24-hour run
cannot be confused. The pilot was a pipeline validation and a first real-traffic
result; the 24-hour run replaces it when the writer stops.

## 24-hour run

The 24-hour capture is at
`ot-security-lab/detection/logs/benign-24h.pcap`. When it completes:

```bash
make lab-benign-check LAB_PCAP=/path/to/benign-24h.pcap
```

This rewrites `deploy/evidence/benign-lab/` with the full capture. The report
records the capture hash, size, observed span, normalized event rate and
per-family result. `scripts/finalize_benign_capture.sh` performs the same step
once the writer stops and the PCAP has been idle for five minutes; it is safe to
leave running because it only waits and then reads the file.

## What this does not prove

- One Dockerised lab, not a plant. There is no physical process, no enterprise
  background load beyond the lab's containers, and no 24/7 operation.
- The network capture cannot see host, auth, PLC diagnostics or sensor health;
  those families are measured on their own samples.
- Suricata and Zeek are the sensors; a different sensor mix will produce a
  different field set and a different false-positive profile.
- Zero network false positives in one capture is a bound, not a guarantee.
