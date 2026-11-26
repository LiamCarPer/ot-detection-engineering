# Lab benign capture

The generated corpus is a model. This is the real-traffic counterpart: a
25.45-hour PCAP captured at the lab gateway, with no adversary traffic,
normalized through the collector and run through the network detection families.

## Method

- Capture on every non-loopback gateway interface with a Scapy `PcapWriter`
  (`ot-security-lab/lab-environment/scripts/benign_capture.py`). The gateway is
  the only multi-homed container, so it sees every inter-zone flow. A routed
  frame is recorded twice, on ingress and egress; Suricata and Zeek normalize
  per flow, so the family measurements count flows, not frames.
- Run Zeek with **`-C`** and the `modbus`/`dnp3` analyzers. Without `-C` the
  capture's checksum offload makes Zeek discard packets and split connections:
  on the 9.5-minute pilot the flow count was **13,949 instead of 5,881**.
- Run Suricata with the repository rules and checksum validation disabled for
  the same reason.
- Decode Modbus with `tshark -Y modbus`, not only Zeek's `modbus.log`: the Zeek
  log has direction and function but no register or quantity, so block-read and
  enumeration rules cannot be evaluated from it.
- Apply the same family functions as `metrics/fpr.py`, then report **per-rule
  input counts**. A rule with zero events from its own logsource is **not
  exercised**; its zero is not a measurement.
- Learn the behaviour baseline on the first two hours and test on the remaining
  23.45 hours. The committed baseline was learned from the generated seed and is
  reported separately as a domain shift, not a false-positive rate.

## Result

| Metric | Value |
| :-- | --: |
| Window | 25.45 h |
| Normalized events | 1,136,470 (44,651 / h) |
| Flows | 890,723 |
| Modbus messages | 245,747 |
| Sigma single-event FPs | 0 |
| Sigma correlation | 0 fired (3 / 7 rules had input) |
| Lab-trained baseline | 0 events over 1,041,580 test events |
| Committed baseline (domain shift) | 159,785 new pairs, 73,800 new assets |
| Stateful | 0 fired (2 / 5 rules had input) |
| Conduit / firewall | not exercised (no iptables records in a PCAP) |
| Native Suricata | 0 alerts |
| Sigma rules with input | 9 / 30 |

In this 25-hour window, the 21 unexercised Sigma rules are the DNP3, OPC UA,
S7comm, SNMP, firewall, host, auth, PLC-diagnostic, sensor-health and
process-safety rules. The capture has no traffic for them, or their source is
not a network packet. The 0.5-hour protocol window below closes the DNP3,
OPC UA, S7comm and SNMP-input part of that gap; it is not a claim that the other
families were measured here.

## Benign protocol window

The 25-hour window is Modbus and flows only. A second, short window runs the
benign DNP3/OPC UA/S7 pollers from the approved engineering client and evaluates
the same families with two additions:

- the pcap supplies flows and Modbus;
- the lab's DPI producers supply normalized DNP3, OPC UA and S7comm events from
  Loki, because the offline pcap decode is weaker for those protocols.

The analyzer merges the two streams, adds the SNMP exporter's JSONL, and reports
input coverage per rule. The committed 30-minute window is:

| Metric | Value |
| :-- | --: |
| Window | 0.5 h |
| Events | 52,811 |
| Flows / Modbus | 35,382 / 15,525 |
| DNP3 / OPC UA / S7comm | 130 / 1,170 / 520 |
| SNMP heartbeats | 83 |
| Sigma rules with input | **22 / 30** (logsource input, not a positive path) |
| Sigma / native FPs | **0 / 0** |
| Lab-trained baseline | **0 / 38,276** |

The 8 rules still without input need a source a network capture cannot carry
(firewall iptables records, HMI auth, host Sysmon, PLC diagnostics, watchdog) or
an attack (process safety). The three SNMP rules have heartbeat input but none of
their config-change/restart/link-down events occurred, so they are not
positively exercised. The Modbus write logsources have input but the window
contains no writes, so their write path is not asserted by this window.

The eight rules still without input are the three firewall rules, HMI auth,
host Sysmon, PLC diagnostics, sensor health and process safety. The protocol
window supplies DNP3, OPC UA, S7comm and SNMP heartbeats; the three SNMP rules
select config-change/restart/link-down events, which this benign window does not
produce.

## Findings

1. **The first 25-hour run exposed 3,576 flow false positives.** All were
   `REJ` from the approved HMI (`172.22.0.10`) to one PLC (`172.21.0.11:502`):
   ordinary reconnect churn against a controller that was not accepting a new
   session. The single-event rule now covers **established-session resets**
   (`RSTO`/`RSTR`) and is named
   `ot_flow_industrial_service_reset.yml`; the benign capture has no resets, and
   the result is zero. Refusal volume belongs in a correlation or the health
   rules, not a per-packet medium alert.
2. **The committed baseline is environment-specific.** Run unchanged against the
   lab it flags 159,785 events on the new-pair rule and 73,800 on the
   new-source-asset rule (the same event can match both). A baseline learned on
   the first two hours and tested on the remaining 23.45 hours flags zero.
3. **Zeek was silently dropping packets.** `-C` changed the pilot from 13,949 to
   5,881 flows. The analyser now records the flag and the corrected count.
4. **The capture outlived its timeout.** `sniff(timeout=86400)` with several
   interfaces did not stop; the run reached 25.45 h. The lab script now uses
   `AsyncSniffer` with an explicit wall-clock deadline.

## Reproduce

```bash
make lab-benign-check LAB_PCAP=/path/to/benign-24h.pcap
```

The committed evidence under `deploy/evidence/benign-lab/` is the capture above;
the report records its window, hash and per-rule coverage.

## What this does not prove

- One Dockerised lab, not a plant. There is no physical process, no enterprise
  background load beyond the lab's containers, and no 24/7 operation.
- The network capture cannot see host, auth, PLC diagnostics, sensor health or
  firewall log records; those families are measured on their own samples.
- This window has Modbus reads and flows only. DNP3, OPC UA, S7comm and SNMP are
  measured in the separate 0.5-hour protocol window, not here; Modbus writes
  are not asserted by either window.
- **More than half of the flows are the lab's own Loki/InfluxDB observability
  traffic.** The result is a lab baseline, not a plant baseline.
- Zero false positives in one window is a bound, not a guarantee.
