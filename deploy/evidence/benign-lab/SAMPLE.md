# Benign capture sample

The full 25.45-hour capture is 1.1 GB and is not committed. This directory
contains a bounded 10-minute slice so a reader can inspect the traffic mix
without trusting the summary alone.

| Field | Value |
| :-- | :-- |
| Sample | `benign-24h-sample.pcap` |
| Window | 2026-11-25T16:45:31Z to 2026-11-25T16:55:31Z |
| Packets | 61,940 |
| Size | 8.5 MB (6.7 MB on the wire) |
| Protocols | Modbus/TCP 1,702; HTTP 6,967; TLS 132; SSDP/mDNS discovery |

The sample is a contiguous slice, not a downsampled or replayed file. It
demonstrates the traffic mix; it does **not** reproduce the 1,136,470-event
result on its own. The full-capture SHA-256, byte count and analysis inputs are
in `summary.json`; the capture path is the lab host's
`ot-security-lab/detection/logs/benign-24h.pcap`.

To reproduce, either obtain the full capture from the lab host or run the same
analyser against the sample:

```bash
make lab-benign-check LAB_PCAP=deploy/evidence/benign-lab/benign-24h-sample.pcap
```

That run reports its own, smaller event count. It is a smoke test of the
pipeline, not the headline measurement.
