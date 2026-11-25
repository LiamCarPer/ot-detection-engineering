# Benign baseline corpus

`benign-events.jsonl` is a **generated, deterministic** corpus of normal OT
telemetry. It exists so the repository can report a false-positive rate over a
sample large enough to be worth a confidence interval, instead of a handful of
hand-written lines.

## Provenance

| Property | Value |
| :--- | :--- |
| Generator | `tools/make_benign.py` |
| Seed | `20260101` |
| Events | 1,000 |
| Determinism | Seeded RNG for field values, fixed template order, clock shifted by the seed; regenerating writes a byte-identical file. |

```bash
python tools/make_benign.py
# writes 1000 benign events (seed 20260101) to metrics/baseline/benign-events.jsonl
```

`tests/test_baseline_corpus.py` regenerates the corpus in memory and fails if it
differs from the committed file, so the provenance above cannot drift.

## What it models

One template per recurring benign behaviour consumed by the rules:

- **Modbus** — reads from the supervisory HMI and approved engineering
  workstation; writes from the two approved writers, always below the
  safety-critical register band; normal responses.
- **DNP3** — authorised link addresses `1` and `2` from the approved masters to
  the field outstations, polls, reads, a control operation and a normal response
  with `IIN = 0`.
- **S7comm** — reads and setup-communication from the approved engineering
  workstation; no download, upload or operating-mode change.
- **OPC UA** — session establishment and read requests/responses; no browse,
  write or method call.
- **Firewall** — the declared conduits and allowed flows, plus an ICMP DROP that
  the conduit rules ignore.
- **Process** — routine `process_update` events and a safety violation that was
  auto-mitigated.
- **Flow** — normal asset pairs and ordinary byte/packet volumes.
- **SNMP** — interface-up and heartbeat events; no down, restart or config change.

## What it does not prove

This is generated telemetry, not traffic captured from a plant. It checks that no
rule fires on **modelled normal operation** and gives a sample size for a
statistical bound; it does not estimate field false-positive volume. A real plant
has vendor quirks, clock skew, partial sessions and long-tail traffic that a
template generator cannot invent. The corpus cycles **30 behavioural shapes**, so
a binomial interval over 1,000 rows overstates the effective sample size.

`metrics/out/fpr.md` measures every family separately. The Sigma single-event
result is the `0/1,000` figure; the behaviour baseline, conduit, correlation and
stateful families are measured on the same corpus and reported there.

The held-out negatives under `metrics/heldout/` are generated with a **different
seed**, so the corpus used to tune detections is not the corpus used to measure
them. The behaviour and per-asset baselines are learned from that held-out seed
(`20260202`) and measured on the tuning corpus (`20260101`), so the learner and
the measurement sample are disjoint.
