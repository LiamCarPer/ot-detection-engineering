# Results

One page of what this repository proves, the evidence for each claim, and how to
reproduce it. Everything here is machine-checked by the test suite or captured
from a real run; nothing is hand-counted.

## Headline

| Metric | Value | Scope |
| :--- | ---: | :--- |
| ATT&CK for ICS coverage | 15 / 97 techniques (15.5%) | Intentionally seeded, not padded. |
| Emulation detection rate | 100% (4 / 4 expectations) | Two adversary steps, replayed from a live lab run. |
| Mean MTTD | 2.45 s | Time from action to first matching alert. |
| Rule fixture agreement | precision 1.0, recall 1.0 | Rule vs. its own committed fixtures — a regression check. |
| Baseline false-positive rate | 0.0 | 50 benign and near-miss events across every telemetry domain. |

## What is functionally validated

| Claim | Evidence | Reproduce |
| :--- | :--- | :--- |
| Native Suricata rules fire on all four protocols, benign captures are silent | `deploy/evidence/*/eve.json`, `deploy/evidence/summary.json` | `make suricata-check` (Docker) |
| The Loki ruler bundle fires all 17 rules in a full stack | `deploy/evidence/loki/` | `make loki-check` (Docker) |
| The ruleset loads and fires inside a Malcolm pipeline alongside 59,188 default rules | `deploy/evidence/malcolm/` | `tools/malcolm_check.py` |
| The generated rules fire on live traffic in a real-endpoint OT lab (DNP3, OPC UA, S7comm) | `deploy/evidence/lab-loki/` | `tools/lab_loki_check.py` (lab up) |
| The Rust decoders' output satisfies the Sigma rules | `deploy/evidence/decoders/summary.json` | `make decoder-check` |
| Every rule converts to Loki, Splunk, Sentinel and OpenSearch, with provenance | `deploy/manifest.json` | `make convert-all` |

See [deploy/report.md](../deploy/report.md) for the full functional report.

## The parts that are uncommon

- **Dependency-free Rust decoders** for DNP3 (CRC-16/DNP validated), S7comm and
  OPC UA, with truncation and mutation robustness tests and a
  decoder-to-rule proof.
- **A live, multi-protocol OT lab** with real `opendnp3`, `asyncua` and
  `python-snap7` endpoints driving the detections, not only synthetic captures.
- **Rendered in a Malcolm pipeline**, the toolchain an OT SOC actually runs,
  rather than only in isolation.
- **Detection-as-code**: one Sigma source converted to four SIEM languages with
  SHA-256 provenance, drift-checked in CI.

## What is not proven

Honest scope, because a detection is only as trustworthy as its evidence:

- The lab is a Dockerized software emulation; there is no physical PLC.
- Fixture precision/recall is rule/fixture agreement, not field performance.
- Coverage is deliberately small; the point is the process.
- Emulation covers two steps and four expectations, not every rule.
- S7comm classic only; OPC UA plaintext only; DNP3 first object header only.

Full detail in [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md).

## Reproduce in five minutes

```bash
make setup
make demo          # decoder -> Sigma match -> generated SIEM queries, offline
make check         # lint, Sigma validation, 177 tests, Rust, bundle drift
make metrics       # coverage, fixture agreement, baseline FPR, emulation replay
```
