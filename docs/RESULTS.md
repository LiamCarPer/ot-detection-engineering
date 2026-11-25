# Results

One page of what this repository proves, the evidence for each claim, and how to
reproduce it. Everything here is machine-checked by the test suite or captured
from a real run; nothing is hand-counted. The full claim-to-evidence map is in
[`docs/CLAIMS.md`](CLAIMS.md), and the reviewer's path is in
[`docs/REVIEWER_GUIDE.md`](REVIEWER_GUIDE.md).

Coverage is not a score. The raw ATT&CK for ICS number is
**32 / 97 techniques (33.0%)**; it is deliberately not the headline, and the
per-tactic rationale for the gaps is in the README.

## Headline

| Metric | Value | Scope |
| :--- | ---: | :--- |
| ATT&CK for ICS coverage | 32 tagged, 32 validated, 10 live-lab proven (raw 32 / 97, 33.0%) | Chosen against the plant threat model; gaps are listed, not padded. |
| Detection content | 30 Sigma + 7 correlation + 4 YARA + 21 native + 5 stateful (plus 3 baseline + 3 conduit) | 73 catalogued rules across all families. |
| Emulation detection rate (MTTD run) | 100% (4 / 4 expectations) | 2026-09-13 run, two steps; the lab's `mitre_id` is cross-checked against the plan. |
| Mean MTTD | 2.45 s | Time from action to first matching alert, 2026-09-13 run (`n=4`, one run). |
| Purple-team live | 11 / 12 Sigma expectations (7 steps, 3 runs) | 2026-11-25; 0 unexpected; benign windows clean; mean MTTD 2.43 s. |
| Purple-team replay | 14 / 14 expectations (8 steps) | 2026-11-24 replay of the lab's `alert_type` snapshot; 0 unexpected, benign window passed; not rule execution and not MTTD. |
| Rule fixture agreement | precision 1.0, recall 1.0 | Rule vs. its own committed fixtures — a regression check. |
| Sigma single-event FPR | 0 / 1,000 (95% Wilson upper bound 0.38%) | Generated benign events; 30 behavioural shapes. |
| All-family FPR | baseline, conduit, stateful, correlation, native, YARA all 0 | Same corpus plus benign captures and fixtures; `deploy/evidence/fpr/report.md`. |
| Held-out single-event recall | 54 / 54 (95% CI 0.9336–1.0) | 2 labeled positives per rule, authored separately from the fixtures. |
| Held-out single-event precision | 54 / 54 (95% CI 0.9336–1.0) | The same positives against 1,024 held-out negatives per rule. |
| Held-out single-event false-positive rate | 0 / 1,024 per rule (95% CI 0.0–0.0037) | 1,000 generated at a different seed plus one near miss per rule. |
| Held-out correlation recall | 13 / 13 windows (95% CI 0.7719–1.0) | Window-level across six correlation rules. |
| Held-out YARA recall | 8 / 8 artifacts (95% CI 0.676–1.0) | Two labeled artifacts per rule against eight shared negatives. |
| Alert-flood case study | 151 alerts → 24 episodes → 5 operational events | One 160-second lab burst; no analyst action timestamps. |
| Suppression | 151 alerts → 21 notifications (86.09%) | Grouping policy; C2/C3/C4/C5 preserved. |
| Detection catalogue | 73 rules, 6 stable, 67 experimental | 12 rules have observed lab volume; the health gate has 0 blocking gaps. |
| Stateful detections | 3 rules, 16 windows, baselines current | Drift, approved change window, per-asset protocol profile. |
| Performance | 7.8–11.0M decoder frames/s; ~2,800 replay events/s; 4,000 events/s sustained, 0 drops | Release build; per-frame p99; small example frames; hardware in `docs/PERFORMANCE.md`. |

## What is functionally validated

| Claim | Evidence | Reproduce |
| :--- | :--- | :--- |
| Native Suricata rules fire on all four protocols, benign captures are silent, and every native SID is exercised | `deploy/evidence/*/eve.json`, `deploy/evidence/summary.json` | `make suricata-check` (Docker) |
| The Loki ruler bundle fires the 18 rules in the live Loki proof, including the original correlation, in a full stack; the newer breadth rules are fixture-proven and included in the bundle | `deploy/evidence/loki/` | `make loki-check` (Docker) |
| The ruleset loads and fires inside a Malcolm pipeline alongside 59,188 default rules | `deploy/evidence/malcolm/` | `tools/malcolm_check.py` |
| The rules the lab exercises fire on live traffic in a real-endpoint OT lab (DNP3, OPC UA, S7comm); 11 of 13 are confirmed in the 2026-09-15 snapshot, which predates the P1 rule changes | `deploy/evidence/lab-loki/` | `tools/lab_loki_check.py` (lab up) |
| The Rust decoders' output satisfies the Sigma rules | `deploy/evidence/decoders/summary.json` | `make decoder-check` |
| Suricata and Zeek sensor output, plus authored NetFlow/IPFIX and SNMP exports in the exporter's shape, normalize to the contract; the SNMP device-event rules fire and stay silent on benign samples | `deploy/evidence/collector/summary.json` | `make collector-check` |
| Behaviour-baseline rules flag a new asset, pair or function code on attack samples and stay silent on benign ones, and the committed baseline is reproducible | `deploy/evidence/baseline/summary.json` | `make baseline-check` |
| Conduit rules flag cross-zone traffic with no declared conduit or an undeclared service, and report the declared conduits never observed | `deploy/evidence/conduit/summary.json` | `make conduit-check` |
| YARA rules flag an embedded executable in a project/firmware artifact and a dropper script, stay silent on benign and near-miss artifacts, and scan a payload blob | `deploy/evidence/yara/summary.json` | `make yara-check` |
| Every single-event rule converts to Loki, Splunk, Sentinel and OpenSearch, with provenance | `deploy/manifest.json` | `make convert-all` |
| Every correlation rule converts to Loki, Splunk, OpenSearch and Sentinel | `deploy/manifest.json` | `make convert-all` |
| Every correlation rule fires on its labeled windows offline; the original correlation also fires in a live Loki stack | `deploy/evidence/loki/`, fixtures | `make loki-check`, `make test` (Docker) |
| The 2026-11-24 lab alert-signal replay matches 14 / 14 expected signals across 8 steps, with 0 unexpected alerts and a passing benign window | `deploy/evidence/purple/` | `make purple-check` |

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
- Held-out precision/recall is a better estimate but still not field
  performance: the positives are authored, the negatives are generated, and
  two positives per rule leave a wide per-rule interval.
- Coverage is prioritized, not maximized; the per-tactic gaps are deliberate and listed in the README.
- The MTTD run covers two steps and four expectations; the 14 / 14 run is a
  replay of the lab's alert labels, not an execution of this repository's
  rules. Neither is a rule-coverage benchmark.
- `0 / 1,000` is the Sigma single-event result. The all-family report in
  `deploy/evidence/fpr/report.md` is the measured FPR for every family; the corpus has 30
  behavioural shapes, so the binomial interval is optimistic.
- S7comm classic only; OPC UA plaintext only; DNP3 first object header only.
- The behaviour baseline is a committed snapshot learned from a benign sample; it
  needs regenerating when the network legitimately changes.
- YARA fixtures are synthetic marker artifacts; no real malware is committed.
- The conduit policy is a committed model of intent; traffic with an unzoned
  endpoint is out of scope, and the zones and conduits must be kept in step with
  the network.

Full detail in [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md).

## Reproduce in five minutes

```bash
make setup
make demo          # decoder -> Sigma match -> generated SIEM queries, offline
make check         # lint, Sigma validation, tests, Rust, bundle drift
make metrics       # coverage, fixture agreement, baseline FPR, emulation replay
make case-study    # regenerate the lab alert-flood analysis
```
