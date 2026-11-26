# OT Detection Engineering

[![ci](https://github.com/LiamCarPer/ot-detection-engineering/actions/workflows/ci.yml/badge.svg)](https://github.com/LiamCarPer/ot-detection-engineering/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![ATT&CK for ICS](https://img.shields.io/badge/ATT%26CK%20for%20ICS-v19.2-cc0000)](metadata/attack_ics_catalog.json)

**A detection-as-code operating model for OT/ICS, demonstrated end to end on a
segmented water-treatment lab.**

This repository treats detections as software: one Sigma source, four SIEM
targets, native protocol DPI, fixture and held-out validation, adversary
emulation, a detection catalogue and measured performance. Every headline claim
has an artifact and a command, and the repository says plainly what it does not
prove.

## Start here

| Time | Path | Why |
| :-- | :-- | :-- |
| 2 min | [`docs/RESULTS.md`](docs/RESULTS.md) | The numbers, their scope, and what they do not mean. |
| 3 min | [`docs/DEMO.md`](docs/DEMO.md) | The offline demo: decoders → case study → purple team → catalogue → performance. |
| 5 min | [`docs/REVIEWER_GUIDE.md`](docs/REVIEWER_GUIDE.md) | A deeper path from summary to code, including where to be skeptical. |
| 6 min | [`docs/CASE_STUDY_ALERT_FLOOD.md`](docs/CASE_STUDY_ALERT_FLOOD.md) | 151 lab alerts → 24 episodes → 5 operational events, and what to suppress. |
| 8 min | [`docs/PURPLE_TEAM.md`](docs/PURPLE_TEAM.md) | 14 / 14 lab alert signals replayed across 8 steps; what that proves and what it does not. |
| 10 min | [`docs/CLAIMS.md`](docs/CLAIMS.md) | Every claim → evidence → the command that proves it. |
| 15 min | [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) | Tradeoffs, failures, and the rule that was withdrawn. |

## The 90-second version

- **What it detects.** 32 ATT&CK for ICS techniques across 30 single-event Sigma
  rules, 7 correlation rules, 4 YARA rules, 21 native Suricata signatures, 5
  stateful detections and 6 baseline/conduit rules, chosen for a segmented
  water-treatment plant and mapped to a committed threat model.
- **What it proves.** Every rule has a committed proof: Sigma fixtures, native
  capture tests, YARA fixtures, baseline/conduit fixtures and stateful windows.
  The Sigmas are held-out-tested; the native rules run in Suricata over the
  committed PCAP captures; 18 rules run in the live Loki smoke test, and
  the native Suricata ruleset runs in a Malcolm pipeline; the Rust decoders are
  proven against the rules they feed; and the converted Splunk, OpenSearch and
  Kusto queries execute in real engines and return exactly the events the
  repository matcher returns.
- **What it tunes.** The repo records the failures its checks found: a Modbus
  response rule that could not attribute the responder and was withdrawn, a DNP3
  allowlist that missed the benign master, and a Suricata exception rule that
  used invalid syntax. The point is the loop, not a perfect first draft.
- **What it is not.** The generated benign corpus is a model, the lab is a
  Dockerised plant, and the purple-team evidence is an 8-step alert-signal
  replay, a separate 2-step MTTD run and a 7-step live run. Those are
  limitations, not footnotes.
- **What the real capture adds.** A 25.45-hour benign gateway capture, decoded
  with Zeek `-C` and Modbus DPI, gives 1.14M events with zero false positives
  from the 9 Sigma single-event rules that have input. The 21 rules without
  input are labelled unexercised, not clean.

## Case study: 151 alerts in 160 seconds

A fresh lab run produced **151 alerts across 17 types from four sources in 160
seconds**. The analysis collapses them into **24 one-minute episodes** and
**five operational events** — four adversary campaigns and one sensor-health
event — and explains what to suppress, what to keep, and what the reduction
does not prove. The implemented grouping policy turns 151 alerts into 21
notifications and preserves the four campaigns and the sensor-health event.

[Read the case study](docs/CASE_STUDY_ALERT_FLOOD.md) ·
[generated report](analysis/out/report.md)

## Detection health

Every rule has an operational entry in
[`metadata/detection-catalog.yaml`](metadata/detection-catalog.yaml): owner,
severity, data source, expected volume, runbook and lifecycle status. `make
health` refuses a rule without an entry, an entry without a rule, a technique
mismatch, or a `stable` rule without a runbook or observed volume.

Current: **73 rules, 6 stable, 67 experimental with at least one operating gap,
12 with observed lab volume**. The word “gap” is overloaded: the health gate has
0 blocking gaps, while 67 experimental rules still need a runbook or volume
history before promotion.
[Health report](deploy/evidence/health/report.md) ·
[Runbooks](docs/runbooks/)

## Coverage: prioritized, not padded

Raw tagged ATT&CK for ICS coverage is **32 / 97 techniques (33.0%)**; all **32**
tagged techniques are validated (fixture plus an independent measurement plus a
clean benign result), and **10** are live-lab proven. The raw number is
deliberately not the headline: the catalogue includes techniques that are not
observable from the telemetry this repository has, and padding it with untested
tags would make the repo worse, not better.

| Tactic | Covered | Why the gap is acceptable |
| :-- | --: | :-- |
| Initial Access | 4 / 12 | Remote services, rogue-master and file-delivered phishing are covered; wireless, transient assets and supply chain need other telemetry. |
| Execution | 3 / 10 | Protocol-level execution is covered; host execution needs EDR telemetry the lab does not have. |
| Persistence | 4 / 10 | Project-file and firmware tampering are covered; PLC program download is counted under Lateral Movement; host persistence needs EDR. |
| Privilege Escalation | 0 / 2 | Host and HMI-auth telemetry is now collected, but no rule models local privilege escalation; tagging a network rule would be dishonest. |
| Evasion | 2 / 9 | Protocol-visible evasion is covered; host evasion needs EDR. |
| Discovery | 3 / 8 | Network-connection, remote-system and device-identification discovery are covered. |
| Lateral Movement | 4 / 11 | PLC program download, remote-service exploitation and cross-zone remote services are covered; the large outbound transfer is counted under Impact. |
| Collection | 4 / 11 | Register and address-space enumeration are covered. |
| Command and Control | 2 / 3 | Control-zone egress and proxy fan-out are covered; a live C2 channel is not built. |
| Inhibit Response Function | 5 / 20 | Device restart, denial of service, alarm suppression, firmware tampering and detection-service health (T0881) are covered. |
| Impair Process Control | 4 / 8 | I/O brute force, parameter modification, unauthorized command messages and firmware tampering are covered; the process-safety envelope is counted under Impact. |
| Impact | 4 / 12 | View/control denial, safety impact and operational-information theft are covered; physical damage needs process context. |

The table is generated by `coverage/generate_coverage.py` and checked against it
by `tests/test_claims.py`.

## Results at a glance

| Metric | Value | Scope |
| :--- | ---: | :--- |
| Detection content | 73 catalogued rules: 30 Sigma + 7 correlation + 4 YARA + 21 native + 5 stateful + 3 baseline + 3 conduit | Every rule is in the detection catalogue. |
| Emulation detection rate (MTTD run) | 100% (4 / 4 expectations) | 2026-09-13 run, two steps; the lab's `mitre_id` is cross-checked against the plan. |
| Mean MTTD (live lab) | 2.45 s | Time from action start to first matching alert, 2026-09-13 run (`n=4`, one run). |
| Purple-team live | 11 / 12 Sigma expectations (7 steps, 3 runs) | 2026-11-25; 0 unexpected; benign windows clean; the process-safety miss was an untimed write, now timed against the live level (re-run pending the 24-hour capture). |
| Purple-team replay | 14 / 14 expectations (8 steps) | 2026-11-24 replay of the lab's `alert_type` snapshot; 0 unexpected; benign window passed; a lab alert-signal mapping test, not rule execution and not MTTD. |
| Performance | 7.8–11.0M decoder frames/s; ~2,800 replay events/s; 4,000 events/s sustained with 0 drops, 20,000 saturates and drops | Release build on the recorded host; small example frames; per-frame p99, see `docs/PERFORMANCE.md`. |
| Rule fixture agreement | precision 1.0, recall 1.0 | Rule matches against its own committed fixtures. A regression check, not field precision. |
| Sigma single-event FPR | 0 / 1,000 (95% Wilson upper bound 0.38%) | Generated benign events across every stream the Sigma rules consume. The corpus has 30 behavioural shapes, so the binomial bound overstates effective N. |
| All-family FPR (generated) | baseline, conduit, stateful, correlation, native and YARA all 0 | Same corpus plus the committed benign captures and fixtures; see [`deploy/evidence/fpr/report.md`](deploy/evidence/fpr/report.md). |
| Lab benign capture (25.45 h) | 0 Sigma/native FPs on 1,136,470 events; lab-trained baseline 0 / 1,041,580 test events | 9 / 30 Sigma rules had input; DNP3, OPC UA, S7, SNMP, firewall, host/auth/PLC/health and process rules are unexercised. See [`docs/BENIGN_CAPTURE.md`](docs/BENIGN_CAPTURE.md). |
| Held-out single-event recall | 54 / 54 (95% CI 0.9336–1.0) | Labeled positives authored separately from the rule fixtures. |
| Held-out single-event precision | 54 / 54 (95% CI 0.9336–1.0) | Same positives against 1,024 held-out negatives per rule. |
| Held-out correlation recall | 13 / 13 positive windows (95% CI 0.7719–1.0) | Window-level across six correlation rules. |
| Held-out YARA recall | 8 / 8 artifacts (95% CI 0.676–1.0) | Two labeled artifacts per rule against eight shared negatives. |

## Architecture

```
rules/sigma/**/*.yml ──┐
                       ├─▶ tools/otde ──▶ ATT&CK coverage map
rules/native/**/*.rules┘        │
                                ├─▶ metrics (precision / recall / FPR / coverage)
                                │
Sigma rule ──▶ pipelines/convert.py ──▶ Loki / OpenSearch / Splunk / Sentinel

rules/** ──▶ pipelines/deploy.py ──▶ deploy/ bundle + provenance manifest
native rules ──▶ tests/captures ──▶ Suricata (container) ──▶ deploy/evidence

DNP3/Modbus/S7comm/OPC UA frames ──▶ tools/*-dpi (Rust) ──▶ ot_ndr events ──▶ Sigma rules
Suricata / Zeek / NetFlow / SNMP ──▶ collector/ ──▶ contract events ──▶ Sigma rules

emulation plan ──▶ purple/runner ──▶ coverage + MTTD ──▶ metrics
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data flow and tooling,
[docs/TELEMETRY.md](docs/TELEMETRY.md) for the event contracts, and
[docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md) for the tradeoffs.

## Repository layout

```
rules/sigma/          Sigma rules with *.test.yaml positive/negative fixtures
rules/baseline/       Behaviour-baseline rules (deviations from learned normal)
rules/conduit/        Conduit rules (deviations from the segmentation policy)
rules/stateful/       Stateful rules (drift, change windows, per-asset profiles)
rules/yara/           YARA rules for project files, firmware and EWS scripts
rules/native/         Suricata rules for protocol DPI
baseline/             Committed behaviour and process baselines and their builders
metadata/             ATT&CK catalog, detection catalogue, policies and JSON Schemas
tools/otde/           Shared library: discovery, technique extraction, matcher
tools/*-dpi/          Rust DNP3, Modbus, S7comm and OPC UA decoders
tools/perf/           Rust decoder microbenchmark
collector/            Normalizes sensor output into the telemetry contract
pipelines/            Sigma-to-backend conversion and deployment bundle builder
deploy/               Installable bundle and committed evidence
coverage/             ATT&CK for ICS coverage map generator
purple/               Adversary emulation plan, runner and recorded observations
metrics/              Detection-quality computation, baseline and held-out set
analysis/             Reproducible lab-data analyses and the alert-flood case study
tests/                Rule, metadata, coverage, metrics and evidence tests
docs/                 Architecture, scope, design decisions, results and runbooks
```

## Quickstart

```bash
make setup             # create .venv and install the toolchain
make demo              # offline decoder -> Sigma rule -> SIEM query walkthrough
make check             # lint, Sigma validation, tests, Rust, evidence checks
make metrics           # coverage, held-out metrics, emulation replay
make case-study        # regenerate the lab alert-flood analysis
make purple-check      # validate the purple-team evidence
make health-check      # validate the detection catalogue
make perf-check        # validate the performance evidence
make convert-all       # Loki, OpenSearch, Splunk and Sentinel
make parity-up         # start Splunk Free and OpenSearch (containers)
make engine-parity     # execute SPL, PPL and KQL; compare with the matcher
make deploy            # build the installable bundle under deploy/
```

`make check` and `make metrics` need no SIEM, lab or external data source. The
container validations (`make suricata-check`, `make loki-check`) require Docker;
`make lab-loki-check` requires the live lab.

## Detection lifecycle

```
author ─▶ validate ─▶ test ─▶ convert/bundle ─▶ emulate ─▶ measure ─▶ operate
```

1. **Author** a rule with an ATT&CK for ICS tag and labeled fixtures.
2. **Validate** with `sigma check` and the metadata governance tests.
3. **Test** each rule against positive and negative events.
4. **Convert and bundle** one rule into four SIEM languages with provenance.
5. **Emulate** an adversary action in the lab and confirm the expected detection.
6. **Measure** coverage, precision, recall, false-positive rate and MTTD.
7. **Operate** the rule through the catalogue, runbook and health gate.

Full instructions are in [docs/DETECTION_LIFECYCLE.md](docs/DETECTION_LIFECYCLE.md).

## Deployment and validation

`make deploy` turns the rules into an installable bundle under [`deploy/`](deploy/):
Grafana Loki ruler alerts, a Suricata ruleset, Splunk saved searches and Sentinel
queries, with a provenance manifest and a per-platform runbook. The bundles are
functionally validated, not just linted: Suricata runs over the committed
captures, the Loki ruler runs in a full stack, and the decoders' output is fed
through the same matcher as the rule tests. The results are in
[deploy/report.md](deploy/report.md), including the Malcolm pipeline and the
11-of-13 live-lab rule proof.

## Scope

- **Machine-checked offline.** Every rule is parsed, tagged, tested and
  converted in CI; the analysis, catalogue and performance evidence are
  regenerated and checked for drift.
- **The lab is a Dockerised plant.** There is no physical PLC, sensor or
  actuator.
- **The benign corpus is generated.** The Sigma single-event claim is `0/1,000`
  with a 95% Wilson upper bound of **0.38%**, not "0.0 FPR". The corpus cycles
  30 behavioural shapes, so the interval overstates the effective sample size.
  Behaviour-baseline, conduit, correlation and stateful rules are measured on
  the same corpus in [`deploy/evidence/fpr/report.md`](deploy/evidence/fpr/report.md); they are not
  included in the Sigma-only bound.
- **Held-out labels are authored.** They are independent of the rule fixtures,
  but the set is small and the per-rule intervals are wide.
- **No production telemetry or 24/7 SOC.** There is no on-call rota, shift
  handover or production incident load.

The detailed limits are in [docs/SCOPE.md](docs/SCOPE.md), and every claim is in
[docs/CLAIMS.md](docs/CLAIMS.md).

## Further reading

- [Purple team](docs/PURPLE_TEAM.md) — coverage, MTTD and the lab-only gaps.
- [Evidence map](docs/EVIDENCE_MAP.md) — every independent run, its date, and what it does not prove.
- [Stateful detections](docs/STATE_DETECTIONS.md) — drift, change windows and per-asset profiles.
- [Performance](docs/PERFORMANCE.md) — decoder p99, replay throughput and SLOs.
- [Operations](docs/OPERATIONS.md) — one rule from catalogue to rollback.
- [Write-up](docs/WRITEUP.md) — the loop, the findings and the failures.
- [Roadmap](docs/ROADMAP.md) — what is next and what is deliberately not done.

Also included: a security-engineering workstream (threat model, 29 controls,
ingest API, LLM triage tests) as supporting evidence. See
[docs/AI_SECURITY.md](docs/AI_SECURITY.md).

## Related projects

- [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) — the
  segmented lab this project validates detections against.
- [OT-NDR-Malcolm-Pipeline](https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline) —
  network DPI and SIEM depth that consume generated rules.

## License

MIT. See [LICENSE](LICENSE).
