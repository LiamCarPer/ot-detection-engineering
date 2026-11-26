# Claims register

Every headline claim in this repository maps to an artifact and, where possible,
a command that proves it. This file exists because a portfolio's credibility
depends on its claims being checkable; a claim without evidence is a liability.

**Statuses**

- **Verified** — machine-checked offline by the test suite or a guard test.
- **Implemented** — built and exercised, but the proof is a committed snapshot
  from Docker or the live lab rather than a check re-run on every commit.
- **Partial** — only part of the claim is demonstrated.
- **Known gap** — deliberately not claimed.

Last audited: **2026-11-24**. The independent runs and their limits are in
[`EVIDENCE_MAP.md`](EVIDENCE_MAP.md).

## Canonical numbers

If you quote this repository, use only these figures. Older draft figures are
not current and must not be used.

| Figure | Current value |
| :-- | :-- |
| ATT&CK for ICS coverage | **32 / 97 techniques (33.0%)** tagged, **32 validated**, **10 live-lab proven** |
| Detection content | **30 Sigma + 7 correlation + 4 YARA + 21 native + 5 stateful**, plus 3 baseline + 3 conduit = 73 catalogued rules |
| Benign baseline (generated) | **Sigma single-event: 0 / 1,000 generated events**, 95% Wilson upper bound **0.38%**; all-family report in `deploy/evidence/fpr/report.md` |
| Lab benign capture | **25.45 h, 1,136,470 events, 0 Sigma/native FPs** from the 9 / 30 rules with input; lab-trained baseline **0 / 1,041,580** |
| Benign protocol window | **0.5 h, 52,811 events, 0 Sigma/native FPs**; **22 / 30** Sigma rules had input, including DNP3, OPC UA, S7comm and SNMP; lab-trained baseline **0 / 38,276** |
| Held-out single-event | **54 / 54** positives, **0** false positives over 1,024 negatives per rule |
| Held-out correlation | **13 / 13** positive windows, **0** false positives over 15 negative windows |
| Held-out YARA | **8 / 8** artifacts, **0** false positives over 8 shared negatives |
| Purple team (MTTD run) | **4 / 4** expectations, mean MTTD **2.45 s** (`n=4`, one run) |
| Purple team (live) | **12 / 12 Sigma expectations**, 7 steps, 3 runs, 0 unexpected, benign windows clean; non-process MTTD mean **2.53 s**, process step **125 s** (fill-cycle wait) |
| Purple team (replay) | **14 / 14** lab alert signals, 8 steps, 0 unexpected, benign passed |
| Suppression | **151 alerts → 21 notifications (86.09%)**; C2/C3/C4/C5 preserved |
| Sensor health | **Detection Service Stopped firing live** in the lab ruler |
| Alert-flood case study | **151 alerts → 24 episodes → 5 operational events** |
| Detection catalogue | **73 rules, 6 stable, 67 experimental, 12 with observed lab volume, 0 blocking gaps** |
| Performance | **7.8–11.0M decoder frames/s; ~2,800 replay events/s; ~3,375 events/s achieved at a 4,000 target, 0 drops** on the recorded host |
| Engine parity | **30 / 30 single-event rules** execute in Splunk Free, OpenSearch PPL and Kusto and return exactly the matcher's event set |
| Detection allowlists | **6 sets generated from the asset inventory**; every Sigma filter and native exclusion is bound to one |
| Process safety | **Independent mass balance catches an unsafe command through a 60% spoofed level** where a shadow monitor does not |
| Lab proof | **One command** runs the live health, live rules, live purple, engine parity and benign capture, and refuses to attack a running capture |
| Test suite | The count is not a quality claim; see the CI run |
| Live lab | **11 of the 13 rules the lab exercises** fire on live traffic (snapshot 2026-09-15; predates the P1 rule changes) |

## Claims

| Claim | Status | Evidence | Check |
| :-- | :-- | :-- | :-- |
| Every Sigma rule parses and carries a known ATT&CK for ICS tag | Verified | `rules/sigma/`, `metadata/attack_ics_catalog.json` | `make validate`, `tests/test_metadata.py` |
| Every single-event Sigma rule has a positive and a negative fixture and matches both | Verified | `rules/sigma/ot/*.test.yaml` | `tests/test_sigma_rules.py` |
| Every correlation rule fires on its labeled windows and stays silent on its negatives | Verified | `rules/sigma/ot/*.test.yaml` (`windows:`) | `tests/test_sigma_correlations.py` |
| YARA rules compile, match their synthetic positives, and pass the EICAR self-test | Verified | `rules/yara/`, `deploy/evidence/yara/summary.json` | `make yara-check`, `tests/test_yara.py` |
| Native Suricata rules fire on the attack captures and stay silent on the benign captures | Implemented | `deploy/report.md`, `deploy/evidence/*/eve.json` | `make suricata-check` (Docker) |
| The ruleset loads and fires inside a Malcolm pipeline alongside 59,188 default rules | Implemented | `deploy/evidence/malcolm/` | `tools/malcolm_check.py` |
| The Loki ruler bundle fires the 18 rules in the live Loki proof in a full stack | Implemented | `deploy/evidence/loki/` | `make loki-check` (Docker) |
| The generated rules fire on live traffic in a real-endpoint OT lab for 11 of the 13 rules the lab exercises | Implemented (snapshot 2026-09-15; predates the P1 rule changes) | `deploy/evidence/lab-loki/` | `tools/lab_loki_check.py` (lab up) |
| The Rust decoders decode the committed examples and the resulting events satisfy the Sigma rules | Verified | `deploy/evidence/decoders/summary.json` | `make decoder-check` |
| Suricata and Zeek sensor output, plus authored NetFlow/IPFIX and SNMP exports in the exporter's shape, normalize to the contract and fire the expected rules | Verified | `deploy/evidence/collector/summary.json` | `make collector-check` |
| The behaviour baseline is reproducible and its rules fire on deviations and stay silent on benign telemetry | Verified | `deploy/evidence/baseline/summary.json` | `make baseline-check` |
| Conduit rules flag an undeclared cross-zone path and an undeclared service; the evidence records declared conduits never observed | Verified | `deploy/evidence/conduit/summary.json` | `make conduit-check` |
| Every single-event rule converts to Loki, OpenSearch, Splunk and Sentinel with SHA-256 provenance | Verified | `deploy/manifest.json` | `make convert-all` |
| The converted SPL, PPL and KQL select exactly the same events as the repository matcher over the held-out corpus | Verified | `deploy/evidence/engine-parity/summary.json` | `make engine-parity` (containers) |
| Every rule exclusion resolves to a declared allowlist whose members exist with the declared roles | Verified | `metadata/allowlists.generated.yaml` | `make allowlists-check` |
| A mass-balance estimate detects an unsafe command while the reported level is spoofed; the normal cycle stays quiet | Verified (model) | `deploy/evidence/process-model/` | `make process-model-check` |
| The real-traffic analyser decodes Modbus and flows, reports 0 Sigma/native FPs over 25.45 h, and labels every rule without input as unexercised | Verified | `deploy/evidence/benign-lab/` | `make lab-benign-check LAB_PCAP=...` |
| A benign DNP3/OPC UA/S7/SNMP window has input for 22/30 Sigma rules and produces no false positives | Verified | `deploy/evidence/benign-protocols/` | `make lab-protocols-check` |
| Every correlation rule converts to Loki, Splunk, OpenSearch and Sentinel | Verified | `deploy/manifest.json` | `make convert-all` |
| The committed deployment bundle cannot drift from the rules | Verified | `deploy/`, `pipelines/deploy.py --check` | `make deploy-check` |
| Coverage, fixture metrics and held-out metrics are derived from rule content | Verified | `coverage/`, `metrics/` | `make coverage`, `make metrics`, `tests/test_coverage.py`, `tests/test_metrics.py` |
| The benign baseline is deterministic and reproducible | Verified | `metrics/baseline/` | `tests/test_baseline_corpus.py` |
| The benign baseline is 0 / 1,000 for the single-event Sigma family, with a 95% Wilson upper bound of 0.38% | Verified (modelled) | `metrics/baseline/README.md`, `deploy/evidence/fpr/report.md` | `make fpr` |
| Every detection family is measured on the benign corpus: baseline, conduit, correlation, stateful, native and YARA are silent | Verified (modelled) | `deploy/evidence/fpr/report.md` | `make fpr-check` |
| Held-out single-event precision and recall are 54 / 54 with 0 false positives over 1,024 negatives per rule | Verified (authored/generated set) | `metrics/heldout/README.md` | `make metrics`, `tests/test_heldout.py` |
| Held-out correlation recall is 13 / 13 positive windows with 0 false positives over 15 negatives | Verified (authored set) | `metrics/heldout/README.md` | `make metrics`, `tests/test_heldout.py` |
| Held-out YARA recall is 8 / 8 artifacts with 0 false positives over 8 shared negatives | Verified (authored set) | `metrics/heldout/README.md` | `make metrics`, `tests/test_heldout.py` |
| No held-out event duplicates a rule fixture | Verified | `tests/test_heldout.py` | `make test` |
| The purple-team plan validates that each referenced rule detects the plan's technique | Verified | `purple/emulation/emulation-plan.yaml`, `tools/otde/evidence.py` | `make emulate-validate` |
| The purple-team runner fails when a lab alert's `mitre_id` disagrees with the plan's `lab_technique` | Verified | `purple/runner/run_emulation.py` | `tests/test_emulation.py` |
| The alert-flood case study is reproducible from a pinned lab snapshot | Verified | `analysis/data/lab-2026-11-24/`, `analysis/out/` | `make case-study-check`, `tests/test_lab_case_study.py` |
| 151 lab alerts collapse to 24 one-minute episodes and 5 operational events, with every alert assigned | Verified | `analysis/out/summary.json` | `tests/test_lab_case_study.py` |
| The analysis keeps the secondary SIEM and runtime datasets separate from the 160-second burst | Verified | `analysis/out/report.md` | `tests/test_lab_case_study.py` |
| Every rule has exactly one detection-catalogue entry, and every entry has a rule | Verified | `metadata/detection-catalog.yaml` | `make health-check`, `tests/test_detection_health.py` |
| A stable rule has an owner, data source, runbook, observed volume and validation date | Verified | `metadata/detection-catalog.yaml`, `docs/runbooks/` | `make health-check` |
| Three stateful detections fire on their positive windows and stay silent on their negatives | Verified | `rules/stateful/`, `deploy/evidence/stateful/summary.json` | `make stateful-check`, `tests/test_stateful.py` |
| The process-value and per-asset baselines are reproducible from committed benign data | Verified | `baseline/process-values.json`, `baseline/asset-behaviour.json` | `tests/test_stateful.py` |
| The change calendar is schema-valid and reviewed as code | Verified | `metadata/change-calendar.yaml` | `tests/test_stateful.py` |
| The decoder microbenchmark records throughput and p99 per frame and passes its SLO | Verified (hardware-specific) | `deploy/evidence/perf/summary.json` | `make perf-check`, `tests/test_perf.py` |
| The offline replay processes 1,000 distinct benign events ten times (10,000 evaluation passes) through 30 rules with 0 matches | Verified | `deploy/evidence/perf/summary.json` | `make perf-check` |
| The write-up, demo and operations walkthrough use the current evidence and state their scope | Verified | `docs/WRITEUP.md`, `docs/DEMO.md`, `docs/OPERATIONS.md` | `tests/test_communication.py` |
| The catalogue's observed volume matches the Phase 1 lab analysis | Verified | `analysis/out/rule_health.json` | `tests/test_detection_health.py` |
| The recorded purple-team MTTD run detected 4 / 4 expectations at a mean MTTD of 2.45 s | Implemented (`n=4`, one run) | `purple/emulation/lab-observations-2026-09-13.json`, `purple/results/` | `make metrics` (replay) |
| The 2026-11-25 live run executes the generated Loki rules against 7 steps and 3 runs | Implemented (lab, 3 runs) | `deploy/evidence/purple-live/` | `python purple/runner/live_lab.py` |
| The 2026-11-24 lab alert-signal replay matches 14 / 14 expected signals across 8 steps | Verified (replay) | `deploy/evidence/purple/emulation_results.json` | `make purple-check`, `tests/test_emulation.py` |
| The 2026-11-24 replay produced 0 unexpected alerts and passed a 30-second benign window | Verified (replay) |
| The Alertmanager grouping policy reduces 151 alerts to 21 notifications and preserves C2/C3/C4/C5 | Verified (model) | `analysis/out/suppression.json` | `python analysis/suppression.py` |
| The sensor-health rule fires on a stopped detection producer in the lab | Implemented (lab) | `deploy/evidence/lab-health/` | `make lab-health-check` | `deploy/evidence/purple/emulation_results.json` | `make purple-check` |
| Security controls and threats are governed as code | Verified | `metadata/security-controls.yaml`, `metadata/threat-model.yaml` | `make security-preflight`, `tests/test_security_governance.py` |
| CI runs the offline checks; container and live-lab evidence is committed and guarded rather than re-run | Verified | `.github/workflows/ci.yml`, `tests/test_*_evidence.py` | CI |
| No real malware is committed; YARA samples are inert and the engine is proven with EICAR in memory | Verified | `tests/yara/samples/README.md`, `tools/yara_check.py` | `make yara-check` |

## Known gaps

These are deliberately not claimed. They are also listed in
[`docs/REVIEWER_GUIDE.md`](REVIEWER_GUIDE.md).

| Gap | Why it is open |
| :-- | :-- |
| Production field telemetry | The repo has no plant traffic. The benign corpus is generated and the lab is a Dockerised plant. |
| Host and authentication telemetry | Sysmon and HMI access logs are collected, but Privilege Escalation is `0/2` because no rule maps local privilege escalation; tagging a network rule would be tag-gaming. |
| Purple-team breadth and repeatability | The live run is 7 steps / 12 Sigma expectations over 3 runs; the 2026-11-24 replay is 8 steps / 14 lab signals; the MTTD run is 2 steps / 4 expectations. Analyst MTTA is not measured. |
| Live execution of every rule | The live purple run covers the plan's 7 steps; the older lab-loki snapshot covers 11 of 13 exercised rules. The newer breadth rules are fixture-proven and bundle-converted. |
| Commercial BAS | AttackIQ is commercial; the lab uses a deterministic harness and an optional Caldera profile. |
| 24/7 SOC operations | No on-call rota, shift handover, or production incident load. |
| Physical process safety | The lab is a software emulation; there is no physical PLC, sensor or actuator. |
| Real malware analysis | Out of scope by design. Public-sample analysis in an isolated lab would be the credible next step. |
| Production triage / MTTA | The case study has no analyst acknowledgement or resolution timestamps; it measures queue reduction, not human performance. |
| MTTD on the replay | The 2026-11-24 snapshot has alert timestamps but not action start timestamps; MTTD comes only from the 2026-09-13 run. |
| C2-beacon and OT-port-scan coverage | The lab emits those alerts, but the repository has no matching rule; they are not scored in the purple plan. HMI login failure and its burst now have rules. |
| Lab-capture protocol coverage | The 25.45-hour benign window contains Modbus reads and flows only. DNP3, OPC UA, S7, SNMP and Modbus writes are unexercised; a separate benign protocol capture is the next step. |
| Baseline portability | The committed baseline is learned from the generated seed and flags every lab asset and pair as new. The lab result uses a baseline trained on the first two hours; a deployment must learn its own baseline. |
| Operational maturity of most rules | 67 of 73 rules are `experimental`; only 6 have runbooks and 12 have observed lab volume. |
| Production-scale performance | The benchmark is a desktop, small example frames, no pcap replay, no sustained load, no backpressure. |

## How to audit this file

```bash
make setup
make check        # offline claims
make metrics      # metric claims
make deploy-check # bundle claims
```

Container and lab claims:

```bash
make suricata-check
make loki-check
make lab-loki-check   # requires OT-Security-Lab running
```

If a claim here is wrong, it is a bug in the repository. Open an issue or a PR
with the failing command.
