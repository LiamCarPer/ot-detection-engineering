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

Last audited: **2026-11-24**.

## Canonical numbers

If you quote this repository, use these. Older figures such as “17.5% coverage”
or “52 benign events” are stale and must not be used.

| Figure | Current value |
| :-- | :-- |
| ATT&CK for ICS coverage | **29 / 97 techniques (29.9%)**, prioritized, not padded |
| Detection content | **24 Sigma + 6 correlation + 4 YARA + 24 native** |
| Benign baseline | **0 / 1,000 generated events**, 95% Wilson upper bound **0.38%** |
| Held-out single-event | **48 / 48** positives, **0** false positives over 1,024 negatives per rule |
| Held-out correlation | **12 / 12** positive windows, **0** false positives over 14 negative windows |
| Held-out YARA | **8 / 8** artifacts, **0** false positives over 8 shared negatives |
| Purple team | **4 / 4** expectations, mean MTTD **2.45 s** (`n=4`, one run) |
| Alert-flood case study | **151 alerts → 24 episodes → 5 operational events** |
| Detection catalogue | **63 rules, 6 stable, 12 with observed lab volume, 0 gaps** |
| Test suite | 478 tests at the time of this audit; the count is not a quality claim |
| Live lab | **11 of the 13 rules the lab exercises** fire on live traffic |

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
| The generated rules fire on live traffic in a real-endpoint OT lab for 11 of the 13 rules the lab exercises | Implemented | `deploy/evidence/lab-loki/` | `tools/lab_loki_check.py` (lab up) |
| The Rust decoders decode the committed examples and the resulting events satisfy the Sigma rules | Verified | `deploy/evidence/decoders/summary.json` | `make decoder-check` |
| Real Suricata, Zeek, NetFlow/IPFIX and SNMP input normalizes to the contract and fires the expected rules | Verified | `deploy/evidence/collector/summary.json` | `make collector-check` |
| The behaviour baseline is reproducible and its rules fire on deviations and stay silent on benign telemetry | Verified | `deploy/evidence/baseline/summary.json` | `make baseline-check` |
| Conduit rules flag an undeclared cross-zone path, an undeclared service, and a declared conduit never observed | Verified | `deploy/evidence/conduit/summary.json` | `make conduit-check` |
| Every single-event rule converts to Loki, OpenSearch, Splunk and Sentinel with SHA-256 provenance | Verified | `deploy/manifest.json` | `make convert-all` |
| Every correlation rule converts to Loki, Splunk and OpenSearch; Sentinel records them as unsupported | Verified | `deploy/manifest.json` (`unsupported`) | `make convert-all` |
| The committed deployment bundle cannot drift from the rules | Verified | `deploy/`, `pipelines/deploy.py --check` | `make deploy-check` |
| Coverage, fixture metrics and held-out metrics are derived from rule content | Verified | `coverage/`, `metrics/` | `make coverage`, `make metrics`, `tests/test_coverage.py`, `tests/test_metrics.py` |
| The benign baseline is deterministic and reproducible | Verified | `metrics/baseline/` | `tests/test_baseline_corpus.py` |
| The benign baseline is 0 / 1,000 with a 95% Wilson upper bound of 0.38% | Verified (modelled) | `metrics/baseline/README.md` | `make metrics` |
| Held-out single-event precision and recall are 48 / 48 with 0 false positives over 1,024 negatives per rule | Verified (authored/generated set) | `metrics/heldout/README.md` | `make metrics`, `tests/test_heldout.py` |
| Held-out correlation recall is 12 / 12 positive windows with 0 false positives over 14 negatives | Verified (authored set) | `metrics/heldout/README.md` | `make metrics`, `tests/test_heldout.py` |
| Held-out YARA recall is 8 / 8 artifacts with 0 false positives over 8 shared negatives | Verified (authored set) | `metrics/heldout/README.md` | `make metrics`, `tests/test_heldout.py` |
| No held-out event duplicates a rule fixture | Verified | `tests/test_heldout.py` | `make test` |
| The purple-team plan validates that each referenced rule detects the plan's technique | Verified | `purple/emulation/emulation-plan.yaml`, `tools/otde/evidence.py` | `make emulate-validate` |
| The purple-team runner fails when a lab alert's `mitre_id` disagrees with the plan's `lab_technique` | Verified | `purple/runner/run_emulation.py` | `tests/test_emulation.py` |
| The alert-flood case study is reproducible from a pinned lab snapshot | Verified | `analysis/data/lab-2026-11-24/`, `analysis/out/` | `make case-study-check`, `tests/test_lab_case_study.py` |
| 151 lab alerts collapse to 24 one-minute episodes and 5 operational events, with every alert assigned | Verified | `analysis/out/summary.json` | `tests/test_lab_case_study.py` |
| The analysis keeps the secondary SIEM and runtime datasets separate from the 160-second burst | Verified | `analysis/out/report.md` | `tests/test_lab_case_study.py` |
| Every rule has exactly one detection-catalogue entry, and every entry has a rule | Verified | `metadata/detection-catalog.yaml` | `make health-check`, `tests/test_detection_health.py` |
| A stable rule has an owner, data source, runbook, observed volume and validation date | Verified | `metadata/detection-catalog.yaml`, `docs/runbooks/` | `make health-check` |
| The catalogue's observed volume matches the Phase 1 lab analysis | Verified | `analysis/out/rule_health.json` | `tests/test_detection_health.py` |
| The recorded purple-team run detected 4 / 4 expectations at a mean MTTD of 2.45 s | Implemented (`n=4`, one run) | `purple/emulation/lab-observations.json`, `purple/results/` | `make metrics` (replay) |
| Security controls and threats are governed as code | Verified | `metadata/security-controls.yaml`, `metadata/threat-model.yaml` | `make security-preflight`, `tests/test_security_governance.py` |
| CI runs the offline checks; container and live-lab evidence is committed and guarded rather than re-run | Verified | `.github/workflows/ci.yml`, `tests/test_*_evidence.py` | CI |
| No real malware is committed; YARA samples are inert and the engine is proven with EICAR in memory | Verified | `tests/yara/samples/README.md`, `tools/yara_check.py` | `make yara-check` |

## Known gaps

These are deliberately not claimed. They are also listed in
[`docs/REVIEWER_GUIDE.md`](REVIEWER_GUIDE.md).

| Gap | Why it is open |
| :-- | :-- |
| Production field telemetry | The repo has no plant traffic. The benign corpus is generated and the lab is a Dockerised plant. |
| Host and authentication telemetry | Privilege Escalation is `0/2` because the repo has no host/auth source; tagging a network rule would be tag-gaming. |
| Purple-team breadth and repeatability | Two steps, four expectations, one recorded run. The runner now scores the lab label but does not yet score unexpected alerts or repeat runs. |
| Live execution of every rule | The live-lab proof covers 11 of 13 exercised rules; the newer breadth rules are fixture-proven and bundle-converted. |
| Commercial BAS | AttackIQ is commercial; the lab uses a deterministic harness and an optional Caldera profile. |
| 24/7 SOC operations | No on-call rota, shift handover, or production incident load. |
| Physical process safety | The lab is a software emulation; there is no physical PLC, sensor or actuator. |
| Real malware analysis | Out of scope by design. Public-sample analysis in an isolated lab would be the credible next step. |
| Production triage / MTTA | The case study has no analyst acknowledgement or resolution timestamps; it measures queue reduction, not human performance. |
| Operational maturity of most rules | 57 of 63 rules are `experimental`; only 6 have runbooks and 12 have observed lab volume. |

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
