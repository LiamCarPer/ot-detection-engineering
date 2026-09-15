# Architecture

## Goal

Treat OT detections as software: versioned, reviewed, tested, converted from a
single source of truth, proven against adversary emulation, and measured. The
offline checks are self-contained; integration with the live lab, a Malcolm
pipeline and the target SIEM query languages is done, and the evidence is
committed under `deploy/evidence/`.

## Design principles

1. **One source of truth per detection.** A rule is authored once. Queries for
   Loki, OpenSearch, Splunk and Microsoft Sentinel are generated from it, never
   hand-maintained.
2. **Derive, do not duplicate.** ATT&CK coverage and detection metrics are
   computed from rule content, so they cannot disagree with the rules.
3. **Fail loudly.** The validation matcher raises on Sigma features it does not
   implement rather than silently passing a test.
4. **Offline-first.** The detection checks need no external data source: no
   SIEM, no lab and no live feed. The ATT&CK catalog is pinned in-tree, fixtures
   are committed, and dependencies are pinned.

## Content model

Detection content is split by what each format can actually express.

| Format | Used for | Why |
| :--- | :--- | :--- |
| Sigma | Log-based detections: firewall decisions, NDR alerts, application and process events. | Portable, parsed and converted by pySigma, testable offline. |
| Native Suricata | Modbus function codes, exception responses and other protocol DPI. | Sigma has no vocabulary for industrial protocol semantics; forcing it would lose fidelity. |

Both formats are governed identically: every rule carries an ATT&CK for ICS
technique, and both feed the same coverage and metrics calculations.

## Data flow

```
rules/sigma/**/*.yml ──┐
                       ├─▶ tools/otde ──▶ coverage map (JSON/MD/HTML)
rules/native/**/*.rules┘        │
                                ├─▶ metrics (precision/recall/FPR/coverage)
                                │
Sigma rule ──▶ pipelines/convert.py ──▶ Loki LogQL / OpenSearch PPL /
                                        Splunk SPL / Sentinel KQL + manifest

rules/** ──▶ pipelines/deploy.py ──▶ deploy/ bundle + provenance manifest
native rules ──▶ tests/captures ──▶ Suricata (container) ──▶ deploy/evidence

DNP3/S7comm/OPC UA ──▶ tools/*-dpi (Rust) ──▶ ot_ndr events ──▶ Sigma rules

decoder examples ──▶ tools/decoder_check.py ──▶ ot_ndr events ──▶ Sigma rules
                                                              └─▶ deploy/evidence

emulation-plan.yaml ──▶ purple/runner ──▶ detection rate + MTTD ──▶ metrics
        (or recorded observations)         (against the lab or a replay)
```

## Components

| Path | Responsibility |
| :--- | :--- |
| `rules/` | Detection content: Sigma rules with `.test.yaml` sidecars, and native Suricata rules. |
| `metadata/` | Pinned ATT&CK for ICS catalog and JSON Schemas for rule test cases, the catalog, and the emulation plan. |
| `tools/otde/` | Shared library: rule discovery, technique extraction, Suricata reader, and the pySigma-based validation matcher. |
| `tools/dnp3-dpi/`, `tools/s7comm-dpi/`, `tools/opcua-dpi/` | Dependency-free Rust decoders (Cargo workspace) that emit normalized `ot_ndr` events for the DNP3, S7comm and OPC UA Sigma rules. |
| `pipelines/` | Sigma-to-backend conversion and the deployment bundle builder. |
| `deploy/` | Committed, installable bundle (Loki ruler, Suricata, Splunk, Sentinel), provenance manifest, runbook and Suricata evidence. |
| `coverage/` | Derived ATT&CK for ICS coverage map. |
| `purple/` | Adversary emulation plan, runner, and recorded observations. |
| `metrics/` | Detection-quality computation and the benign baseline corpus. |
| `tests/` | Rule regression, metadata governance, native rule lint, coverage and metrics tests. |

## Tooling choices

- **pySigma and sigma-cli** are the industry-standard Sigma toolchain. Rules are
  parsed by pySigma and converted by official backends (`pySigma-backend-loki`,
  `pySigma-backend-opensearch`, `pySigma-backend-splunk`, `pySigma-backend-kusto`).
  Splunk SPL and Microsoft Sentinel KQL are first-class targets because those are
  the platforms most enterprise and MSSP detection teams run.
- **The validation matcher builds on pySigma's parsed model**, not on a
  re-implementation of Sigma. pySigma handles condition parsing and modifier
  application; the matcher only interprets the resulting tree. This keeps the
  test semantics aligned with the reference implementation.
- **Native rules are validated functionally, not only linted.** Suricata runs in
  a container over captures generated with Scapy, and the alert evidence is
  committed. This is what surfaced that Suricata ships Modbus and DNP3
  application-layer detection disabled by default, and that the original Modbus
  exception rule used invalid syntax.
- **Decoder output is validated against the rules, not assumed.** Each decoder's
  committed example frames are decoded and the resulting events are run through
  the same matcher the rule tests use (`tools/decoder_check.py`), so the decoder
  and its Sigma rules cannot drift apart.
- **Protocols are decoded natively in Rust** when no app-layer parser exists.
  DNP3, S7comm and OPC UA have dependency-free decoders (`#![forbid(unsafe_code)]`)
  that emit the normalized events the corresponding Sigma rules run on. S7comm
  carries no source identity, so its unauthorized-write detection lives in the
  native Suricata rules where the client IP is available; OPC UA service bodies
  are only readable when the channel is not encrypted, so `SignAndEncrypt`
  traffic yields metadata but no service.
- **JSON Schema** governs rule test cases, the catalog and the emulation plan, so
  malformed metadata fails in CI with a precise location.
- **The ATT&CK for ICS catalog is pinned** and regenerated by a script. Coverage
  checks run offline and against an explicit dataset version.

## Testing strategy

| Layer | What it proves |
| :--- | :--- |
| `test_sigma_matcher.py` | The matcher's semantics: equality, wildcards, regex, CIDR, comparisons, keyword and unsupported-feature handling. |
| `test_sigma_rules.py` | Every rule fires on its positive fixtures and stays quiet on its negative fixtures. |
| `test_metadata.py` | Rule policy, unique IDs, and ATT&CK tags that exist in the pinned ICS catalog. |
| `test_native_rules.py` | Native rules carry required fields, unique reserved SIDs and known technique tags. |
| `test_emulation.py` | The emulation plan is valid and the evaluation logic computes detection rate and MTTD correctly. |
| `test_coverage.py`, `test_metrics.py` | Derived coverage and metrics are internally consistent, and no rule fires on the benign baseline. |
| `test_deploy.py`, `test_deploy_evidence.py` | The bundle matches the rules and the committed Suricata evidence fires the expected signatures. |
| `test_malcolm_evidence.py` | The committed Malcolm evidence shows the ruleset loading with no failures alongside Malcolm's default rules and firing the expected signatures on every capture. |
| `test_lab_loki_evidence.py` | The committed lab evidence shows the generated DNP3, OPC UA, S7comm, firewall and process ruler rules firing in OT-Security-Lab on lab-shipped normalized events. |
| `test_decoder_evidence.py` | The committed decoder evidence fires each protocol's Sigma rules on real decoder output. |
| `test_loki_evidence.py`, `test_readme.py` | The committed Loki ruler evidence is complete and the README figures match the generated metrics. |

## Metric definitions

- **Coverage** — techniques with at least one detection divided by all ICS
  techniques in the pinned catalog.
- **Precision** — true positives divided by true positives plus false positives,
  from labeled fixtures.
- **Recall** — true positives divided by true positives plus false negatives,
  from labeled fixtures.
- **Baseline false-positive rate** — benign events matched by any rule divided by
  all benign events. The committed baseline holds 50 events, so this catches a
  rule that fires on clearly benign telemetry rather than estimating field
  false-positive volume.
- **Detection rate** — emulation expectations that fired divided by all
  expectations.
- **MTTD** — mean time from the start of an emulation step to the first matching
  alert, in seconds.

## Integration points

The repository is built to plug into the live environment without changing
detection content:

- **Suricata rules are installed in a Malcolm pipeline.** `tools/malcolm_check.py`
  copies `deploy/suricata/ot-detection.rules` into a Malcolm installation and
  runs Malcolm's own Suricata image and configuration over the captures, with
  the default ruleset enabled; the result is committed under
  `deploy/evidence/malcolm/`. This is what surfaced the SID collision with the
  NSacyber ELITEWOLF rules and moved the repository to the private
  `9000000-9000099` range.
- **The Loki ruler bundle is installed in the lab.** `siem/rules/` in
  [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) holds the
  generated bundle. The lab runs real DNP3, OPC UA and S7comm endpoints plus DPI
  producers that ship normalized `ot_ndr` events, and the gateway's
  `firewall_events.py` ships normalized `ot_firewall` events; those, with the
  physics-aware monitor's `ot_process` events, exercise the generated rules.
  `tools/lab_loki_check.py` records the DNP3, OPC UA, S7comm, firewall and
  process rules firing on live traffic under `deploy/evidence/lab-loki/`.
- `pipelines/convert.py` emits Loki, OpenSearch, Splunk and Microsoft Sentinel
  queries, and `pipelines/deploy.py` packages them into an installable `deploy/`
  bundle.
- `purple/runner/run_emulation.py --execute` runs the plan against
  [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) via
  `docker exec`.
