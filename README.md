# OT Detection Engineering

[![ci](https://github.com/LiamCarPer/ot-detection-engineering/actions/workflows/ci.yml/badge.svg)](https://github.com/LiamCarPer/ot-detection-engineering/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![ATT&CK for ICS](https://img.shields.io/badge/ATT%26CK%20for%20ICS-v19.2-cc0000)](metadata/attack_ics_catalog.json)

Detection-as-code for operational technology: OT Sigma rules, native protocol
DPI, MITRE ATT&CK for ICS coverage, purple-team validation, and measurable
detection quality.

Detections are treated as software. They live in version control, are validated
and tested in CI, are converted to each target platform from a single source of
truth, and are proven against adversary emulation. Coverage and detection
metrics are derived from the rules themselves, so they cannot drift.

## Start here

- **See it run in a minute:** `make setup && make demo` decodes a real DNP3,
  S7comm and OPC UA frame, matches each event against the Sigma rules, and prints
  the generated Loki, Splunk, Sentinel and OpenSearch queries. No Docker, no
  network.
- **Run the full check:** `make check` (lint, Sigma validation, 177 tests, the
  Rust decoders, and deployment-bundle drift).
- **Read the proof:** `deploy/report.md` records 11 generated detection rules
  firing on live traffic in a Dockerized OT lab, the Suricata ruleset running
  inside a Malcolm pipeline, and the decoder-to-rule proof.
- **Understand the tradeoffs:** `docs/DESIGN_DECISIONS.md` explains why the
  system is built this way and what it does not do.

## Results

Every figure is derived from the rules themselves and kept honest by tests:
`tests/test_readme.py` fails if this table drifts from `make metrics`, and the
committed evidence under `deploy/evidence/` is guarded by its own tests. Generate
the full report with `make metrics` (it writes `metrics/out/report.md`, which is
not committed). The emulation figures are replayed from a genuine run against
[OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) on 2026-09-13
(lab `6d68b6f`); the raw capture is committed at
`purple/emulation/lab-observations.json` and documented in
[`purple/emulation/lab-run.md`](purple/emulation/lab-run.md).

| Metric | Value | Scope |
| :--- | ---: | :--- |
| Emulation detection rate | 100% (4 / 4 expectations) | Two emulation steps — enterprise pivot (Modbus write, cross-zone traffic, I/O brute force) and a process-safety violation. |
| Mean MTTD (live lab) | 2.45 s | Time from action start to first matching alert, replayed from the recorded lab run. |
| Rule fixture agreement (precision) | 1.0 | Rule matches against its own committed positive/negative fixtures. A regression check, not field precision. |
| Rule fixture agreement (recall) | 1.0 | As above. |
| Baseline false-positive rate | 0.0 | 50 committed benign events across every protocol and stream the rules consume. |
| ATT&CK for ICS coverage | 15 / 97 techniques (15.5%) | Intentionally low: a small, fully tested ruleset rather than untested padding. |

Coverage is intentionally low: this repository seeds the pipeline with a small,
fully tested ruleset rather than padding coverage with untested rules. The point
is the engineering process, which scales to a large ruleset unchanged.

## Scope and limitations

The repository is explicit about what is proven and what is not, because a
detection is only as trustworthy as the evidence behind it.

- **What is machine-checked.** Every rule is parsed, tagged, converted and tested
  in CI; the native rules are executed by Suricata over committed captures; the
  Loki ruler bundle is executed in a full stack; the decoders' output is run
  through the same matcher the rule tests use; and coverage, precision, recall
  and false-positive rate are derived from the rules. All of that runs offline
  and deterministically.
- **What is emulated.** The lab this project validates against is a Dockerized
  software emulation of a segmented plant; there is no physical PLC, sensor or
  actuator. The emulation figures come from a recorded run against that lab.
- **Fixture metrics are agreement, not field performance.** Precision and recall
  are computed against fixtures authored alongside each rule, so they measure
  that the rule and its fixtures agree — useful as a regression guard, not as a
  claim about production precision.
- **The benign baseline is small.** The baseline false-positive rate is measured
  over 50 committed benign events spanning normal Modbus, DNP3, S7comm and OPC UA
  traffic, zone-firewall decisions and process updates. It is authored, not
  harvested from a plant, so it catches a rule that fires on clearly
  benign telemetry, not enough to estimate field false-positive volume.
- **Emulation scope.** The emulation plan covers two adversary steps and four
  expectations; it does not exercise every rule.
- **Protocol limits.** The S7comm decoder handles classic S7comm only (not
  S7comm Plus); OPC UA service bodies are only visible on unencrypted channels
  (`None`/`Sign`, not `SignAndEncrypt`); the DNP3 decoder reads the first object
  header only; and the native Modbus/DNP3 rules require Suricata's application
  layer to be enabled.
- **CI vs. local validation.** CI runs the offline checks and the decoder proof.
  The container validations (Suricata, Loki, Malcolm) and the live-lab capture
  require Docker or the lab, so they run locally and their committed evidence is
  guarded by tests rather than re-run on every commit.

## Approach

Detection content is split by what each format can actually express, then
recombined through shared metadata, testing and metrics.

| Content | Format | Rationale |
| :--- | :--- | :--- |
| Log-based detections (firewall, NDR alerts, application and process events) | Sigma | Portable, converted by pySigma, testable offline. |
| Protocol DPI (Modbus and DNP3 function codes, S7comm program transfer, OPC UA services) | Native Suricata, plus Rust decoders for DNP3, S7comm and OPC UA application semantics | Sigma cannot express industrial protocol semantics. |

Every rule, regardless of format, carries an ATT&CK for ICS technique, is
covered by labeled fixtures, and is included in the generated coverage map.

Log-based rules are converted from Sigma into the platforms detection teams
actually run: **Loki LogQL**, **OpenSearch PPL**, **Splunk SPL** and
**Microsoft Sentinel KQL** (Kusto).

## Architecture

```
rules/sigma/**/*.yml ──┐
                       ├─▶ tools/otde ──▶ ATT&CK coverage map
rules/native/**/*.rules┘        │
                                ├─▶ metrics (precision / recall / FPR / coverage)
                                │
Sigma rule ──▶ pipelines/convert.py ──▶ Loki LogQL / OpenSearch PPL /
                                        Splunk SPL / Sentinel KQL + provenance

rules/** ──▶ pipelines/deploy.py ──▶ deploy/ bundle + provenance manifest
native rules ──▶ tests/captures ──▶ Suricata (container) ──▶ deploy/evidence

DNP3 frames   ──▶ tools/dnp3-dpi (Rust)   ──▶ ot_ndr/dnp3 events   ──▶ Sigma rules
S7comm frames ──▶ tools/s7comm-dpi (Rust) ──▶ ot_ndr/s7comm events ──▶ Sigma rules
OPC UA msgs   ──▶ tools/opcua-dpi (Rust)  ──▶ ot_ndr/opcua events  ──▶ Sigma rules

emulation plan ──▶ purple/runner ──▶ detection rate + MTTD ──▶ metrics
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design rationale,
[docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md) for why the system is built
this way and what it does not do, and [docs/TELEMETRY.md](docs/TELEMETRY.md) for
the event contracts.

## Repository layout

```
rules/sigma/          Sigma rules with *.test.yaml positive/negative fixtures
rules/native/         Suricata rules for protocol DPI
metadata/             Pinned ATT&CK for ICS catalog and JSON Schemas
tools/otde/           Shared library: discovery, technique extraction, matcher
tools/dnp3-dpi/       Rust DNP3 decoder emitting normalized ot_ndr/dnp3 events
tools/s7comm-dpi/     Rust S7comm decoder emitting normalized ot_ndr/s7comm events
tools/opcua-dpi/      Rust OPC UA decoder emitting normalized ot_ndr/opcua events
pipelines/            Sigma-to-backend conversion and deployment bundle builder
deploy/               Installable bundle: Loki ruler, Suricata, Splunk, Sentinel, OpenSearch
coverage/             ATT&CK for ICS coverage map generator
purple/               Adversary emulation plan, runner and recorded observations
metrics/              Detection-quality computation and benign baseline
tests/                Rule, metadata, coverage and metrics tests
docs/                 Architecture, design decisions, telemetry and lifecycle docs
```

## Quickstart

```bash
make setup             # create .venv and install the toolchain
make demo              # offline decoder -> Sigma rule -> SIEM query walkthrough
make check             # lint + sigma-cli validation + tests + Rust + bundle drift
make convert BACKEND=loki
make convert BACKEND=opensearch
make convert BACKEND=splunk     # Splunk SPL
make convert BACKEND=sentinel   # Microsoft Sentinel KQL
make convert-all                # all four target platforms
make deploy            # build the installable bundle under deploy/
make suricata-check    # validate the native rules over captures (Docker)
make loki-check        # prove the Loki ruler bundle in a full stack (Docker)
make decoder-check     # prove the decoders' events fire the Sigma rules
make metrics           # coverage + emulation replay + metrics report
```

`make check` and `make metrics` need no SIEM, lab or external data source: the
ATT&CK catalog is pinned in-tree, fixtures are committed, and dependencies are
pinned in `requirements.txt`. `make suricata-check` and `make loki-check` require
Docker (both pull their images on first run); `make lab-loki-check` requires the
live lab.

## Detection lifecycle

```
author ─▶ validate ─▶ test ─▶ convert/bundle ─▶ emulate ─▶ measure
```

1. **Author** a rule with an ATT&CK for ICS tag and labeled fixtures.
2. **Validate** with `sigma check` and the metadata governance tests.
3. **Test** each rule against positive and negative events.
4. **Convert and bundle** one rule into Loki, OpenSearch, Splunk and Sentinel
   queries, and into an installable `deploy/` bundle with recorded provenance.
5. **Emulate** an adversary action in the lab and confirm the expected detection.
6. **Measure** coverage, precision, recall, false-positive rate, detection rate
   and MTTD.

Full instructions are in [docs/DETECTION_LIFECYCLE.md](docs/DETECTION_LIFECYCLE.md).

## Deployment and validation

`make deploy` turns the rules into an installable bundle under [`deploy/`](deploy/):
Grafana Loki ruler alerts, a Suricata ruleset, Splunk saved searches and Sentinel
queries, with a provenance manifest and a per-platform runbook
([deploy/DEPLOY.md](deploy/DEPLOY.md)). `python pipelines/deploy.py --check`
fails CI when the committed bundle drifts from the rules.

The bundles are functionally validated, not just linted. `make suricata-check`
runs Suricata in a container over the committed captures in `tests/captures/`,
`make loki-check` runs the generated Loki ruler rules in a full stack (Loki,
Alertmanager, Grafana), and `make decoder-check` runs the Rust decoders over the
committed example frames and feeds the decoded events through the Sigma rules.
Each refreshes evidence in `deploy/evidence/`. The results are recorded in
[deploy/report.md](deploy/report.md): every attack capture fires exactly the
expected signatures, every Loki ruler alert fires, every protocol rule fires on
the decoded events, and no benign input produces an alert. The Suricata ruleset
is also installed into a Malcolm pipeline and run with Malcolm's own Suricata
image and default ruleset (`tools/malcolm_check.py`), confirming it loads and
fires there rather than only in isolation. The Loki ruler bundle is deployed
into [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab), a live
segmented lab with real DNP3, OPC UA and S7comm endpoints. After the lab's own
adversary emulations run, `tools/lab_loki_check.py` confirms **11 of the 13
generated rules firing on live lab traffic** — every DNP3, OPC UA, S7comm,
firewall and process rule. The two generated Modbus rules are validated offline
instead: the lab reports Modbus as JSON alert events, not normalized `ot_ndr`
telemetry. The proof is committed under `deploy/evidence/lab-loki/`; the full
breakdown is in [deploy/report.md](deploy/report.md).

## Tooling

- **pySigma / sigma-cli** for parsing, validation and conversion, with the
  official Loki, OpenSearch, Splunk and Kusto (Sentinel KQL) backends.
- **JSON Schema** for rule test cases, the ATT&CK catalog and the emulation plan.
- **Pinned ATT&CK for ICS v19.2** catalog, regenerated from the upstream STIX
  collection by `scripts/build_attack_catalog.py`.
- **A pySigma-based validation matcher** that interprets pySigma's parsed rule
  model and raises on unsupported features instead of passing silently.
- **Dependency-free Rust protocol decoders** (`tools/dnp3-dpi`,
  `tools/s7comm-dpi` and `tools/opcua-dpi`, `#![forbid(unsafe_code)]`) that
  validate framing (CRC-16/DNP for DNP3) and emit the normalized events the DNP3,
  S7comm and OPC UA Sigma rules consume.
- **Suricata functional validation in a container** over generated captures
  (Scapy), with committed alert evidence, so the native rules are proven to fire
  rather than only parsed.
- **Decoder-to-rule validation**: each decoder's committed example frames are
  decoded and the resulting events are run through the same pySigma matcher the
  rule tests use, so the decoders and their Sigma rules cannot drift apart.

## Status and roadmap

Implemented: detection-as-code pipeline, OT Sigma rules, native protocol DPI for
Modbus/TCP, DNP3, OPC UA and S7comm (DNP3, S7comm and OPC UA also decoded in
Rust for application-layer Sigma rules), multi-platform conversion (Loki,
OpenSearch, Splunk SPL, Sentinel KQL), installable deployment bundles, Suricata
functional validation over committed captures and in a Malcolm pipeline, ATT&CK
for ICS coverage, adversary emulation, and detection metrics. The pipeline,
conversion, tests, coverage and metrics run in CI; the container, Malcolm and
live-lab validations run locally and their committed evidence is guarded by
tests.

Integration status:

- [x] Install the Suricata ruleset into
      [OT-NDR-Malcolm-Pipeline](https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline)
      and run it with Malcolm's own Suricata image and default ruleset over the
      captures, recording provenance in `deploy/evidence/malcolm/`.
- [x] Install the Loki ruler bundle into
      [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) and confirm
      the generated DNP3, OPC UA, S7comm, firewall and process rules firing on
      live lab traffic, recording provenance in `deploy/evidence/lab-loki/`.
- [ ] Run emulation against the live lab in CI and publish live metrics.
- [ ] Add Wazuh as a conversion target.

Protocol coverage:

- [x] Modbus/TCP — native Suricata function-code DPI.
- [x] DNP3 — native Suricata function/object DPI, plus a Rust application-layer
      decoder with Sigma rules over the decoded events.
- [x] S7comm — native Suricata function-code DPI (program download/upload, PLC
      stop, unauthorized write), plus a Rust application-layer decoder with
      Sigma rules for program transfer and mode changes.
- [x] OPC UA — native Suricata TCP message-header DPI, plus a Rust service
      decoder with Sigma rules for plaintext (None/Sign) channels.
- [ ] PROFINET (layer-2 / DCE-RPC; needs non-IP rule hooks).

## Related projects

- [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) — the
  segmented lab this project validates detections against.
- [OT-NDR-Malcolm-Pipeline](https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline) —
  network DPI and SIEM depth that consume generated rules.

## License

MIT. See [LICENSE](LICENSE).
