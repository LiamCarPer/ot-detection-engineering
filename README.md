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

## Results

Kept in sync with `make metrics` by `tests/test_readme.py`; the full report is at
`metrics/out/report.md`. The emulation figures are from a genuine run against
[OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) on 2026-09-13
(lab `6d68b6f`); the raw capture is committed at
`purple/emulation/lab-observations.json` and documented in
[`purple/emulation/lab-run.md`](purple/emulation/lab-run.md).

| Metric | Value |
| :--- | ---: |
| ATT&CK for ICS coverage | 11 / 97 techniques (11.3%) |
| Rule precision (labeled fixtures) | 1.0 |
| Rule recall (labeled fixtures) | 1.0 |
| Baseline false-positive rate | 0.0 |
| Emulation detection rate | 100% (4 / 4 expectations) |
| Mean MTTD (live lab) | 2.45 s |

Coverage is intentionally low: this repository seeds the pipeline with a small,
fully tested ruleset rather than padding coverage with untested rules. The point
is the engineering process, which scales to a large ruleset unchanged.

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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design rationale and
[docs/TELEMETRY.md](docs/TELEMETRY.md) for the event contracts.

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
deploy/               Installable bundle: Loki ruler, Suricata, Splunk, Sentinel
coverage/             ATT&CK for ICS coverage map generator
purple/               Adversary emulation plan, runner and recorded observations
metrics/              Detection-quality computation and benign baseline
tests/                Rule, metadata, coverage and metrics tests
docs/                 Architecture, telemetry and lifecycle documentation
```

## Quickstart

```bash
make setup             # create .venv and install the toolchain
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

`make check` and `make metrics` need no SIEM, lab or network access: the ATT&CK
catalog is pinned in-tree and fixtures are committed. Only `make suricata-check`
requires Docker (and pulls the Suricata image on first run).

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
fires there rather than only in isolation.

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
for ICS coverage, adversary emulation, and detection metrics, all wired into CI.

Deferred by design (integration phase):

- [x] Install the Suricata ruleset into
      [OT-NDR-Malcolm-Pipeline](https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline)
      and run it with Malcolm's own Suricata image and default ruleset over the
      captures, recording provenance in `deploy/evidence/malcolm/`.
- [ ] Install the Loki ruler bundle into
      [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) end to
      end, recording deployment provenance.
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
