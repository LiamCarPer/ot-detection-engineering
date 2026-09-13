# OT Detection Engineering

Detection-as-code for operational technology: OT Sigma rules, native protocol
DPI, MITRE ATT&CK for ICS coverage, purple-team validation, and measurable
detection quality.

This repository treats detections as software: they live in version control,
are validated and tested in CI, are converted to each target platform from a
single source of truth, and are proven against adversary emulation in a live lab.

## Why

Most OT detection content is written once, deployed by hand, and never measured.
It is duplicated across a SIEM, an NDR platform, and a firewall with no shared
provenance, no regression tests, and no answer to basic questions:

- Which ATT&CK for ICS techniques do we actually detect?
- How long does a detection take to fire (MTTD)?
- How many benign events does it flag (false positives)?
- Did a rule change break a previously working detection?

This project answers those questions with automation rather than intent.

## Approach

Detection content is split by what it can actually express, then recombined
through a shared metadata and validation layer.

| Content | Format | Rationale |
| :--- | :--- | :--- |
| Log-based detections (firewall, EDR/Sysmon, auth, application, NDR alerts) | Sigma | Portable, reviewed by CI, converted to Loki and OpenSearch. |
| Protocol DPI (Modbus function codes, register ranges, exception bursts) | Native Suricata / Zeek | Sigma cannot express industrial protocol semantics. |

Every rule, regardless of format, is tagged with MITRE ATT&CK for ICS
technique IDs, covered by labeled positive and negative fixtures, and included
in the generated coverage map.

## Architecture

```
   author              validate / test           convert               prove
┌────────────┐      ┌────────────────────┐   ┌──────────────┐   ┌──────────────────┐
│ Sigma      │─────▶│ sigma-cli check    │──▶│ pySigma      │──▶│ OT-Security-Lab  │
│ + native   │      │ + TP/FP fixtures   │   │ Loki         │   │ (purple range)   │
│ OT rules   │      │ + coverage map     │   │ OpenSearch   │   └──────────────────┘
└────────────┘      └────────────────────┘   └──────────────┘            │
       ▲                     │                      │                    ▼
  ATT&CK for ICS ◀───────────┘          NDR / SIEM platforms      MTTD / FP / coverage
  (pinned catalog)                      consume generated rules     metrics from execution
```

## Repository layout

```
rules/sigma/          Sigma rules (OT and host/host-adjacent)
rules/native/         Suricata and Zeek rules for protocol DPI
metadata/             ATT&CK for ICS catalog, validation schema
scripts/              Build-time tooling (catalog generation)
pipelines/            Sigma-to-backend conversion
coverage/             ATT&CK for ICS coverage map generator
purple/               Adversary emulation plans and runner
metrics/              MTTD / false-positive / coverage computation
tests/                Rule validation and labeled fixtures
docs/                 Design and lifecycle documentation
```

## Quickstart

```bash
make setup            # create .venv and install the toolchain
make validate         # sigma-cli rule validation
make test             # rule and tooling tests
make check            # lint + validate + test (CI entrypoint)
make convert BACKEND=loki
```

## Detection lifecycle

1. **Author** a rule with an ATT&CK for ICS technique tag and labeled fixtures.
2. **Validate** — CI parses the rule, checks required metadata, and runs it
   against positive and negative fixtures.
3. **Convert** — one rule becomes a Loki query, an OpenSearch query, or a native
   rule with recorded provenance.
4. **Emulate** — an adversary emulation plan is executed against the lab and the
   expected detection is confirmed.
5. **Measure** — MTTD, false-positive rate, detection rate, and ATT&CK coverage
   are computed from the run and published as a report.

## Status

This project is under active construction. Implemented so far:

- [x] Repository scaffold, toolchain, and CI entrypoint
- [x] Pinned MITRE ATT&CK for ICS catalog (v19.2) and generator
- [ ] OT Sigma rules and labeled fixtures
- [ ] Sigma-to-backend conversion
- [ ] ATT&CK for ICS coverage map
- [ ] Purple-team emulation plan and runner
- [ ] MTTD / false-positive / coverage metrics

## Related projects

- [OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) — the
  segmented lab this project validates detections against.
- [OT-NDR-Malcolm-Pipeline](https://github.com/LiamCarPer/OT-NDR-Malcolm-Pipeline) —
  network DPI and SIEM depth that consume generated rules.

## License

MIT. See [LICENSE](LICENSE).
