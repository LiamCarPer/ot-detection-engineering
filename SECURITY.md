# Security policy

## Supported versions

This repository ships detection content, not a long-lived service. Security fixes
are applied to `main`; there is no back-port branch. The `deploy/` bundle is
regenerated from `main`, so install from a build of the current commit.

## Reporting a vulnerability

Please report privately through GitHub's **Security advisories** for this
repository ("Report a vulnerability") rather than in a public issue. Include:

- the affected component (rule, decoder, collector, pipeline, workflow),
- a minimal reproduction or the malformed input,
- the impact you believe it has, and
- whether you intend to publish.

You will get an acknowledgement within **3 working days**. We will confirm the
issue, agree a disclosure date, and credit you unless you prefer otherwise.

Do **not** test against systems you do not own. The lab in
[OT-Security-Lab](https://github.com/LiamCarPer/OT-Security-Lab) is a separate
project with its own policy; this policy covers only this repository.

## Severity and remediation

Severity uses CVSS v3.1, with an OT-specific adjustment: a defect that can stop
telemetry or crash a passive sensor is treated as one band higher than its base
score, because loss of visibility in OT is a safety-relevant outcome. The
remediation targets are in
[docs/VULNERABILITY_MANAGEMENT.md](docs/VULNERABILITY_MANAGEMENT.md).

## Scope

In scope: the Python tooling, the Rust decoders, the collector, the generated
bundles, the GitHub Actions workflows, and the ingest service when present.
Out of scope: third-party tools (pySigma, Suricata, Loki, Malcolm) — report those
upstream — and the emulated lab environment.
