# Detection lifecycle

Every detection follows the same path. Nothing is merged that has not passed the
automated checks, and every number in the report is derived from the rules
themselves.

```
author ─▶ validate ─▶ test ─▶ convert/bundle ─▶ emulate ─▶ measure
```

## 1. Author

### A log-based detection (Sigma)

Create `rules/sigma/ot/<name>.yml`. Required metadata is enforced in CI: UUID,
title, description, author, date, level, logsource, false positives, and at
least one ATT&CK for ICS technique tag.

```yaml
title: Example Detection
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: What this detects and why it matters.
references:
  - https://attack.mitre.org/techniques/T0000/
author: Liam Carvajal
date: 2026-09-13
logsource:
  product: ot_ndr
  service: modbus
detection:
  selection:
    function_code: 6
  condition: selection
fields:
  - src_ip
  - dst_ip
falsepositives:
  - Documented benign cause.
level: high
tags:
  - attack.t0000
```

Add a sidecar `rules/sigma/ot/<name>.test.yaml` with at least one positive and
one negative case:

```yaml
cases:
  - name: unauthorized write
    expect: match
    event:
      function_code: 6
      src_ip: 172.24.0.10
  - name: authorized write
    expect: no_match
    event:
      function_code: 6
      src_ip: 172.21.0.20
```

The event fields must match the telemetry contract in
[TELEMETRY.md](TELEMETRY.md).

### A protocol DPI detection (native Suricata)

Create or extend a file under `rules/native/suricata/`. Every rule needs `msg`,
`classtype`, `sid`, `rev`, and `metadata: attack_ics <technique>`. SIDs live in
the reserved `9000000-9000099` range and must be unique.

## 2. Validate

```bash
make validate          # sigma-cli parsing and best-practice checks
make lint              # ruff
make emulate-validate  # emulation plan consistency
```

`make validate` excludes sigma-cli's ATT&CK validator, which only knows
Enterprise ATT&CK; ICS tags are checked against the pinned catalog by the test
suite.

## 3. Test

```bash
make test
```

This runs the rule fixtures, metadata governance, native rule lint, coverage and
metrics consistency, and the emulation logic. A rule without a sidecar, without
a positive case, or with a tag that is not in the catalog fails.

## 4. Convert and bundle

```bash
make convert BACKEND=loki
make convert BACKEND=opensearch
make convert BACKEND=splunk    # Splunk SPL
make convert BACKEND=sentinel  # Microsoft Sentinel KQL
make convert-all               # all four target platforms
make deploy                    # installable bundle under deploy/
```

Generated queries land in `pipelines/out/` and the installable bundle under
`deploy/`, each with a manifest that links every artifact to the SHA-256 of the
rule revision that produced it. Output is deterministic, so a diff always
reflects a rule change.

## 5. Emulate

Map the new detection to an adversary action in
`purple/emulation/emulation-plan.yaml`:

```yaml
- id: my-step
  name: Adversary action
  technique: T0000
  description: What the adversary does.
  execute:
    command: docker exec ot_attacker python3 /attacker/<script>.py
  expectations:
    - signal: ALERT_TYPE_EMITTED_BY_THE_LAB
      technique: T0000
      rule: rules/sigma/ot/<name>.yml
```

Validate the plan, then run it against a live lab or replay a recorded run:

```bash
make emulate-validate
python purple/runner/run_emulation.py --execute --alerts /path/to/alerts.json
python purple/runner/run_emulation.py \
  --observations purple/emulation/lab-observations.json
```

The runner checks that the referenced rule actually carries the expected
technique, so a plan cannot claim coverage a rule does not provide.

## 6. Measure

```bash
make metrics
```

Produces `metrics/out/report.md` and `metrics/out/metrics.json`: coverage, rule
precision and recall from fixtures, false-positive rate against the benign
baseline, and emulation detection rate and MTTD.

## Updating the ATT&CK catalog

```bash
curl -sSL -o /tmp/ics-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json
python scripts/build_attack_catalog.py --stix /tmp/ics-attack.json
```

Review the diff: a technique that moved or was deprecated will surface as a
failing tag check, which is the point.

## Review checklist

- [ ] Rule has complete metadata and a known ICS technique tag.
- [ ] Sidecar has at least one positive and one negative case.
- [ ] `make check` passes (including deployment-bundle drift).
- [ ] Backend conversion succeeds for every target.
- [ ] `make deploy` run so `deploy/` and its manifest match the rule.
- [ ] For a native rule, `make suricata-check` refreshed `deploy/evidence/`.
- [ ] For a Sigma rule, `make loki-check` refreshed `deploy/evidence/loki/`.
- [ ] Emulation plan updated if the technique is newly covered.
- [ ] Metrics regenerated and committed in the pull request description.
