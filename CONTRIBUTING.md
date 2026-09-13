# Contributing

This repository treats detection content as code. Contributions are expected to
follow the same lifecycle as the existing rules.

## Before opening a pull request

```bash
make check     # lint + sigma-cli validation + tests
make metrics   # regenerate coverage and the metrics report
```

Both must pass. CI runs `make check`'s constituent steps and fails on any rule
that is invalid, untested, untagged, or that fires on the benign baseline.

## Conventions

- **One detection per file.** Sigma rules live in `rules/sigma/{ot,host}/`,
  native protocol rules in `rules/native/`.
- **Every rule is tested.** A Sigma rule needs a `.test.yaml` sidecar with at
  least one `match` and one `no_match` case. See
  [docs/DETECTION_LIFECYCLE.md](docs/DETECTION_LIFECYCLE.md).
- **Every rule is tagged.** At least one ATT&CK for ICS technique tag, drawn
  from `metadata/attack_ics_catalog.json`.
- **Respect the SID range.** Native rules use unique SIDs in `1000000-1000999`.
- **Document false positives.** The `falsepositives` field is required and is
  used to interpret baseline results.
- **Do not hand-edit derived artifacts.** Coverage and metrics are generated.

## Commit style

Commits are scoped and describe the detection or tooling change, not the
mechanics. Examples: `feat: detect Modbus writes from unauthorized control
writers`, `fix: exclude device identification responses from the scan rule`.

## Reporting issues

Open an issue with the rule or component, the observed behaviour, and a
reproducing event or command. For detection gaps, include the ATT&CK for ICS
technique and a sample event.
