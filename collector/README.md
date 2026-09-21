# Collector

The Sigma rules run on a normalized event contract ([docs/TELEMETRY.md](../docs/TELEMETRY.md)),
not on a vendor's native format. This package is the producer: it turns standard
sensor output into contract events with the routing fields the rules select on.

Without it the contract exists only as fixtures and decoder output, and a
reviewer can reasonably ask where the events come from in a real deployment.

## Usage

```bash
python -m collector.cli --source suricata --input eve.json
python -m collector.cli --source zeek --input modbus.log --input dnp3.log
python -m collector.cli --source suricata --input eve.json \
  --sink loki --loki-url http://localhost:3100/loki/api/v1/push
python -m collector.cli --source suricata --input eve.json --dry-run --sink loki
```

Every emitted event is validated against `metadata/telemetry.schema.json`;
violations are printed to stderr and make the command exit non-zero. The default
sink is JSON Lines on stdout. The Loki sink ships one stream per
`(product, service)` with the `service` label the generated ruler queries select
on, so the collector and the rules agree on routing.

## Sources

| Source | Adapter | Reads |
| :-- | :-- | :-- |
| Suricata | `collector/sources/suricata.py` | `eve.json` OT application-layer records (`modbus`, `dnp3`) |
| Zeek | `collector/sources/zeek.py` | `modbus.log`, `dnp3.log` (tab-separated, `#fields` header) |

A source that cannot see a field omits it rather than guessing, so a rule can
tell "the master was authorized" from "the master was not visible".

## Sensor fidelity

The same protocol yields different fields depending on the sensor, which changes
which detections are possible. This is a real property of OT collection, not a
gap in the collector:

| Contract field | Suricata | Zeek | Rust decoder |
| :-- | :--: | :--: | :--: |
| `direction`, `function_code` | yes | yes (mapped from the name) | yes |
| `src_ip` / `dst_ip` | yes | yes | no |
| `unit_id` | yes | yes | n/a |
| `register` / `value` | yes | **no** | n/a |
| `link_source` / `link_destination` | yes | **no** | yes |
| `object_group` / `object_variation` | yes | no | yes |
| S7comm / OPC UA service | no | no | yes |

Consequences, made explicit because they affect detection:

- **The parameter-band write rule cannot fire on Zeek data** — Zeek's
  `modbus.log` has no register address. The decoder and Suricata paths do.
- **The DNP3 control rule's master allowlist cannot be applied on Zeek data** —
  Zeek's `dnp3.log` has no link addresses. Today the rule treats an unidentified
  master as unauthorized, so it fires on Zeek control requests. The correct fix
  is for the rule to require link identity (so it never mis-attributes) and to
  add a separate "control from an unidentified master" rule; that change is
  tracked as follow-up work because it touches the generated bundle.

## The proof

`make collector-check` (`tools/collector_check.py`) normalizes the committed
samples, validates every event against the schema, routes them through the same
pySigma matcher the rule tests use, and asserts the rules fired against
`tools/otde/evidence.py`. The evidence is committed at
`deploy/evidence/collector/summary.json` and guarded by
`tests/test_collector_evidence.py`. It needs no SIEM and no container, so it runs
in CI.

## Samples

The committed samples under `collector/samples/` are real Suricata and Zeek
output captured from the repository's own PCAPs. See
[`samples/PROVENANCE.md`](samples/PROVENANCE.md) for the exact commands.
