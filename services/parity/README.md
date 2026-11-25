# Real engines for parity

The repository converts every single-event Sigma rule to Loki, Splunk, Sentinel
(KQL) and OpenSearch (PPL). `make convert-all` proves that an artifact exists;
`make engine-parity` proves that the artifact selects the same events as the
repository matcher.

This directory starts the two engines that are not part of the OT lab:

- **Splunk Free** on `127.0.0.1:18000` (REST `18089`, HEC `18088`), index
  `ot_parity`.
- **OpenSearch** on `127.0.0.1:19200` (security plugin disabled, PPL enabled),
  with `*-parity` indices created and removed by the harness.

Loki is measured separately on live lab traffic by `make lab-loki-check`. Kusto
uses the lab's `kustainer` on `127.0.0.1:18080`; the harness writes and then
drops only the `OTTelemetry` table.

## Start

```bash
docker compose -f services/parity/docker-compose.yml up -d
```

Starting the container sets `SPLUNK_GENERAL_TERMS` and
`SPLUNK_START_ARGS=--accept-license`, which is Splunk's required signal that you
accept the Splunk General Terms and the Free licence. Splunk takes one to two
minutes on first start. Splunk Free is single-user and
has a 500 MB/day indexing limit, far above the few hundred parity events.

## Run

```bash
make engine-parity
```

## Stop

```bash
docker compose -f services/parity/docker-compose.yml down -v
```

The harness is destructive only inside its own index/table names: `ot_parity`,
`*-parity` and `OTTelemetry`. It does not change the lab's own data.
