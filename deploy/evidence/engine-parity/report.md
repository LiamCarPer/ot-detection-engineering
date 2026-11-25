# Engine parity

The converted Splunk SPL, OpenSearch PPL and Kusto KQL are executed against
the committed held-out positives, near-misses and benign corpus. A rule
passes when the engine returns exactly the same `parity_id` set as the
repository matcher.

Corpus: 1,078 events (54 positives, 24 near-misses, 1,000 benign).

Engines: Splunk 10.6.2.5 Free, index ot_parity; OpenSearch 3.10.1 PPL at http://127.0.0.1:19200; Kusto 2026.11.22.1236-2647-5eeef1d-master at http://127.0.0.1:18080 table OTTelemetry.

| Engine | Pass | Fail | Not converted | Skipped |
| :-- | --: | --: | --: | --: |
| kusto | 30 | 0 | 0 | 0 |
| opensearch | 30 | 0 | 0 | 0 |
| splunk | 30 | 0 | 0 | 0 |

## Failures

- none

## Limits

- Single-event rules only. Correlation rules aggregate over windows and are
  covered by the local stateful harness and the live Loki run.
- Splunk search clauses are the converted search without the trailing
  presentation `table`, plus `fields parity_id` so the result can be
  compared. The selection logic is unchanged.
- OpenSearch and Kusto receive one extra projection/limit clause to return
  the id column; the selection logic is unchanged.
- One lab corpus, not a production feed. The engine images are pinned by
  digest in the compose file; the observed versions are recorded above.
