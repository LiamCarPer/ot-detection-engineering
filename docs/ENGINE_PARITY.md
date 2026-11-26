# Engine parity

The deployment bundle contains a query for every single-event rule in four
languages. Producing a query is not the same as producing a query that selects
the intended events.

## Method

`tools/engine_parity.py` builds a corpus from the committed held-out positives,
the near-misses and the benign corpus. Each event gets a `parity_id`. The
repository matcher produces the golden `parity_id` set for every single-event
Sigma rule. The converted query is then executed in the real engine and the
returned set is compared exactly: a missing id is a false negative, an extra id
is a false positive, and either one fails parity.

- **Splunk Free** (`services/parity/docker-compose.yml`) receives the corpus over
  HEC into `index=ot_parity` with indexed JSON extraction. Searches run through
  the REST search API.
- **OpenSearch** (`services/parity/docker-compose.yml`) receives one `*-parity`
  index per product/service and runs the generated PPL through `_plugins/_ppl`.
- **Kusto** (`kustainer`) receives the corpus in `OTTelemetry` and runs the
  generated Sentinel KQL.
- **Loki** is measured on live lab traffic by `make lab-loki-check`, not here.

Two deployment facts the harness has to supply, because the emitted queries do
not contain them:

- Splunk saved searches are installed against an index/sourcetype, and Sentinel
  queries against a table that holds one product. The harness indexes everything
  in one place, so it adds `product`/`service` scoping from the rule's
  logsource. Without that, a DNP3 rule matches Modbus events that share field
  names.
- The presentation clause (`| table ...`) is removed and replaced with
  `fields parity_id`, and OpenSearch/Kusto get an id projection and limit. The
  selection logic is unchanged.

## Result

| Engine | Rules | Result |
| :-- | --: | :-- |
| Splunk Free (SPL) | 30 | 30 pass |
| OpenSearch (PPL) | 30 | 30 pass |
| Kusto (KQL) | 30 | 30 pass |

The run also found two real conversion bugs that the conversion-only gate could
not see:

1. **PPL escaped literal underscores.** `event_type="login\_failure"` searched
   for a backslash. The artifact was syntactically valid and matched nothing.
   The pipeline now unescapes `\_` outside `LIKE()` patterns; seven rules
   (`hmi_login_failure`, `snmp_config_change`, `process_safety_violation`, ...)
   went from zero matches to their expected event.
2. **A missing numeric field looked present.** With a default of `0`, the Kusto
   rule `isnotempty(exception_code)` matched every event without the field.
   The harness now ingests missing values as null.

## Limits

- One corpus of 1,078 events from a lab, not a production feed.
- Single-event rules only. Correlation rules aggregate over windows and are
  covered by the local stateful harness and the live Loki run; their converted
  aggregations are syntax-checked but not executed here.
- Splunk Free is a single-user 500 MB/day instance, bound to `127.0.0.1`. It is
  a parity fixture, not a sizing or throughput result.
- Splunk and OpenSearch are pinned by image digest; the vendor Kusto image has no
  stable manifest digest available, so its observed version is recorded in the
  evidence instead.
