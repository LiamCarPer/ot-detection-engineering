# Ingest service

The product's HTTP surface: normalized telemetry ingest and AI-assisted triage.
It exists so the repository has a real AppSec/AI-Sec target whose security
properties are tested rather than asserted.

## Run

```bash
INGEST_API_KEY=... uvicorn services.ingest.app:create_app --factory --host 0.0.0.0 --port 8080
```

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `INGEST_API_KEY` | **required** | Required `x-api-key`. There is no default credential: the service refuses to start without it. |
| `INGEST_MAX_BODY_BYTES` | `65536` | Request body cap (the edge should also cap). |
| `INGEST_EVENT_RATE` | `120` | Requests per window per client on `/events`. |
| `INGEST_TRIAGE_RATE` | `30` | Requests per window per client on `/triage`. |

## Endpoints

- `GET /healthz` — public liveness.
- `POST /events` — authenticated, rate-limited, schema-validated telemetry.
- `POST /triage` — authenticated, rate-limited, AI-assisted triage of one event.

## Security properties (tested)

- API key compared with `hmac.compare_digest`; missing or wrong key is `401`.
- Sliding-window rate limiting per client; bodies larger than the cap are `413`,
  including chunked requests that carry no `Content-Length`.
- Telemetry validated against `metadata/telemetry.schema.json`.
- Triage output validated against a strict schema, never executed, and always
  `requires_human_review: true`; a provider returning extra fields or disabling
  human review yields `502`.
- The provider receives a sanitised `TriageRequest`, never the raw event. Its
  prompt is built from an allowlisted, length-bounded, control-character-stripped
  view wrapped in a per-request nonce delimiter, so a field value cannot close
  the data block.
- Accepted events and triage decisions are written to the structured audit log
  at INFO by default.
- Conservative security headers; errors return no stack traces or internals.

## AI provider

`services/ingest/ai.py` defines the `TriageProvider` protocol. The default
`StubProvider` is deterministic and offline, so CI needs no API key or network.
A real provider implements the same protocol; its output still passes the same
schema validation, the same no-tools boundary and the same human-review rule.

## Container

```bash
docker build -f services/ingest/Dockerfile -t ot-ingest .
docker run --rm -p 8080:8080 -e INGEST_API_KEY=... ot-ingest
```

Runs as uid 10001, no shell entrypoint, no debug or reload, and no access log
(the structured audit log is separate). Image scanning and the DAST baseline are
planned controls (C-025/C-026); the scripts exist, but the scan is not run on
every commit.
