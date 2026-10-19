# Ingest service

The product's HTTP surface: normalized telemetry ingest and AI-assisted triage.
It exists so the repository has a real AppSec/AI-Sec target whose security
properties are tested rather than asserted.

## Run

```bash
INGEST_API_KEY=... uvicorn services.ingest.app:app --host 0.0.0.0 --port 8080
```

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `INGEST_API_KEY` | `change-me` | Required `x-api-key`. Set a real secret in any deployment. |
| `INGEST_MAX_BODY_BYTES` | `65536` | Request body cap (the edge should also cap). |
| `INGEST_EVENT_RATE` | `120` | Requests per window per client on `/events`. |
| `INGEST_TRIAGE_RATE` | `30` | Requests per window per client on `/triage`. |

## Endpoints

- `GET /healthz` — public liveness.
- `POST /events` — authenticated, rate-limited, schema-validated telemetry.
- `POST /triage` — authenticated, rate-limited, AI-assisted triage of one event.

## Security properties (tested)

- API key compared with `hmac.compare_digest`; missing or wrong key is `401`.
- Sliding-window rate limiting per client; oversized bodies are `413`.
- Telemetry validated against `metadata/telemetry.schema.json`.
- Triage output validated against a strict schema, never executed, and always
  `requires_human_review: true`; a provider returning extra fields or disabling
  human review yields `502`.
- The prompt is built from an allowlisted, length-bounded, control-character-
  stripped view of the event, wrapped in an explicit `<telemetry>` data boundary;
  attacker text cannot change the stub verdict.
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
(the structured audit log is separate). The image is the target of the container
scan and the DAST baseline.
