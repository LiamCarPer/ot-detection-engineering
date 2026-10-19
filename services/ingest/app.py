"""Telemetry ingest and AI-assisted triage HTTP service.

Security properties, all tested:

- every endpoint except ``/healthz`` requires an API key compared in constant time;
- requests are rate-limited per client and the body size is capped;
- telemetry is validated against the repository's schema before it is accepted;
- triage output is schema-validated and never executed, always requires human
  review, and the prompt contains only an allowlisted, bounded view of the event;
- responses carry conservative security headers and errors do not leak internals.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator

from services.ingest.ai import StubProvider, TriageProvider, build_prompt, validate_triage
from services.ingest.auth import RateLimiter, key_matches
from services.ingest.settings import Settings

REPO_ROOT = Path(__file__).resolve().parents[2]
TELEMETRY_SCHEMA = REPO_ROOT / "metadata" / "telemetry.schema.json"
AUDIT = logging.getLogger("ingest.audit")


def _errors(validator: Draft202012Validator, payload: Any) -> list[str]:
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in validator.iter_errors(payload)
    ]


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def create_app(
    settings: Settings | None = None, provider: TriageProvider | None = None
) -> FastAPI:
    settings = settings or Settings()
    provider = provider or StubProvider()
    telemetry = Draft202012Validator(json.loads(TELEMETRY_SCHEMA.read_text(encoding="utf-8")))

    app = FastAPI(title="OT ingest", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.provider = provider
    app.state.event_limiter = RateLimiter(settings.event_rate_limit, settings.rate_window_seconds)
    app.state.triage_limiter = RateLimiter(
        settings.triage_rate_limit, settings.rate_window_seconds
    )

    async def require_key(request: Request, x_api_key: str | None = Header(default=None)) -> None:
        if not key_matches(x_api_key, request.app.state.settings.api_key):
            AUDIT.warning("auth_rejected path=%s client=%s", request.url.path, _client(request))
            raise HTTPException(status_code=401, detail="invalid api key")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None:
            try:
                size = int(length)
            except ValueError:
                return JSONResponse({"detail": "invalid content-length"}, status_code=400)
            if size > settings.max_body_bytes:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        AUDIT.error("unhandled path=%s error=%s", request.url.path, type(exc).__name__)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/events", dependencies=[Depends(require_key)])
    def ingest(request: Request, payload: dict) -> dict[str, Any]:
        if not request.app.state.event_limiter.allow(_client(request)):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        errors = _errors(telemetry, payload)
        if errors:
            AUDIT.info("event_rejected client=%s errors=%d", _client(request), len(errors))
            raise HTTPException(status_code=422, detail={"errors": errors})
        AUDIT.info(
            "event_accepted client=%s product=%s service=%s",
            _client(request),
            payload.get("product"),
            payload.get("service"),
        )
        return {"accepted": True}

    @app.post("/triage", dependencies=[Depends(require_key)])
    def triage(request: Request, payload: dict) -> dict[str, Any]:
        if not request.app.state.triage_limiter.allow(_client(request)):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        event = payload.get("event")
        if not isinstance(event, dict):
            raise HTTPException(status_code=422, detail="event must be an object")
        if len(json.dumps(event)) > settings.max_triage_chars:
            raise HTTPException(status_code=413, detail="event too large for triage")
        errors = _errors(telemetry, event)
        if errors:
            raise HTTPException(status_code=422, detail={"errors": errors})

        build_prompt(event)  # the data boundary is constructed, not concatenated
        output: dict[str, Any] = request.app.state.provider.triage(event)
        problems = validate_triage(output)
        if problems:
            AUDIT.warning("triage_rejected client=%s", _client(request))
            raise HTTPException(status_code=502, detail="triage output rejected")
        AUDIT.info(
            "triage_decided client=%s verdict=%s model=%s",
            _client(request),
            output["verdict"],
            output["model"],
        )
        return output

    return app


app = create_app()
