"""Security and behaviour tests for the ingest API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from services.ingest.app import create_app
from services.ingest.settings import Settings

KEY = "test-key"
HEADERS = {"x-api-key": KEY}


def _client(**overrides) -> TestClient:
    settings = Settings(
        api_key=KEY,
        max_body_bytes=2_048,
        event_rate_limit=3,
        triage_rate_limit=3,
        rate_window_seconds=60.0,
        **overrides,
    )
    return TestClient(create_app(settings))


def _event(**overrides):
    event = {
        "timestamp": "2026-10-19T10:00:00Z",
        "product": "ot_ndr",
        "service": "modbus",
        "direction": "request",
        "function_code": 6,
        "src_ip": "172.24.0.10",
        "dst_ip": "172.21.0.10",
    }
    event.update(overrides)
    return event


def test_health_is_public() -> None:
    assert _client().get("/healthz").json() == {"status": "ok"}


def test_events_require_a_valid_api_key() -> None:
    client = _client()
    assert client.post("/events", json=_event()).status_code == 401
    assert client.post("/events", json=_event(), headers={"x-api-key": "wrong"}).status_code == 401


def test_events_accept_schema_valid_telemetry() -> None:
    response = _client().post("/events", json=_event(), headers=HEADERS)
    assert response.status_code == 200
    assert response.json() == {"accepted": True}


def test_events_reject_invalid_telemetry_without_leaking_internals() -> None:
    response = _client().post("/events", json={"product": "ot_ndr"}, headers=HEADERS)
    assert response.status_code == 422
    assert "errors" in response.json()["detail"]
    assert "Traceback" not in response.text


def test_oversized_bodies_are_rejected() -> None:
    huge = _event(src_ip="x" * 4_096)
    response = _client().post("/events", json=huge, headers=HEADERS)
    assert response.status_code == 413


def test_requests_are_rate_limited() -> None:
    client = _client()
    statuses = [
        client.post("/events", json=_event(), headers=HEADERS).status_code for _ in range(3)
    ]
    assert statuses == [200, 200, 200]
    assert client.post("/events", json=_event(), headers=HEADERS).status_code == 429


def test_responses_carry_security_headers() -> None:
    response = _client().get("/healthz")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == "default-src 'none'"


@pytest.mark.parametrize("path", ["/events", "/triage"])
def test_unknown_errors_do_not_return_a_traceback(path: str) -> None:
    response = _client().post(path, content=b"{ not json", headers=HEADERS)
    assert response.status_code in {400, 422}
    assert "Traceback" not in response.text
