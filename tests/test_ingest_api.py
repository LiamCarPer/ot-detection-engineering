"""Security and behaviour tests for the ingest API."""

from __future__ import annotations

import json
import logging

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


def test_settings_require_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("INGEST_API_KEY", raising=False)
    with pytest.raises(ValueError, match="INGEST_API_KEY"):
        Settings()


def test_settings_reject_an_empty_api_key() -> None:
    with pytest.raises(ValueError, match="INGEST_API_KEY"):
        Settings(api_key="")


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


def test_chunked_oversized_bodies_are_rejected() -> None:
    # A chunked request has no Content-Length header, so the cap must be
    # enforced while the body is received.
    huge = json.dumps(_event(src_ip="x" * 4_096)).encode("utf-8")

    def chunks():
        for index in range(0, len(huge), 128):
            yield huge[index : index + 128]

    response = _client().post(
        "/events",
        content=chunks(),
        headers={**HEADERS, "content-type": "application/json"},
    )
    assert response.status_code == 413


def test_audit_log_records_accepted_and_decided_events(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="ingest.audit"):
        accepted = _client().post("/events", json=_event(), headers=HEADERS)
        decided = _client().post("/triage", json={"event": _event()}, headers=HEADERS)
    assert accepted.status_code == 200
    assert decided.status_code == 200
    assert "event_accepted" in caplog.text
    assert "triage_decided" in caplog.text


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
