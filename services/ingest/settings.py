"""Runtime settings, read from the environment with safe defaults for tests."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Service configuration. Every limit is explicit and bounded."""

    api_key: str = field(default_factory=lambda: os.environ.get("INGEST_API_KEY", "change-me"))
    max_body_bytes: int = field(default_factory=lambda: _env_int("INGEST_MAX_BODY_BYTES", 65_536))
    event_rate_limit: int = field(default_factory=lambda: _env_int("INGEST_EVENT_RATE", 120))
    triage_rate_limit: int = field(default_factory=lambda: _env_int("INGEST_TRIAGE_RATE", 30))
    rate_window_seconds: float = 60.0
    max_triage_chars: int = 4_000
