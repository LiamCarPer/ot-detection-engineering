"""The normalized telemetry contract: timestamp handling, event building, schema.

A contract event carries the routing fields (``product``, ``service``, an ISO
8601 UTC ``timestamp``) plus whichever protocol fields the source can populate.
Fields a sensor cannot see are omitted, never guessed, so a downstream rule can
tell "the master was authorized" from "the master was not visible".
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "metadata" / "telemetry.schema.json"

_OFFSET_RE = re.compile(r"([+-]\d{2})(\d{2})$")


def _parse(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    match = _OFFSET_RE.search(text)
    if match:
        text = f"{text[: match.start()]}{match.group(1)}:{match.group(2)}"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def normalize_timestamp(value: str | float | int) -> str:
    """Return an ISO 8601 UTC timestamp with a ``Z`` suffix.

    Accepts an epoch float (Zeek) or an offset string (Suricata). Naive values
    are read as UTC, matching the rest of the repository.
    """
    if isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(float(value), tz=UTC)
    else:
        moment = _parse(str(value))
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def event(
    product: str, service: str, timestamp: str | float | int, **fields: Any
) -> dict[str, Any]:
    """Build a contract event, dropping fields the source did not provide."""
    event: dict[str, Any] = {
        "product": product,
        "service": service,
        "timestamp": normalize_timestamp(timestamp),
    }
    for name, value in fields.items():
        if value is not None:
            event[name] = value
    return event


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def schema_errors(event: dict[str, Any]) -> list[str]:
    """Return the schema violations in ``event`` (empty when it is valid)."""
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(load_schema())
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in validator.iter_errors(event)
    ]
