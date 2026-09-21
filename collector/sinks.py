"""Output sinks for normalized telemetry events.

The default sink is JSON Lines on stdout, which needs no infrastructure. The
Loki sink ships one stream per ``(product, service)`` with the ``service`` label
the generated ruler queries select on, so the collector and the detection rules
agree on routing.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any


def to_jsonl(events: Iterable[dict[str, Any]]) -> str:
    """Serialize events as newline-delimited JSON."""
    return "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)


def _nanoseconds(timestamp: str) -> str:
    moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(UTC)
    return str(int(moment.timestamp() * 1_000_000_000))


def _logfmt(value: Any) -> str:
    text = str(value)
    if text == "" or any(character in text for character in ' "='):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def to_loki_streams(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group events into Loki push streams keyed by product and service."""
    grouped: dict[tuple[str, str], list[list[str]]] = {}
    for event in events:
        key = (event["product"], event["service"])
        line = " ".join(
            f"{name}={_logfmt(value)}"
            for name, value in event.items()
            if name not in {"product", "service"}
        )
        grouped.setdefault(key, []).append([_nanoseconds(event["timestamp"]), line])
    return [
        {"stream": {"job": product, "service": service}, "values": values}
        for (product, service), values in grouped.items()
    ]


def push_loki(streams: list[dict[str, Any]], url: str, timeout: float = 10.0) -> None:
    """Push pre-built streams to a Loki push endpoint."""
    payload = json.dumps({"streams": streams}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()
