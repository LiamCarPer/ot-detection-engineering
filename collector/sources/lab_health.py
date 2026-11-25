"""Lab detection-health events -> ``ot_detection_health`` contract.

The lab's watchdog writes ``DETECTION_SERVICE_DOWN`` records to its alert log
when a detection producer stops. This adapter normalizes those records so the
repository's sensor-health rule can be proven offline, and the lab-side
``health_dpi.py`` uses the same shape to push them to Loki.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_detection_health"
LOGGER = logging.getLogger("collector.lab_health")

# The lab event type -> the contract event type.
HEALTH_EVENTS = {
    "DETECTION_SERVICE_DOWN": "detection_service_down",
    "DETECTION_SERVICE_UP": "detection_service_up",
}


def events(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                LOGGER.warning("%s: skipping malformed line: %s", Path(path).name, error)
                continue
            converted = _record(record)
            if converted is not None:
                yield converted


def _record(record: dict[str, Any]) -> dict[str, Any] | None:
    raw = record.get("alert_type") or record.get("event_type")
    if raw is None:
        return None
    lowered = str(raw).lower()
    if lowered in {"detection_service_down", "detection_service_up"}:
        event_type = lowered
    else:
        event_type = HEALTH_EVENTS.get(str(raw).upper())
    if event_type is None:
        return None
    return event(
        PRODUCT,
        "watchdog",
        record["timestamp"],
        event_type=event_type,
        producer=record.get("service") or record.get("producer"),
        severity=record.get("severity") or "critical",
        description=record.get("description"),
    )
