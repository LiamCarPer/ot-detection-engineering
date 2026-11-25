"""Sysmon JSON -> ``ot_host`` contract.

The lab ships a synthetic Sysmon sample to Loki as ``job=sysmon_edr`` and the
repository uses it to demonstrate endpoint-to-network correlation. The adapter
keeps only the fields a detection needs and never invents a missing value.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_host"
LOGGER = logging.getLogger("collector.sysmon")


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
    details = record.get("details") or {}
    timestamp = record.get("timestamp")
    if not timestamp:
        return None
    initiated = details.get("Initiated")
    return event(
        PRODUCT,
        "sysmon",
        timestamp,
        hostname=record.get("hostname"),
        event_id=record.get("event_id"),
        image=details.get("Image"),
        user=details.get("User"),
        dst_ip=details.get("DestinationIp"),
        dst_port=_int(details.get("DestinationPort")),
        initiated=str(initiated).lower() if initiated is not None else None,
        proto=details.get("Protocol"),
    )


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
