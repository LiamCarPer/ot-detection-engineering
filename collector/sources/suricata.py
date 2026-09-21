"""Suricata ``eve.json`` -> telemetry contract.

Suricata's OT application-layer records carry both sides of a transaction in one
record (``modbus.request``/``modbus.response``), so each populated side becomes
its own contract event, matching the "one record per request or response" shape
in docs/TELEMETRY.md. Suricata parses Modbus and DNP3 framing but not S7comm or
OPC UA service bodies.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_ndr"


def events(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    """Yield contract events from one or more ``eve.json`` files."""
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            yield from _record(json.loads(line))


def _record(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    event_type = record.get("event_type")
    if event_type == "modbus":
        yield from _modbus(record)
    elif event_type == "dnp3":
        yield _dnp3(record)


def _modbus(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    body = record.get("modbus") or {}
    for side in ("request", "response"):
        detail = body.get(side)
        if not detail:
            continue
        write = detail.get("write") or {}
        read = detail.get("read") or {}
        value = write.get("data")
        yield event(
            PRODUCT,
            "modbus",
            record["timestamp"],
            direction=side,
            function_code=detail.get("function_raw"),
            unit_id=detail.get("unit_id"),
            src_ip=record.get("src_ip"),
            dst_ip=record.get("dest_ip"),
            register=write.get("address", read.get("address")),
            value=value if isinstance(value, int) else None,
        )


def _dnp3(record: dict[str, Any]) -> dict[str, Any]:
    body = record.get("dnp3") or {}
    control = body.get("control") or {}
    application = body.get("application") or {}
    app_control = application.get("control") or {}
    objects = application.get("objects") or []
    first = objects[0] if objects else {}
    return event(
        PRODUCT,
        "dnp3",
        record["timestamp"],
        direction=body.get("type"),
        function_code=application.get("function_code"),
        link_source=body.get("src"),
        link_destination=body.get("dst"),
        link_function=control.get("function_code"),
        object_group=first.get("group"),
        object_variation=first.get("variation"),
        object_count=first.get("count"),
        application_sequence=app_control.get("sequence"),
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dest_ip"),
    )
