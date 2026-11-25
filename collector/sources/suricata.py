"""Suricata ``eve.json`` -> telemetry contract.

Suricata's OT application-layer records carry both sides of a transaction in one
record (``modbus.request``/``modbus.response``), so each populated side becomes
its own contract event, matching the "one record per request or response" shape
in docs/TELEMETRY.md. Suricata parses Modbus and DNP3 framing but not S7comm or
OPC UA service bodies.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_ndr"
LOGGER = logging.getLogger("collector.suricata")


def events(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    """Yield contract events from one or more ``eve.json`` files.

    A malformed record is reported and skipped; one bad sensor line must not
    abort the whole file.
    """
    for path in paths:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                LOGGER.warning("%s: skipping malformed JSON: %s", path.name, error)
                continue
            try:
                yield from _record(record)
            except (KeyError, TypeError, ValueError) as error:
                LOGGER.warning("%s: skipping malformed record: %s", path.name, error)


def _record(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    event_type = record.get("event_type")
    if event_type == "modbus":
        yield from _modbus(record)
    elif event_type == "dnp3":
        yield _dnp3(record)


def _modbus(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    body = record.get("modbus") or {}
    origin = record.get("src_ip")
    responder = record.get("dest_ip")
    for side in ("request", "response"):
        detail = body.get(side)
        if not detail:
            continue
        write = detail.get("write") or {}
        read = detail.get("read") or {}
        value = write.get("data")
        register = write.get("address", read.get("address"))
        quantity = write.get("quantity", read.get("quantity"))
        register_end = (
            register + quantity - 1
            if isinstance(register, int) and isinstance(quantity, int) and quantity > 0
            else None
        )
        # Suricata's flow endpoints are the originator and responder, not the
        # packet direction. A response is sent by the responder, so swap them.
        src_ip, dst_ip = (
            (responder, origin) if side == "response" else (origin, responder)
        )
        yield event(
            PRODUCT,
            "modbus",
            record["timestamp"],
            direction=side,
            function_code=detail.get("function_raw"),
            unit_id=detail.get("unit_id"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            responder_ip=responder if side == "response" else None,
            register=register,
            register_end=register_end,
            quantity=quantity,
            value=value if isinstance(value, int) else None,
            exception_code=(
                detail.get("exception") if isinstance(detail.get("exception"), int) else None
            ),
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
        responder_ip=(
            record.get("dest_ip") if body.get("type") == "response" else None
        ),
    )
