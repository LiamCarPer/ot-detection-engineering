"""nginx JSON access log -> ``ot_auth`` contract.

The HMI itself does not log authentication outcomes; the DMZ reverse proxy does.
A failed Scada-LTS login is a POST to ``login.htm`` that redirects back to the
login page. The adapter turns those requests into ``ot_auth/hmi`` events so the
repository can detect a credential burst independently of the lab's own monitor.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from collector.contract import event, normalize_timestamp

PRODUCT = "ot_auth"
LOGGER = logging.getLogger("collector.nginx")


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


def _timestamp(value: str) -> str:
    moment = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    return normalize_timestamp(moment.isoformat())


def _record(record: dict[str, Any]) -> dict[str, Any] | None:
    request = str(record.get("request", ""))
    location = str(record.get("location", ""))
    if "login.htm" not in request:
        return None
    if request.startswith("POST ") and "login.htm" in location:
        event_type = "login_failure"
    elif request.startswith("POST ") and location:
        event_type = "login_success"
    else:
        return None
    forwarded = record.get("x_forwarded_for")
    source = str(forwarded).split(",")[0].strip() if forwarded else record.get("remote_addr")
    return event(
        PRODUCT,
        "hmi",
        _timestamp(str(record["time"])),
        event_type=event_type,
        src_ip=source,
        request=request,
        status=record.get("status"),
        location=location,
    )
