"""SNMP trap / poll JSON -> telemetry contract (``ot_snmp`` / ``snmp``).

Reads JSON exported from ``snmptrapd`` or a poller — one object or an array per
file — and normalizes it to the SNMP contract. The lab has no managed switch to
poll, so the committed sample is a labelled export in the documented shape
(``collector/samples/snmp/PROVENANCE.md``) rather than a live capture; the
adapter itself is the same shape a real exporter produces.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_snmp"


def events(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        records = data if isinstance(data, list) else [data]
        for record in records:
            yield _record(record)


def _record(record: dict[str, Any]) -> dict[str, Any]:
    device = record.get("device") or record.get("src_ip")
    return event(
        PRODUCT,
        "snmp",
        record["timestamp"],
        src_ip=device,
        device=device,
        event_type=record.get("event_type"),
        oid=record.get("oid"),
        snmp_value=_string(record.get("value")),
        severity=record.get("severity"),
    )


def _string(value: Any) -> str | None:
    return None if value is None else str(value)
