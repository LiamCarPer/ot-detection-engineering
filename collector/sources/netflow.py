"""NetFlow / IPFIX JSON export -> telemetry contract (``ot_flow`` / ``flow``).

Reads flow records in the shape produced by ``nfdump -o json`` or an IPFIX
collector export — one object or an array per file — so a real NetFlow exporter
feeds the same contract as Zeek's ``conn.log``. Real NetFlow needs an exporter on
the wire; the committed sample is a labelled export in the documented shape
(``collector/samples/netflow/PROVENANCE.md``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_flow"


def events(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        records = data if isinstance(data, list) else [data]
        for record in records:
            yield _record(record)


def _record(record: dict[str, Any]) -> dict[str, Any]:
    return event(
        PRODUCT,
        "flow",
        record["timestamp"],
        src_ip=record.get("src_ip") or record.get("srcaddr"),
        dst_ip=record.get("dst_ip") or record.get("dstaddr"),
        src_port=_int(record.get("src_port") or record.get("srcport")),
        dst_port=_int(record.get("dst_port") or record.get("dstport")),
        proto=_string(record.get("proto") or record.get("protocol")),
        bytes=_int(record.get("bytes") or record.get("bytes_total")),
        packets=_int(record.get("packets") or record.get("pkts")),
        duration=_float(record.get("duration")),
        flow_state=_string(record.get("flow_state")),
    )


def _int(value: Any) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _string(value: Any) -> str | None:
    return None if value is None else str(value)
