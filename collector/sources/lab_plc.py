"""PLC integrity / diagnostics JSON -> ``ot_plc`` contract.

The lab's ``plc_integrity_check.py`` appends ``PLC_LOGIC_TAMPERED`` records when
a deployed program file no longer matches the golden manifest. This adapter
normalizes those records; the lab-side ``plc_dpi.py`` uses the same shape for
the live Loki path.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_plc"
LOGGER = logging.getLogger("collector.lab_plc")


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
    if (
        record.get("alert_type") != "PLC_LOGIC_TAMPERED"
        and record.get("event_type") != "logic_tampered"
    ):
        return None
    return event(
        PRODUCT,
        "diagnostics",
        record["timestamp"],
        event_type="logic_tampered",
        plc=record.get("plc"),
        status=record.get("status"),
        severity=record.get("severity") or "critical",
        description=record.get("description"),
    )
