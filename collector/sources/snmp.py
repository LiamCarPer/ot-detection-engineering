"""SNMP trap / poll JSON -> telemetry contract (``ot_snmp`` / ``snmp``).

Reads JSON exported from ``snmptrapd`` or a poller — one object or an array per
file — and normalizes it to the SNMP contract. The lab has no managed switch to
poll, so the committed sample is a labelled export in the documented shape
(``collector/samples/snmp/PROVENANCE.md``) rather than a live capture; the
adapter itself is the same shape a real exporter produces.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from collector.contract import event

PRODUCT = "ot_snmp"
LOGGER = logging.getLogger("collector.snmp")

# Trap OIDs that carry a device event. The OID is the authority: an exporter
# label is not trusted, because a mislabelled or attacker-supplied `event_type`
# would otherwise be routed as a detection.
OID_EVENTS: dict[str, str] = {
    "1.3.6.1.6.3.1.1.5.1": "device_restart",  # coldStart
    "1.3.6.1.6.3.1.1.5.2": "device_restart",  # warmStart
    "1.3.6.1.6.3.1.1.5.3": "interface_down",  # linkDown
    "1.3.6.1.6.3.1.1.5.4": "interface_up",  # linkUp
    "1.3.6.1.2.1.1.3.0": "heartbeat",  # sysUpTime
    "1.3.6.1.4.1.9.9.43.2.0.1": "config_change",  # Cisco config change
}


def events(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
            records = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # A live poller appends one object per line; the committed sample is
            # a JSON array. Accept both shapes.
            try:
                records = [
                    json.loads(line)
                    for line in text.splitlines()
                    if line.strip()
                ]
            except json.JSONDecodeError as error:
                LOGGER.warning(
                    "%s: skipping malformed JSON: %s", Path(path).name, error
                )
                continue
        for record in records:
            try:
                yield _record(record)
            except (KeyError, TypeError, ValueError) as error:
                LOGGER.warning("%s: skipping malformed record: %s", Path(path).name, error)


def _record(record: dict[str, Any]) -> dict[str, Any]:
    device = record.get("device") or record.get("src_ip")
    oid = record.get("oid")
    return event(
        PRODUCT,
        "snmp",
        record["timestamp"],
        src_ip=device,
        device=device,
        event_type=OID_EVENTS.get(str(oid)) if oid is not None else None,
        oid=oid,
        snmp_value=_string(record.get("value")),
        severity=record.get("severity"),
    )


def _string(value: Any) -> str | None:
    return None if value is None else str(value)
