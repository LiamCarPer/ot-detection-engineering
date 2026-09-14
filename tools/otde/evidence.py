"""Expected native detections per capture, shared by the runner and the tests.

The mapping is the specification for the functional validation: run Suricata
over each capture and confirm exactly these signatures fire on the attack
captures and nothing fires on the benign captures.
"""

from __future__ import annotations

import json
from pathlib import Path

EXPECTED_SIDS: dict[str, set[int]] = {
    "modbus_benign": set(),
    "modbus_attack": {1000001, 1000002, 1000004},
    "dnp3_benign": set(),
    "dnp3_attack": {
        1000005,
        1000006,
        1000007,
        1000010,
        1000011,
        1000012,
        1000013,
        1000014,
        1000015,
    },
    "opcua_benign": set(),
    "opcua_attack": {1000008, 1000009},
}


def read_alert_sids(eve_path: Path) -> set[int]:
    """Return the set of signature ids in an alert-only eve.json."""
    sids: set[int] = set()
    if not eve_path.exists():
        return sids
    for line in eve_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event_type") == "alert":
            sids.add(event["alert"]["signature_id"])
    return sids
