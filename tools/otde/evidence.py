"""Expected validation results, shared by the runners and the tests.

``EXPECTED_SIDS`` is the specification for the Suricata capture validation: run
Suricata over each capture and confirm exactly these signatures fire on the
attack captures and nothing fires on the benign captures. ``EXPECTED_LOKI_ALERTS``
is the same specification for the Loki ruler smoke test.
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
    "s7comm_benign": set(),
    "s7comm_attack": {
        1000020,
        1000021,
        1000022,
        1000023,
        1000024,
        1000025,
        1000026,
        1000027,
        1000028,
    },
}


EXPECTED_LOKI_ALERTS: set[str] = {
    "Modbus_Write_From_Unauthorized_Control_Writer",
    "Modbus_Device_Identification_Scan",
    "DNP3_Control_Operation_From_Unauthorized_Master",
    "DNP3_Unsolicited_Responses_Disabled",
    "DNP3_Cold_Or_Warm_Restart_Command",
    "S7comm_Program_Download",
    "S7comm_Program_Upload",
    "S7comm_PLC_Control_Or_Stop",
    "Industrial_Protocol_Traffic_From_Enterprise_To_Control_Zone",
    "Process_Safety_Violation_From_Physics_Aware_Monitor",
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
