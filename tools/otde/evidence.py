"""Expected validation results, shared by the runners and the tests.

``EXPECTED_SIDS`` is the specification for the Suricata capture validation: run
Suricata over each capture and confirm exactly these signatures fire on the
attack captures and nothing fires on the benign captures. ``EXPECTED_LOKI_ALERTS``
is the same specification for the Loki ruler smoke test. ``EXPECTED_DECODER_RULES``
is the same specification for the decoder validation: decode the committed
example frames and confirm exactly these rules fire on the decoded events.
"""

from __future__ import annotations

import json
from pathlib import Path

EXPECTED_SIDS: dict[str, set[int]] = {
    "modbus_benign": set(),
    "modbus_attack": {9000001, 9000002, 9000004},
    "dnp3_benign": set(),
    "dnp3_attack": {
        9000005,
        9000006,
        9000007,
        9000010,
        9000011,
        9000012,
        9000013,
        9000014,
        9000015,
    },
    "opcua_benign": set(),
    "opcua_attack": {9000008, 9000009},
    "s7comm_benign": set(),
    "s7comm_attack": {
        9000020,
        9000021,
        9000022,
        9000023,
        9000024,
        9000025,
        9000026,
        9000027,
        9000028,
    },
}


EXPECTED_LOKI_ALERTS: set[str] = {
    "Modbus_Write_From_Unauthorized_Control_Writer",
    "Modbus_Device_Identification_Scan",
    "Modbus_Process_State_Read_From_Unauthorized_Source",
    "Modbus_Write_To_Safety_Critical_Parameter_Register",
    "DNP3_Control_Operation_From_Unauthorized_Master",
    "DNP3_Unsolicited_Responses_Disabled",
    "DNP3_Cold_Or_Warm_Restart_Command",
    "S7comm_Program_Download",
    "S7comm_Program_Upload",
    "S7comm_PLC_Control_Or_Stop",
    "Industrial_Protocol_Traffic_From_Enterprise_To_Control_Zone",
    "Control_Zone_Egress_To_The_Enterprise_Over_A_Standard_Port",
    "Enterprise_Host_Permitted_To_Reach_A_Control_Zone_Service",
    "Process_Safety_Violation_From_Physics_Aware_Monitor",
    "OPC_UA_Write_Request",
    "OPC_UA_Method_Call_Request",
    "OPC_UA_Address_Space_Browse",
    "Modbus_Control_Asset_Enumeration",
}


# The generated-bundle rules the live OT-Security-Lab exercises end to end,
# mapped to the Loki ruler group that evaluates them. Captured by
# tools/lab_loki_check.py after the lab's own protocol, process and cross-zone
# emulations run. The two generated Modbus rules are deliberately absent: the
# lab reports Modbus as JSON alert events, not normalized ot_ndr telemetry, so
# the generated Modbus queries have no input there. Those two rules are covered
# by the offline decoder proof and the Loki stack smoke test instead.
EXPECTED_LAB_RULES: dict[str, str] = {
    "DNP3_Control_Operation_From_Unauthorized_Master": "ot_dnp3_unauthorized_control",
    "DNP3_Unsolicited_Responses_Disabled": "ot_dnp3_unsolicited_disabled",
    "DNP3_Cold_Or_Warm_Restart_Command": "ot_dnp3_restart_command",
    "OPC_UA_Write_Request": "ot_opcua_write_request",
    "OPC_UA_Method_Call_Request": "ot_opcua_method_call",
    "OPC_UA_Address_Space_Browse": "ot_opcua_browse_request",
    "S7comm_Program_Download": "ot_s7comm_program_download",
    "S7comm_Program_Upload": "ot_s7comm_program_upload",
    "S7comm_PLC_Control_Or_Stop": "ot_s7comm_change_operating_mode",
    "Process_Safety_Violation_From_Physics_Aware_Monitor": "ot_process_safety_violation",
    "Industrial_Protocol_Traffic_From_Enterprise_To_Control_Zone": (
        "ot_firewall_cross_zone_violation"
    ),
}

# Normalized telemetry streams the lab ships, keyed by Loki job label. The
# ot_ndr job carries one stream per protocol service.
LAB_NDR_SERVICES = ("dnp3", "opcua", "s7comm")
LAB_EVENT_JOBS = ("ot_ndr", "ot_firewall", "ot_process")


# Detection event service -> Sigma rule titles the decoder examples must fire.
EXPECTED_DECODER_RULES: dict[str, set[str]] = {
    "dnp3": {
        "DNP3 Cold Or Warm Restart Command",
        "DNP3 Control Operation From Unauthorized Master",
        "DNP3 Unsolicited Responses Disabled",
    },
    "s7comm": {
        "S7comm PLC Control Or Stop",
        "S7comm Program Download",
        "S7comm Program Upload",
    },
    "opcua": {
        "OPC UA Address Space Browse",
        "OPC UA Method Call Request",
        "OPC UA Write Request",
    },
}


# Sensor sample -> Sigma rule titles the collector's normalized events must fire.
# Captured from the repository's own PCAPs; see collector/samples/PROVENANCE.md.
EXPECTED_COLLECTOR_RULES: dict[str, set[str]] = {
    "suricata/modbus_attack": {
        "Modbus Write From Unauthorized Control Writer",
        "Modbus Write To Safety Critical Parameter Register",
    },
    "suricata/modbus_benign": set(),
    "suricata/dnp3_attack": {
        "DNP3 Control Operation From Unauthorized Master",
        "DNP3 Unsolicited Responses Disabled",
        "DNP3 Cold Or Warm Restart Command",
    },
    "suricata/dnp3_benign": set(),
    # Zeek's modbus.log has no register value, so the parameter-band rule cannot
    # fire on it; its dnp3.log has no link address, so the control rule's master
    # allowlist cannot be applied (see collector/README.md).
    "zeek/modbus_attack": {"Modbus Write From Unauthorized Control Writer"},
    "zeek/modbus_benign": set(),
    "zeek/dnp3_attack": {"DNP3 Control Operation From Unauthorized Master"},
    "zeek/dnp3_benign": set(),
    # Flow records carry no register or function detail, so no Sigma rule targets
    # them yet; they feed the behaviour-baseline rules instead (see below).
    "zeek/flow_modbus_attack": set(),
    "zeek/flow_modbus_benign": set(),
    "zeek/flow_dnp3_attack": set(),
    "zeek/flow_dnp3_benign": set(),
    "netflow/flows": set(),
    "netflow/flows_violation": set(),
    "snmp/attack": {
        "Network Interface Down On An OT Device",
        "OT Device Restart",
        "OT Device Configuration Change",
    },
    "snmp/benign": set(),
}


# Sensor sample -> behaviour-baseline rule titles the sample must fire.
EXPECTED_BASELINE_RULES: dict[str, set[str]] = {
    "suricata/modbus_attack": {
        "New OT Source Asset Not In The Behaviour Baseline",
        "New OT Communication Pair",
    },
    "suricata/modbus_benign": set(),
    "suricata/dnp3_attack": {
        "New OT Source Asset Not In The Behaviour Baseline",
        "New OT Communication Pair",
        "New Protocol Function Code From An OT Asset",
    },
    "suricata/dnp3_benign": set(),
    "zeek/modbus_attack": {
        "New OT Source Asset Not In The Behaviour Baseline",
        "New OT Communication Pair",
    },
    "zeek/modbus_benign": set(),
    "zeek/dnp3_attack": {
        "New OT Source Asset Not In The Behaviour Baseline",
        "New OT Communication Pair",
        "New Protocol Function Code From An OT Asset",
    },
    "zeek/dnp3_benign": set(),
    # Flow records feed the baseline deviation rules: an attacker that appears
    # only as a flow still shows up as a new source and a new pair.
    "zeek/flow_modbus_attack": {
        "New OT Source Asset Not In The Behaviour Baseline",
        "New OT Communication Pair",
    },
    "zeek/flow_modbus_benign": set(),
    "zeek/flow_dnp3_attack": {
        "New OT Source Asset Not In The Behaviour Baseline",
        "New OT Communication Pair",
    },
    "zeek/flow_dnp3_benign": set(),
    "netflow/flows": set(),
    "netflow/flows_violation": set(),
    "snmp/attack": set(),
    "snmp/benign": set(),
}


# Sensor sample -> conduit rule titles the sample must fire.
EXPECTED_CONDUIT_RULES: dict[str, set[str]] = {
    "suricata/modbus_attack": {"Flow Through An Undeclared Zone Conduit"},
    "suricata/modbus_benign": set(),
    "suricata/dnp3_attack": {"Flow Through An Undeclared Zone Conduit"},
    "suricata/dnp3_benign": set(),
    "zeek/modbus_attack": {"Flow Through An Undeclared Zone Conduit"},
    "zeek/modbus_benign": set(),
    "zeek/dnp3_attack": {"Flow Through An Undeclared Zone Conduit"},
    "zeek/dnp3_benign": set(),
    "zeek/flow_modbus_attack": {"Flow Through An Undeclared Zone Conduit"},
    "zeek/flow_modbus_benign": set(),
    "zeek/flow_dnp3_attack": {"Flow Through An Undeclared Zone Conduit"},
    "zeek/flow_dnp3_benign": set(),
    "netflow/flows": set(),
    "netflow/flows_violation": {"Flow On A Port Outside The Declared Conduit"},
    "snmp/attack": set(),
    "snmp/benign": set(),
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
