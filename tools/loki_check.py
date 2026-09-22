"""Prove the generated Loki ruler bundle fires, end to end.

Runs the self-contained stack in ``tests/loki-stack`` (Loki, Alertmanager,
Grafana and a webhook receiver), ships the generated ruler rules into Loki,
pushes benign and attack log lines, and confirms through Alertmanager that
exactly the expected alerts fire. The result is written to
``deploy/evidence/loki``.

Usage:
    python tools/loki_check.py
    python tools/loki_check.py --no-docker   # only verify committed evidence
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.otde.evidence import EXPECTED_LOKI_ALERTS  # noqa: E402

STACK_DIR = REPO_ROOT / "tests" / "loki-stack"
COMPOSE_FILE = STACK_DIR / "docker-compose.yml"
RECEIVED_DIR = STACK_DIR / "received"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "loki"
SUMMARY_PATH = EVIDENCE_DIR / "summary.json"

LOKI_READY = "http://localhost:13100/ready"
LOKI_PUSH = "http://localhost:13100/loki/api/v1/push"
ALERTMANAGER_READY = "http://localhost:19093/-/ready"
GRAFANA_HEALTH = "http://localhost:13000/api/health"
JOB_LABEL = "ot_loki_smoke"

# Each generated Loki rule, with the line(s) that must fire it and a benign line
# that must not, plus the stream-label service the rule routes on. A correlation
# needs several events — several distinct destinations for one source — so its
# attack value is a list. Keys are the alert
# names emitted by the pySigma Loki ruler backend; the service must match the
# rule's logsource service or the query selects the wrong stream and never fires.
CASES: dict[str, dict[str, object]] = {
    "Modbus_Write_From_Unauthorized_Control_Writer": {
        "service": "modbus",
        "attack": (
            "direction=request function_code=6 src_ip=172.24.0.10 "
            "dst_ip=172.21.0.10 unit_id=1 register=1024"
        ),
        "benign": (
            "direction=request function_code=3 src_ip=172.22.0.10 "
            "dst_ip=172.21.0.10 unit_id=1 register=0"
        ),
    },
    "Modbus_Device_Identification_Scan": {
        "service": "modbus",
        "attack": (
            "direction=request function_code=43 src_ip=172.24.0.10 "
            "dst_ip=172.21.0.10 unit_id=1"
        ),
        "benign": (
            "direction=request function_code=4 src_ip=172.22.0.10 "
            "dst_ip=172.21.0.10 unit_id=1"
        ),
    },
    "Modbus_Process_State_Read_From_Unauthorized_Source": {
        "service": "modbus",
        "attack": (
            "direction=request function_code=3 src_ip=172.24.0.10 "
            "dst_ip=172.21.0.10 unit_id=1 register=0"
        ),
        "benign": (
            "direction=request function_code=3 src_ip=172.22.0.10 "
            "dst_ip=172.21.0.10 unit_id=1 register=0"
        ),
    },
    "Modbus_Control_Asset_Enumeration": {
        # One source reading three distinct control assets inside the window. The
        # referenced rule matches each line on its own; the correlation is what
        # counts the distinct destinations.
        "service": "modbus",
        "attack": [
            f"direction=request function_code=3 src_ip=172.24.0.10 "
            f"dst_ip=172.21.0.{last} unit_id=1 register=0"
            for last in (10, 11, 12)
        ],
        # Three distinct assets again, but from the allowlisted reader the
        # referenced rule filters out, so the correlation has nothing to count.
        #
        # The idle case cannot be "one source polling one asset", because any
        # event that feeds this correlation also matches the rule it references,
        # and the benign phase requires no alerts at all. That distinct-count
        # negative is the offline fixture's job; this one proves the correlation
        # inherits the referenced rule's filter.
        "benign": [
            f"direction=request function_code=3 src_ip=172.22.0.10 "
            f"dst_ip=172.21.0.{last} unit_id=1 register=0"
            for last in (10, 11, 12)
        ],
    },
    "Modbus_Write_To_Safety_Critical_Parameter_Register": {
        "service": "modbus",
        "attack": (
            "direction=request function_code=6 src_ip=172.21.0.20 "
            "dst_ip=172.21.0.10 unit_id=1 register=4001 value=1"
        ),
        "benign": (
            "direction=request function_code=6 src_ip=172.21.0.20 "
            "dst_ip=172.21.0.10 unit_id=1 register=1024 value=50"
        ),
    },
    "DNP3_Control_Operation_From_Unauthorized_Master": {
        "service": "dnp3",
        "attack": "direction=request function_code=5 link_source=7 link_destination=1",
        "benign": "direction=request function_code=5 link_source=1 link_destination=1",
    },
    "DNP3_Unsolicited_Responses_Disabled": {
        "service": "dnp3",
        "attack": "direction=request function_code=21 link_source=7 link_destination=1",
        "benign": "direction=request function_code=20 link_source=1 link_destination=1",
    },
    "DNP3_Cold_Or_Warm_Restart_Command": {
        "service": "dnp3",
        "attack": "direction=request function_code=13 link_source=7 link_destination=1",
        "benign": "direction=request function_code=1 link_source=1 link_destination=1",
    },
    "S7comm_Program_Download": {
        "service": "s7comm",
        "attack": "direction=request function_code=26",
        "benign": "direction=request function_code=4",
    },
    "S7comm_Program_Upload": {
        "service": "s7comm",
        "attack": "direction=request function_code=29",
        "benign": "direction=request function_code=4",
    },
    "S7comm_PLC_Control_Or_Stop": {
        "service": "s7comm",
        "attack": "direction=request function_code=41",
        "benign": "direction=request function_code=4",
    },
    "Industrial_Protocol_Traffic_From_Enterprise_To_Control_Zone": {
        "service": "iptables",
        "attack": (
            "action=DROP proto=TCP src_zone=it dst_zone=control "
            "src_ip=172.24.0.10 dst_ip=172.21.0.10 dst_port=502"
        ),
        "benign": (
            "action=DROP proto=TCP src_zone=ops dst_zone=control "
            "src_ip=172.23.0.50 dst_ip=172.21.0.10 dst_port=502"
        ),
    },
    "Control_Zone_Egress_To_The_Enterprise_Over_A_Standard_Port": {
        "service": "iptables",
        "attack": (
            "action=ACCEPT proto=TCP src_zone=control dst_zone=it "
            "src_ip=172.21.0.10 dst_ip=172.24.0.10 dst_port=443"
        ),
        "benign": (
            "action=ACCEPT proto=TCP src_zone=control dst_zone=dmz "
            "src_ip=172.21.0.10 dst_ip=172.24.0.2 dst_port=8086"
        ),
    },
    "Enterprise_Host_Permitted_To_Reach_A_Control_Zone_Service": {
        "service": "iptables",
        "attack": (
            "action=ACCEPT proto=TCP src_zone=it dst_zone=control "
            "src_ip=172.24.0.10 dst_ip=172.21.0.10 dst_port=502"
        ),
        "benign": (
            "action=ACCEPT proto=TCP src_zone=ops dst_zone=control "
            "src_ip=172.23.0.50 dst_ip=172.21.0.10 dst_port=502"
        ),
    },
    "Process_Safety_Violation_From_Physics_Aware_Monitor": {
        "service": "safety_monitor",
        "attack": "event_type=process_safety_violation response=none",
        "benign": "event_type=process_update response=none",
    },
    "OPC_UA_Write_Request": {
        "service": "opcua",
        "attack": "message_type=MSG opcua_service=WriteRequest direction=request",
        "benign": "message_type=MSG opcua_service=ReadRequest direction=request",
    },
    "OPC_UA_Method_Call_Request": {
        "service": "opcua",
        "attack": "message_type=MSG opcua_service=CallRequest direction=request",
        "benign": "message_type=MSG opcua_service=ReadRequest direction=request",
    },
    "OPC_UA_Address_Space_Browse": {
        "service": "opcua",
        "attack": "message_type=MSG opcua_service=BrowseRequest direction=request",
        "benign": "message_type=MSG opcua_service=ReadRequest direction=request",
    },
}

assert set(CASES) == EXPECTED_LOKI_ALERTS, "smoke-test cases drift from evidence.py"


def _payloads() -> list[dict]:
    payloads: list[dict] = []
    for path in sorted(RECEIVED_DIR.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                payloads.append(json.loads(line))
    return payloads


def _alertnames(payloads: list[dict]) -> set[str]:
    names = set()
    for payload in payloads:
        for alert in payload.get("alerts", []):
            name = alert.get("labels", {}).get("alertname")
            if name:
                names.add(name)
    return names


def _clear_received() -> None:
    # Create the directory before compose starts so it is owned by the host
    # user, not root, and the received files can be cleaned up afterwards.
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    for path in RECEIVED_DIR.glob("*"):
        path.unlink()


def _wait_for(url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(1)
    raise TimeoutError(f"timed out waiting for {url}")


def _push(entries: list[tuple[str, str]]) -> None:
    base = time.time_ns()
    streams: dict[str, list[list[str]]] = {}
    for index, (service, line) in enumerate(entries):
        streams.setdefault(service, []).append([str(base + index), line])
    payload = json.dumps(
        {
            "streams": [
                {"stream": {"job": JOB_LABEL, "service": service}, "values": values}
                for service, values in sorted(streams.items())
            ]
        }
    )
    request = urllib.request.Request(
        LOKI_PUSH,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def _lines(value: object) -> list[str]:
    """Return a case's log line(s) as a list, so a case may supply several."""
    if isinstance(value, str):
        return [value]
    return list(value)  # type: ignore[arg-type]


def _compose(*args: str) -> None:
    subprocess.run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], check=True)


def run() -> int:
    _clear_received()
    observed: set[str] = set()
    false_positives: list[str] = []
    try:
        _compose("up", "-d")
        _wait_for(LOKI_READY, 60)
        _wait_for(ALERTMANAGER_READY, 60)
        _wait_for(GRAFANA_HEALTH, 60)

        _clear_received()
        _push([(case["service"], line) for case in CASES.values()
               for line in _lines(case["benign"])])
        time.sleep(20)
        false_positives = sorted(_alertnames(_payloads()) & EXPECTED_LOKI_ALERTS)

        _clear_received()
        _push([(case["service"], line) for case in CASES.values()
               for line in _lines(case["attack"])])
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            observed = _alertnames(_payloads())
            if EXPECTED_LOKI_ALERTS <= observed:
                break
            time.sleep(2)

        alerts: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for payload in _payloads():
            for alert in payload.get("alerts", []):
                key = (alert.get("labels", {}).get("alertname"), alert.get("status"))
                if key[0] and key not in seen:
                    seen.add(key)
                    alerts.append({"alertname": key[0], "status": key[1]})
    finally:
        _compose("down", "-v")

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "alerts.json").write_text(
        json.dumps(sorted(alerts, key=lambda item: item["alertname"]), indent=2) + "\n",
        encoding="utf-8",
    )
    SUMMARY_PATH.write_text(
        json.dumps(
            {
                "expected": sorted(EXPECTED_LOKI_ALERTS),
                "observed": sorted(observed),
                "benign_false_positives": false_positives,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if false_positives:
        print(f"benign events fired alerts: {false_positives}")
        return 1
    missing = sorted(EXPECTED_LOKI_ALERTS - observed)
    if missing:
        print(f"expected alerts did not fire: {missing}")
        return 1
    print(f"all {len(EXPECTED_LOKI_ALERTS)} Loki ruler alerts fired")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-docker", action="store_true", help="Only verify committed evidence")
    args = parser.parse_args(argv)

    if not args.no_docker:
        return run()

    summary = json.loads(SUMMARY_PATH.read_text(encoding="utf-8"))
    if summary["observed"] != summary["expected"] or summary["benign_false_positives"]:
        print(f"committed Loki evidence is stale: {summary}")
        return 1
    print("committed Loki evidence matches the expected alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
