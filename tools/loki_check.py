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

# Each generated Loki rule, with a line that must fire it and a benign line that
# must not. Keys are the alert names emitted by the pySigma Loki ruler backend.
CASES: dict[str, dict[str, str]] = {
    "Modbus_Write_From_Unauthorized_Control_Writer": {
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
        "attack": (
            "direction=request function_code=43 src_ip=172.24.0.10 "
            "dst_ip=172.21.0.10 unit_id=1"
        ),
        "benign": (
            "direction=request function_code=4 src_ip=172.22.0.10 "
            "dst_ip=172.21.0.10 unit_id=1"
        ),
    },
    "DNP3_Control_Operation_From_Unauthorized_Master": {
        "attack": "direction=request function_code=5 link_source=7 link_destination=1",
        "benign": "direction=request function_code=5 link_source=1 link_destination=1",
    },
    "DNP3_Unsolicited_Responses_Disabled": {
        "attack": "direction=request function_code=21 link_source=7 link_destination=1",
        "benign": "direction=request function_code=20 link_source=1 link_destination=1",
    },
    "DNP3_Cold_Or_Warm_Restart_Command": {
        "attack": "direction=request function_code=13 link_source=7 link_destination=1",
        "benign": "direction=request function_code=1 link_source=1 link_destination=1",
    },
    "S7comm_Program_Download": {
        "attack": "direction=request function_code=26",
        "benign": "direction=request function_code=4",
    },
    "S7comm_Program_Upload": {
        "attack": "direction=request function_code=29",
        "benign": "direction=request function_code=4",
    },
    "S7comm_PLC_Control_Or_Stop": {
        "attack": "direction=request function_code=41",
        "benign": "direction=request function_code=4",
    },
    "Industrial_Protocol_Traffic_From_Enterprise_To_Control_Zone": {
        "attack": (
            "action=DROP proto=TCP src_zone=it dst_zone=control "
            "src_ip=172.24.0.10 dst_ip=172.21.0.10 dst_port=502"
        ),
        "benign": (
            "action=DROP proto=TCP src_zone=ops dst_zone=control "
            "src_ip=172.23.0.50 dst_ip=172.21.0.10 dst_port=502"
        ),
    },
    "Process_Safety_Violation_From_Physics_Aware_Monitor": {
        "attack": "event_type=process_safety_violation response=none",
        "benign": "event_type=process_update response=none",
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


def _push(lines: list[str]) -> None:
    base = time.time_ns()
    values = [[str(base + index), line] for index, line in enumerate(lines)]
    payload = json.dumps({"streams": [{"stream": {"job": JOB_LABEL}, "values": values}]})
    request = urllib.request.Request(
        LOKI_PUSH,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


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
        _push([case["benign"] for case in CASES.values()])
        time.sleep(20)
        false_positives = sorted(_alertnames(_payloads()) & EXPECTED_LOKI_ALERTS)

        _clear_received()
        _push([case["attack"] for case in CASES.values()])
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
