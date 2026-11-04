"""Generate a deterministic benign OT telemetry corpus.

The corpus is generated, not harvested from a plant. It models normal operation
across every product and service the rules consume — approved writers, authorized
masters, reads and sub-band writes, allowed conduits, process updates, normal
flows and SNMP heartbeats — so the false-positive rate is measured over a large,
reproducible set rather than a handful of hand-written events.

A different seed and output path produce the held-out negatives, so the corpus
used for tuning is not the corpus used for measurement.

Usage:
    python tools/make_benign.py --count 1000 --seed 20260101
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl"
DEFAULT_SEED = 20260101
DEFAULT_COUNT = 1000
STEP_SECONDS = 30


def _templates() -> list[dict[str, Any]]:
    """Normal operation, one template per recurring behaviour."""
    modbus = {"product": "ot_ndr", "service": "modbus"}
    dnp3 = {"product": "ot_ndr", "service": "dnp3"}
    s7 = {"product": "ot_ndr", "service": "s7comm"}
    opcua = {"product": "ot_ndr", "service": "opcua"}
    fw = {"product": "ot_firewall", "service": "iptables"}
    proc = {"product": "ot_process", "service": "safety_monitor"}
    flow = {"product": "ot_flow", "service": "flow"}
    snmp = {"product": "ot_snmp", "service": "snmp"}

    return [
        {
            **modbus,
            "direction": "request",
            "function_code": 3,
            "src_ip": "172.22.0.10",
            "dst_ip": "172.21.0.10",
            "unit_id": 1,
            "register": 0,
        },
        {
            **modbus,
            "direction": "request",
            "function_code": 4,
            "src_ip": "172.22.0.10",
            "dst_ip": "172.21.0.11",
            "unit_id": 1,
            "register": 100,
        },
        {
            **modbus,
            "direction": "request",
            "function_code": 6,
            "src_ip": "172.21.0.20",
            "dst_ip": "172.21.0.10",
            "unit_id": 1,
            "register": 1024,
            "value": 1,
        },
        {
            **modbus,
            "direction": "request",
            "function_code": 16,
            "src_ip": "172.21.0.20",
            "dst_ip": "172.21.0.12",
            "unit_id": 1,
            "register": 512,
            "value": 1,
        },
        {
            **modbus,
            "direction": "response",
            "function_code": 3,
            "src_ip": "172.21.0.10",
            "dst_ip": "172.22.0.10",
            "unit_id": 1,
        },
        {
            **modbus,
            "direction": "response",
            "function_code": 6,
            "src_ip": "172.21.0.10",
            "dst_ip": "172.21.0.20",
            "unit_id": 1,
        },
        {
            **dnp3,
            "direction": "request",
            "function_code": 1,
            "link_source": 1,
            "link_destination": 10,
            "object_group": 1,
        },
        {
            **dnp3,
            "direction": "request",
            "function_code": 20,
            "link_source": 2,
            "link_destination": 10,
        },
        {
            **dnp3,
            "direction": "request",
            "function_code": 5,
            "link_source": 1,
            "link_destination": 10,
            "object_group": 12,
            "control_code": 3,
        },
        {
            **dnp3,
            "direction": "response",
            "function_code": 129,
            "link_source": 10,
            "link_destination": 1,
            "iin": 0,
        },
        {
            **s7,
            "direction": "request",
            "function_code": 4,
            "src_ip": "172.21.0.20",
            "dst_ip": "172.21.0.10",
        },
        {
            **s7,
            "direction": "request",
            "function_code": 240,
            "src_ip": "172.21.0.20",
            "dst_ip": "172.21.0.10",
        },
        {
            **s7,
            "direction": "request",
            "function_code": 5,
            "src_ip": "172.21.0.20",
            "dst_ip": "172.21.0.10",
        },
        {**s7, "direction": "response", "function_code": 4, "rosctr": 3},
        {
            **opcua,
            "message_type": "MSG",
            "opcua_service": "ReadRequest",
            "service_id": 631,
            "direction": "request",
        },
        {
            **opcua,
            "message_type": "MSG",
            "opcua_service": "ReadResponse",
            "service_id": 634,
            "direction": "response",
        },
        {
            **opcua,
            "message_type": "MSG",
            "opcua_service": "ActivateSessionRequest",
            "service_id": 473,
            "direction": "request",
        },
        {
            **opcua,
            "message_type": "MSG",
            "opcua_service": "CreateSessionRequest",
            "service_id": 467,
            "direction": "request",
        },
        {**opcua, "message_type": "CLO", "direction": "request"},
        {
            **fw,
            "action": "ACCEPT",
            "proto": "TCP",
            "src_zone": "supervisory",
            "dst_zone": "control",
            "src_ip": "172.22.0.10",
            "dst_ip": "172.21.0.10",
            "dst_port": 502,
        },
        {
            **fw,
            "action": "ACCEPT",
            "proto": "TCP",
            "src_zone": "ops",
            "dst_zone": "control",
            "src_ip": "172.23.0.50",
            "dst_ip": "172.21.0.10",
            "dst_port": 502,
        },
        {
            **fw,
            "action": "ACCEPT",
            "proto": "TCP",
            "src_zone": "control",
            "dst_zone": "field",
            "src_ip": "172.21.0.20",
            "dst_ip": "172.31.0.10",
            "dst_port": 20000,
        },
        {
            **fw,
            "action": "ACCEPT",
            "proto": "TCP",
            "src_zone": "supervisory",
            "dst_zone": "ops",
            "src_ip": "172.22.0.10",
            "dst_ip": "172.23.0.10",
            "dst_port": 8086,
        },
        {
            **fw,
            "action": "ACCEPT",
            "proto": "TCP",
            "src_zone": "it",
            "dst_zone": "dmz",
            "src_ip": "172.24.0.10",
            "dst_ip": "172.25.0.2",
            "dst_port": 443,
        },
        {
            **fw,
            "action": "DROP",
            "proto": "ICMP",
            "src_zone": "it",
            "dst_zone": "control",
            "src_ip": "172.24.0.2",
            "dst_ip": "172.21.0.10",
        },
        {
            **proc,
            "event_type": "process_update",
            "asset": "plc_intake",
            "register": 100,
            "value": 0,
            "tank_level_pct": 42,
            "actor": "172.22.0.10",
            "response": "none",
        },
        {
            **proc,
            "event_type": "process_update",
            "asset": "plc_treatment",
            "register": 200,
            "value": 55,
            "tank_level_pct": 55,
            "actor": "172.22.0.10",
            "response": "none",
        },
        {
            **proc,
            "event_type": "process_safety_violation",
            "asset": "plc_intake",
            "register": 100,
            "value": 1,
            "tank_level_pct": 97,
            "actor": "172.22.0.10",
            "response": "auto_mitigated",
        },
        {
            **flow,
            "src_ip": "172.21.0.20",
            "dst_ip": "172.31.0.10",
            "src_port": 42000,
            "dst_port": 20000,
            "proto": "tcp",
            "bytes": 500,
            "packets": 10,
            "duration": 0.01,
            "flow_state": "SF",
        },
        {
            **flow,
            "src_ip": "172.22.0.10",
            "dst_ip": "172.21.0.10",
            "src_port": 41000,
            "dst_port": 502,
            "proto": "tcp",
            "bytes": 300,
            "packets": 8,
            "duration": 0.008,
            "flow_state": "SF",
        },
        {
            **flow,
            "src_ip": "172.24.0.10",
            "dst_ip": "172.25.0.2",
            "src_port": 51000,
            "dst_port": 443,
            "proto": "tcp",
            "bytes": 200,
            "packets": 6,
            "duration": 0.02,
            "flow_state": "SF",
        },
        {
            **snmp,
            "device": "172.21.0.10",
            "src_ip": "172.21.0.10",
            "event_type": "interface_up",
            "oid": "1.3.6.1.6.3.1.1.5.4",
            "snmp_value": "linkUp",
            "severity": "info",
        },
        {
            **snmp,
            "device": "172.21.0.10",
            "src_ip": "172.21.0.10",
            "event_type": "heartbeat",
            "oid": "1.3.6.1.2.1.1.3.0",
            "snmp_value": "123456",
            "severity": "info",
        },
    ]


def _vary(event: dict[str, Any], index: int) -> dict[str, Any]:
    """Vary values deterministically without leaving normal behaviour."""
    varied = dict(event)
    if "register" in varied and varied.get("direction") == "request":
        if varied.get("function_code") in (6, 16):
            # Stay well below the safety-critical parameter band.
            varied["register"] = 100 + (index * 7) % 3_800
        else:
            varied["register"] = (index * 13) % 1_000
    if "value" in varied:
        varied["value"] = index % 2
    if "tank_level_pct" in varied and varied.get("event_type") == "process_update":
        varied["tank_level_pct"] = 35 + (index * 11) % 45
    if varied.get("service") == "flow":
        varied["bytes"] = 200 + (index * 37) % 4_000
        varied["packets"] = 6 + index % 20
    return varied


def build(count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> list[dict[str, Any]]:
    templates = _templates()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    events: list[dict[str, Any]] = []
    for index in range(count):
        event = _vary(templates[index % len(templates)], index + seed)
        event["timestamp"] = (
            (start + timedelta(seconds=STEP_SECONDS * index)).isoformat().replace("+00:00", "Z")
        )
        events.append(event)
    return events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    events = build(args.count, args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(events)} benign events (seed {args.seed}) to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
