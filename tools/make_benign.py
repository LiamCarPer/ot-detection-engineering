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
import random
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


def _vary(event: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    """Vary values deterministically without leaving normal behaviour.

    Every choice stays inside the set the rules treat as benign: approved
    writers and readers, authorized DNP3 link addresses, writes below the
    safety band, and declared firewall conduits. The randomness exists so a
    second seed produces a genuine second sample rather than the same events
    with a shifted timestamp.
    """
    varied = dict(event)
    service = varied.get("service")
    direction = varied.get("direction")

    if service == "modbus":
        varied["unit_id"] = rng.choice([1, 2])
        if direction == "request":
            if varied.get("function_code") in (6, 16):
                # Stay well below the safety-critical parameter band.
                varied["register"] = rng.randint(100, 3_899)
                if "value" in varied:
                    varied["value"] = rng.randint(0, 1)
            else:
                varied["register"] = rng.randint(0, 999)
        if "src_ip" in varied and direction == "request":
            varied["src_ip"] = rng.choice(["172.21.0.20", "172.22.0.10"])
        if "dst_ip" in varied:
            varied["dst_ip"] = rng.choice(
                ["172.21.0.10", "172.21.0.11", "172.21.0.12"]
            )
    elif service == "dnp3":
        if direction == "request":
            varied["link_source"] = rng.choice([1, 2])
            varied["link_destination"] = rng.choice([10, 11, 12])
            if "object_group" in varied:
                varied["object_group"] = rng.randint(1, 30)
            if "control_code" in varied:
                varied["control_code"] = rng.randint(1, 4)
        else:
            varied["link_source"] = rng.choice([10, 11, 12])
            varied["link_destination"] = rng.choice([1, 2])
    elif service == "s7comm":
        if direction == "request":
            varied["src_ip"] = rng.choice(["172.21.0.20", "172.22.0.10"])
        if "pdu_reference" in varied:
            varied["pdu_reference"] = rng.randint(1, 500)
    elif service == "opcua":
        if "request_id" in varied:
            varied["request_id"] = rng.randint(1, 10_000)
        if "secure_channel_id" in varied:
            varied["secure_channel_id"] = rng.randint(1, 20)
    elif service == "iptables":
        # Keep the zone and service pair from the template, so the conduit is
        # unchanged; only the host and ephemeral port move.
        if "dst_ip" in varied:
            parts = varied["dst_ip"].split(".")
            parts[-1] = str(rng.randint(2, 60))
            varied["dst_ip"] = ".".join(parts)
        varied["src_port"] = rng.randint(1024, 65_000)
    elif service == "safety_monitor":
        if varied.get("event_type") == "process_update":
            varied["tank_level_pct"] = rng.randint(35, 79)
            if "value" in varied:
                varied["value"] = rng.randint(0, 1)
    elif service == "flow":
        varied["bytes"] = rng.randint(200, 4_200)
        varied["packets"] = rng.randint(6, 25)
        varied["duration"] = round(rng.uniform(0.005, 0.05), 3)
        varied["src_port"] = rng.randint(1024, 65_000)
    elif service == "snmp":
        varied["device"] = rng.choice(
            ["172.21.0.40", "172.21.0.41", "172.21.0.50"]
        )
        if "src_ip" in varied:
            varied["src_ip"] = varied["device"]
        if varied.get("event_type") == "heartbeat":
            varied["snmp_value"] = str(rng.randint(100_000, 999_999))
    return varied


def build(count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> list[dict[str, Any]]:
    templates = _templates()
    rng = random.Random(seed)
    # Shift the clock by the seed as well, so two seeds never share an event.
    start = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(
        seconds=(seed % 10_000) * STEP_SECONDS
    )
    events: list[dict[str, Any]] = []
    for index in range(count):
        event = _vary(templates[index % len(templates)], rng)
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
