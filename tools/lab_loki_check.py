"""Capture the proof that the generated ruler rules run inside OT-Security-Lab.

The lab is a live Grafana/Loki stack, so this runner does not start anything: it
queries a running lab Loki for the firewall-drop events shipped by the gateway
and for the ruler's view of the cross-zone rule, and records both. It needs the
lab up (``lab-environment/docker-compose.yml`` plus
``lab-environment/scripts/firewall_events.py``) and a recent cross-zone flow, so
CI does not run it; the committed evidence is guarded by
``tests/test_lab_loki_evidence.py``.

Usage:
    LAB_LOKI_URL=http://localhost:3100 python tools/lab_loki_check.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "lab-loki"

GROUP = "ot_firewall_cross_zone_violation"
ALERT = "Industrial_Protocol_Traffic_From_Enterprise_To_Control_Zone"
EVENT_QUERY = '{job="ot_firewall"}'
WINDOW_SECONDS = 600


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def rule_state(base_url: str) -> dict:
    payload = get_json(f"{base_url}/prometheus/api/v1/rules")
    for group in payload["data"]["groups"]:
        if group["name"] != GROUP:
            continue
        for rule in group["rules"]:
            if rule["name"] == ALERT:
                return {
                    "group": group["name"],
                    "rule": rule["name"],
                    "state": rule.get("state"),
                    "health": rule.get("health"),
                }
    raise RuntimeError(f"rule {ALERT} not found in the lab's ruler")


def recent_events(base_url: str) -> list[dict]:
    end = int(time.time())
    params = urllib.parse.urlencode(
        {
            "query": EVENT_QUERY,
            "start": f"{end - WINDOW_SECONDS}000000000",
            "end": f"{end}000000000",
        }
    )
    payload = get_json(f"{base_url}/loki/api/v1/query_range?{params}")
    events = []
    for stream in payload["data"]["result"]:
        for timestamp, line in stream["values"]:
            events.append(
                {
                    "timestamp": timestamp,
                    "stream": stream["stream"],
                    "line": line,
                }
            )
    return sorted(events, key=lambda event: event["timestamp"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loki-url", default=os.environ.get("LAB_LOKI_URL", "http://localhost:3100"))
    args = parser.parse_args(argv)
    base_url = args.loki_url.rstrip("/")

    state = rule_state(base_url)
    events = recent_events(base_url)
    streams = sorted({json.dumps(event["stream"], sort_keys=True) for event in events})

    summary = {**state, "events": len(events), "streams": streams}
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (EVIDENCE_DIR / "events.json").write_text(
        json.dumps(events, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if state["state"] != "firing" or state["health"] != "ok":
        print(f"lab ruler validation failed: rule state is {state}", file=sys.stderr)
        return 1
    if not events:
        print("lab ruler validation failed: no firewall events in the last window", file=sys.stderr)
        return 1
    print(f"lab ruler validation passed: {ALERT} is firing on {len(events)} events")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
