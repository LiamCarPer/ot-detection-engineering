"""Capture the live proof that the sensor-health rule fires in the lab.

The watchdog writes ``DETECTION_SERVICE_DOWN``; ``health_dpi.py`` ships it as
``job=ot_detection_health``; the generated ``ot_detection_service_down`` rule
fires in the lab ruler. This runner records both the event and the rule state.

Usage:
    python tools/lab_health_check.py
    LAB_LOKI_URL=http://localhost:3100 python tools/lab_health_check.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.otde.http import open_http  # noqa: E402

EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "lab-health"
SUMMARY = EVIDENCE_DIR / "summary.json"
EVENTS = EVIDENCE_DIR / "events.json"
RULE = "Detection_Service_Stopped"


def _get(url: str) -> dict:
    with open_http(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def ruler_rule(base_url: str) -> dict | None:
    payload = _get(f"{base_url}/prometheus/api/v1/rules")
    for group in payload["data"]["groups"]:
        for rule in group["rules"]:
            if rule["name"] == RULE:
                return {
                    "name": rule["name"],
                    "group": group["name"],
                    "state": rule.get("state"),
                    "health": rule.get("health"),
                }
    return None


def health_events(base_url: str, seconds: int) -> list[dict]:
    end = int(time.time())
    params = urllib.parse.urlencode(
        {
            "query": '{job="ot_detection_health"}',
            "start": f"{end - seconds}000000000",
            "end": f"{end}000000000",
            "limit": 20,
        }
    )
    payload = _get(f"{base_url}/loki/api/v1/query_range?{params}")
    events = []
    for stream in payload["data"]["result"]:
        for timestamp, line in stream["values"]:
            events.append({"timestamp": timestamp, "line": line})
    return sorted(events, key=lambda event: event["timestamp"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--loki-url",
        default=os.environ.get("LAB_LOKI_URL", "http://localhost:3100"),
    )
    parser.add_argument("--window-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    base_url = args.loki_url.rstrip("/")

    rule = ruler_rule(base_url)
    events = health_events(base_url, args.window_seconds)
    failures = []
    if rule is None:
        failures.append(f"ruler rule {RULE} is not loaded")
    elif rule["state"] != "firing" or rule["health"] != "ok":
        failures.append(f"{RULE}: state={rule['state']} health={rule['health']}")
    if not events:
        failures.append("no ot_detection_health events in the window")

    summary = {
        "captured_at": datetime.now(UTC).isoformat(),
        "loki_url": base_url,
        "lab_revision": os.environ.get("LAB_REVISION") or None,
        "rule": rule,
        "events_total": len(events),
        "events": events,
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    EVENTS.write_text(json.dumps(events, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if failures:
        print("sensor-health validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"sensor-health rule firing on {len(events)} event(s) in the lab")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
