"""Capture the proof that the generated ruler rules fire inside OT-Security-Lab.

The lab is a live Grafana/Loki stack, so this runner does not start anything: it
queries a running lab Loki for the ruler's view of every generated rule and for
the normalized protocol events the rules run on, then records both. It needs the
lab up (``lab-environment/docker-compose.yml`` plus the emulation scripts) and a
recent run of the lab's own protocol, process and cross-zone emulations, so CI
does not run it. The committed evidence is guarded by
``tests/test_lab_loki_evidence.py``.

The generated rules the lab exercises are declared in
``tools.otde.evidence.EXPECTED_LAB_RULES``. The two generated Modbus rules are
not part of that set: the lab reports Modbus as JSON alert events, not normalized
``ot_ndr`` telemetry, so the generated Modbus queries have no input there; those
rules are covered by the offline decoder proof and the Loki smoke test instead.

Usage:
    LAB_LOKI_URL=http://localhost:3100 python tools/lab_loki_check.py
    python tools/lab_loki_check.py --loki-url http://172.24.0.20:3100
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.otde.evidence import (  # noqa: E402
    EXPECTED_LAB_RULES,
    LAB_EVENT_JOBS,
    LAB_NDR_SERVICES,
)

EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "lab-loki"
SUMMARY_PATH = EVIDENCE_DIR / "summary.json"
EVENTS_PATH = EVIDENCE_DIR / "events.json"

DEFAULT_URL = "http://localhost:3100"
WINDOW_SECONDS = 900
SAMPLE_LIMIT = 5


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def ruler_rules(base_url: str) -> dict[str, dict]:
    """Return every ruler rule keyed by alert name, with state and health."""
    payload = get_json(f"{base_url}/prometheus/api/v1/rules")
    rules: dict[str, dict] = {}
    for group in payload["data"]["groups"]:
        for rule in group["rules"]:
            rules[rule["name"]] = {
                "name": rule["name"],
                "group": group["name"],
                "state": rule.get("state"),
                "health": rule.get("health"),
            }
    return rules


def wait_for_firing(base_url: str, timeout: float) -> dict[str, dict]:
    """Poll the ruler until every expected rule is firing and healthy.

    The lab evaluates the ruler every 15 s and each rule looks back one minute,
    so a rule can lag one evaluation cycle behind the traffic. Polling (the same
    approach the lab's own compliance suite uses) captures a moment when all the
    rules are firing together instead of a single racy snapshot.
    """
    deadline = time.monotonic() + timeout
    observed: dict[str, dict] = {}
    while True:
        observed = ruler_rules(base_url)
        pending = [
            name
            for name in EXPECTED_LAB_RULES
            if observed.get(name, {}).get("state") != "firing"
            or observed.get(name, {}).get("health") != "ok"
        ]
        if not pending or time.monotonic() >= deadline:
            return observed
        print(f"waiting for {len(pending)} rule(s) to fire: {', '.join(sorted(pending))}")
        time.sleep(3)


def _query(base_url: str, query: str, limit: int) -> list[dict]:
    end = int(time.time())
    params = urllib.parse.urlencode(
        {
            "query": query,
            "start": f"{end - WINDOW_SECONDS}000000000",
            "end": f"{end}000000000",
            "limit": limit,
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


def sample_events(base_url: str, limit: int) -> dict[str, list[dict]]:
    """Sample the normalized streams the generated rules consume."""
    events: dict[str, list[dict]] = {}
    for service in LAB_NDR_SERVICES:
        events[f"ot_ndr/{service}"] = _query(
            base_url, f'{{job="ot_ndr", service="{service}"}}', limit
        )
    for job in LAB_EVENT_JOBS:
        if job == "ot_ndr":
            continue
        events[job] = _query(base_url, f'{{job="{job}"}}', limit)
    return events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--loki-url",
        default=os.environ.get("LAB_LOKI_URL", DEFAULT_URL),
        help="Base URL of the lab Loki (default: $LAB_LOKI_URL or %(default)s)",
    )
    parser.add_argument(
        "--sample-limit", type=int, default=SAMPLE_LIMIT, help="Events sampled per stream"
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=90.0,
        help="Seconds to poll for all expected rules to fire (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    base_url = args.loki_url.rstrip("/")

    observed = wait_for_firing(base_url, args.wait)
    events = sample_events(base_url, args.sample_limit)

    rules = []
    missing = []
    for name, group in EXPECTED_LAB_RULES.items():
        rule = observed.get(name)
        if rule is None:
            missing.append(f"{group}: rule {name} is not loaded in the lab ruler")
            continue
        rules.append(rule)
        if rule["state"] != "firing" or rule["health"] != "ok":
            missing.append(f"{name}: state={rule['state']} health={rule['health']}")

    events_total = sum(len(samples) for samples in events.values())
    for stream in ("ot_ndr/dnp3", "ot_ndr/opcua", "ot_ndr/s7comm", "ot_firewall", "ot_process"):
        if not events.get(stream):
            missing.append(f"no events observed on the {stream} stream")

    summary = {
        "loki_url": base_url,
        "lab_revision": os.environ.get("LAB_REVISION") or None,
        "captured_at": datetime.now(UTC).isoformat(),
        "rules": sorted(rules, key=lambda rule: rule["name"]),
        "expected": dict(sorted(EXPECTED_LAB_RULES.items())),
        "streams": {stream: len(samples) for stream, samples in sorted(events.items())},
        "events_total": events_total,
    }

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    EVENTS_PATH.write_text(
        json.dumps(events, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if missing:
        print("lab ruler validation failed:")
        for problem in missing:
            print(f"  - {problem}")
        return 1
    firing = ", ".join(sorted(rule["name"] for rule in rules))
    print(f"{len(rules)} generated rules firing in the lab on {events_total} sampled events")
    print(f"  {firing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
