"""Guard the committed live sensor-health evidence."""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "lab-health"
    / "summary.json"
)


def test_sensor_health_rule_is_firing_in_the_lab() -> None:
    summary = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    events = json.loads((EVIDENCE.parent / "events.json").read_text(encoding="utf-8"))
    rule = summary["rule"]
    assert rule["name"] == "Detection_Service_Stopped"
    assert rule["state"] == "firing"
    assert rule["health"] == "ok"
    assert summary["events"] == events
    assert summary["events_total"] == len(events) == 1
    assert "detection_service_down" in events[0]["line"]
    assert int(events[0]["timestamp"]) > 0
