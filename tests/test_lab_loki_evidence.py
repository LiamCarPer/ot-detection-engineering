"""Functional evidence: the generated ruler rule runs inside OT-Security-Lab.

CI has no lab, so the integration run is captured once (tools/lab_loki_check.py)
and committed; these tests assert the committed evidence. Regenerate with the
lab up via `python tools/lab_loki_check.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_LOKI_ALERTS

EVIDENCE_DIR = (
    Path(__file__).resolve().parents[1] / "deploy" / "evidence" / "lab-loki"
)


def _summary() -> dict:
    return json.loads((EVIDENCE_DIR / "summary.json").read_text(encoding="utf-8"))


def test_the_cross_zone_rule_is_firing_in_the_lab() -> None:
    summary = _summary()
    assert summary["rule"] in EXPECTED_LOKI_ALERTS
    assert summary["state"] == "firing"
    assert summary["health"] == "ok"


def test_lab_events_were_shipped_by_the_gateway() -> None:
    summary = _summary()
    events = json.loads((EVIDENCE_DIR / "events.json").read_text(encoding="utf-8"))
    assert summary["events"] == len(events) > 0
    for event in events:
        assert event["stream"]["job"] == "ot_firewall"
        assert "action=DROP" in event["line"]
        assert "dst_zone=control" in event["line"]
