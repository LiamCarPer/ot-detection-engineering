"""Functional evidence: the Loki ruler bundle fired on the smoke-test events.

CI cannot run the Loki stack, so the run is captured once (tools/loki_check.py)
and committed; these tests assert the committed evidence against the
expectations in tools/otde/evidence.py. Regenerate with `make loki-check`.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_LOKI_ALERTS

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "deploy" / "evidence" / "loki"


def _summary() -> dict:
    return json.loads((EVIDENCE_DIR / "summary.json").read_text(encoding="utf-8"))


def test_all_expected_alerts_fired() -> None:
    summary = _summary()
    assert set(summary["expected"]) == EXPECTED_LOKI_ALERTS
    assert set(summary["observed"]) == EXPECTED_LOKI_ALERTS


def test_no_benign_events_fired() -> None:
    assert _summary()["benign_false_positives"] == []


def test_alert_evidence_matches_the_summary() -> None:
    alerts = json.loads((EVIDENCE_DIR / "alerts.json").read_text(encoding="utf-8"))
    firing = {alert["alertname"] for alert in alerts if alert["status"] == "firing"}
    assert firing == EXPECTED_LOKI_ALERTS
