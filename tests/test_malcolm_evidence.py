"""Functional evidence: the ruleset loaded and fired inside Malcolm.

CI has no Malcolm installation, so the integration run is captured once
(tools/malcolm_check.py) and committed; these tests assert the committed
evidence against the expectations in tools/otde/evidence.py. Regenerate with
`MALCOLM_DIR=/path/to/Malcolm python tools/malcolm_check.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_SIDS

EVIDENCE_DIR = (
    Path(__file__).resolve().parents[1] / "deploy" / "evidence" / "malcolm"
)


def _summary() -> dict:
    return json.loads((EVIDENCE_DIR / "summary.json").read_text(encoding="utf-8"))


def test_loads_alongside_the_default_ruleset() -> None:
    meta = _summary()["meta"]
    assert meta["rules_failed"] == 0
    assert meta["duplicate_signatures"] == 0
    assert (meta["rules_loaded"] or 0) > 1000


def test_every_capture_matches_its_expectation() -> None:
    captures = _summary()["captures"]
    assert set(captures) == set(EXPECTED_SIDS)
    for name, expected in EXPECTED_SIDS.items():
        assert set(captures[name]["expected"]) == expected
        assert set(captures[name]["observed"]) == expected


def test_alert_evidence_matches_the_summary() -> None:
    alerts = json.loads((EVIDENCE_DIR / "alerts.json").read_text(encoding="utf-8"))
    by_capture: dict[str, set[int]] = {name: set() for name in EXPECTED_SIDS}
    for alert in alerts:
        by_capture[alert["capture"]].add(alert["sid"])
    for name, expected in EXPECTED_SIDS.items():
        assert by_capture[name] == expected
