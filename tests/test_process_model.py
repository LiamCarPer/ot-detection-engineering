"""Guard the independent mass-balance evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.process_model_check import OUT_DIR, build  # noqa: E402


def _report() -> dict:
    return json.loads((OUT_DIR / "summary.json").read_text(encoding="utf-8"))


def test_evidence_is_current() -> None:
    assert _report() == build()


def test_normal_cycle_is_quiet_and_both_attacks_are_detected() -> None:
    rows = {row["scenario"]: row for row in _report()["scenarios"]}
    assert rows["normal"]["detections"] == 0
    assert rows["unsafe"]["detections"] == 1
    assert rows["spoof"]["detections"] == 1


def test_the_mass_balance_is_not_blinded_by_a_spoofed_sensor() -> None:
    rows = {row["scenario"]: row for row in _report()["scenarios"]}
    spoof = rows["spoof"]
    assert spoof["shadow_would_detect"] is False
    assert spoof["max_divergence_pct"] >= 40
    assert spoof["first_detection"]["estimated_level_pct"] >= 90
    assert spoof["first_detection"]["reported_level_pct"] < 90
