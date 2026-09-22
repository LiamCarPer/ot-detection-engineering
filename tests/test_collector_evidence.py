"""Guard the committed collector evidence.

The collection itself needs real sensor output, so it is run once
(tools/collector_check.py) and committed; these tests assert the evidence. They
fail if a rule stops firing on real collector output or if a sample's schema
validation regresses.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_COLLECTOR_RULES

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "collector"
    / "summary.json"
)


def _summary() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_every_sample_is_covered() -> None:
    assert set(_summary()) == set(EXPECTED_COLLECTOR_RULES)


def test_observed_rules_match_expected_and_events_validate() -> None:
    for key, entry in _summary().items():
        assert entry["observed"] == sorted(EXPECTED_COLLECTOR_RULES[key]), key
        assert entry["schema_errors"] == [], key
        assert entry["events"] > 0, key


def test_benign_samples_are_silent() -> None:
    # Flow samples carry no register or function detail, so no single-event rule
    # targets them; their deviation behaviour is proven by the baseline evidence.
    for key, entry in _summary().items():
        if "benign" in key:
            assert entry["observed"] == [], key
