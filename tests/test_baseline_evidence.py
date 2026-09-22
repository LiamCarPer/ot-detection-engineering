"""Guard the committed behaviour-baseline evidence.

The baseline proof needs the committed telemetry samples, so it is run once
(tools/baseline_check.py) and committed; these tests assert the evidence. They
fail if the committed baseline goes stale or a rule stops firing on an attack
sample.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_BASELINE_RULES

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "baseline"
    / "summary.json"
)


def _evidence() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_the_committed_baseline_is_current() -> None:
    assert _evidence()["baseline_current"] is True


def test_every_sample_is_covered_and_matches_expected() -> None:
    samples = _evidence()["samples"]
    assert set(samples) == set(EXPECTED_BASELINE_RULES)
    for key, entry in samples.items():
        assert entry["observed"] == sorted(EXPECTED_BASELINE_RULES[key]), key
        assert entry["events"] > 0, key


def test_benign_samples_are_silent() -> None:
    for key, entry in _evidence()["samples"].items():
        if "benign" in key:
            assert entry["observed"] == [], key
