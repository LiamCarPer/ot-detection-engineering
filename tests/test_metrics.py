"""Tests for the detection metrics layer."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "metrics"))
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from compute import baseline_metrics, fixture_metrics, load_baseline, render_markdown  # noqa: E402

from tools.otde.rules import REPO_ROOT as _REPO_ROOT  # noqa: E402


def test_fixture_aggregate_matches_per_rule() -> None:
    per_rule, aggregate = fixture_metrics()
    assert per_rule
    for key in ("tp", "fn", "fp", "tn"):
        assert aggregate[key] == sum(rule[key] for rule in per_rule)


def test_fixture_metrics_are_consistent() -> None:
    _, aggregate = fixture_metrics()
    expected_precision = aggregate["tp"] / (aggregate["tp"] + aggregate["fp"])
    expected_recall = aggregate["tp"] / (aggregate["tp"] + aggregate["fn"])
    assert aggregate["precision"] == round(expected_precision, 4)
    assert aggregate["recall"] == round(expected_recall, 4)


def test_no_rule_fires_on_the_benign_baseline() -> None:
    events = load_baseline(_REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl")
    result = baseline_metrics(events)
    assert result["events_total"] == len(events)
    assert result["false_positive_events"] == 0, result["details"]


def test_report_renders() -> None:
    per_rule, aggregate = fixture_metrics()
    report = render_markdown(
        {
            "coverage": {"techniques_covered": 5, "techniques_total": 97, "coverage_pct": 5.2},
            "rule_validation": {"per_rule": per_rule, "aggregate": aggregate},
            "baseline": {
                "false_positive_events": 0,
                "events_total": 12,
                "false_positive_rate": 0.0,
            },
            "emulation": None,
        }
    )
    assert "Detection Metrics" in report
    assert "not run" in report
