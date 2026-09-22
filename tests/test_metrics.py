"""Tests for the detection metrics layer."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "metrics"))
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from compute import baseline_metrics, fixture_metrics, load_baseline, render_markdown  # noqa: E402
from generate_coverage import build_report  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402

from tools.otde.rules import single_event_rule_paths  # noqa: E402


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
    events = load_baseline(REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl")
    result = baseline_metrics(events)
    assert result["events_total"] == len(events)
    assert result["false_positive_events"] == 0, result["details"]


def test_baseline_covers_every_rule_logsource() -> None:
    # A rule whose logsource has no benign event is never actually tested for
    # false positives, so the baseline must span every telemetry domain a rule
    # consumes. Correlation rules are excluded: they have no logsource and are
    # evaluated over a sequence, which the single-event baseline cannot express.
    events = load_baseline(REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl")
    covered = {(event.get("product"), event.get("service")) for event in events}
    for rule_path in single_event_rule_paths():
        rule = SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))
        key = (rule.logsource.product, rule.logsource.service)
        assert key in covered, f"no benign baseline event for {key} ({rule_path.name})"


def test_report_renders() -> None:
    per_rule, aggregate = fixture_metrics()
    report = render_markdown(
        {
            "coverage": build_report()["summary"],
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
