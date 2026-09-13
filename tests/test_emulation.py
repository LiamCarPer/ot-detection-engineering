"""Tests for the adversary emulation plan and evaluation logic."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "purple" / "runner"))

from run_emulation import evaluate, load_plan, render_markdown, validate_plan  # noqa: E402

OBSERVATIONS = {
    "enterprise-pivot-and-write": {
        "started_at": "2026-09-13T02:14:00+00:00",
        "finished_at": "2026-09-13T02:14:30+00:00",
        "alerts": [
            {"timestamp": "2026-09-13T02:14:07Z", "alert_type": "UNAUTHORIZED_MODBUS_WRITE"},
            {"timestamp": "2026-09-13T02:14:05Z", "alert_type": "CROSS_ZONE_VIOLATION"},
            {"timestamp": "2026-09-13T02:14:20Z", "alert_type": "OT_BRUTE_FORCE_SCAN"},
        ],
    },
    "physics-aware-safety-violation": {
        "started_at": "2026-09-13T02:15:00+00:00",
        "finished_at": "2026-09-13T02:15:30+00:00",
        "alerts": [
            {"timestamp": "2026-09-13T02:15:02Z", "alert_type": "PROCESS_SAFETY_VIOLATION"},
        ],
    },
}


def test_plan_is_valid() -> None:
    assert validate_plan(load_plan()) == []


def test_evaluate_detects_all_expectations() -> None:
    results = evaluate(load_plan(), OBSERVATIONS)
    summary = results["summary"]
    assert summary["expectations_total"] == 4
    assert summary["expectations_detected"] == 4
    assert summary["detection_rate_pct"] == 100.0
    assert summary["mean_mttd_seconds"] == 8.5
    assert summary["max_mttd_seconds"] == 20.0


def test_missing_signal_is_a_miss() -> None:
    observations = copy.deepcopy(OBSERVATIONS)
    observations["enterprise-pivot-and-write"]["alerts"] = [
        alert
        for alert in observations["enterprise-pivot-and-write"]["alerts"]
        if alert["alert_type"] != "OT_BRUTE_FORCE_SCAN"
    ]
    summary = evaluate(load_plan(), observations)["summary"]
    assert summary["expectations_detected"] == 3
    assert summary["detection_rate_pct"] == 75.0


def test_alert_outside_window_is_ignored() -> None:
    observations = copy.deepcopy(OBSERVATIONS)
    observations["physics-aware-safety-violation"]["alerts"] = [
        {"timestamp": "2026-09-13T02:14:59Z", "alert_type": "PROCESS_SAFETY_VIOLATION"}
    ]
    summary = evaluate(load_plan(), observations)["summary"]
    assert summary["expectations_detected"] == 3


def test_plan_with_wrong_technique_mapping_is_rejected() -> None:
    plan = copy.deepcopy(load_plan())
    plan["steps"][1]["expectations"][0]["technique"] = "T0886"
    problems = validate_plan(plan)
    assert any("does not detect" in problem for problem in problems)


def test_render_markdown_contains_summary() -> None:
    report = render_markdown(evaluate(load_plan(), OBSERVATIONS))
    assert "Adversary Emulation Results" in report
    assert "100.0%" in report
