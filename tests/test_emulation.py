"""Tests for the adversary emulation plan and evaluation logic."""

from __future__ import annotations

import copy
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "purple" / "runner"))

from run_emulation import (  # noqa: E402
    evaluate,
    load_plan,
    main,
    parse_timestamp,
    render_markdown,
    run_plan,
    validate_plan,
)

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


def test_naive_timestamp_is_treated_as_utc() -> None:
    # The lab detectors run in UTC containers, so naive timestamps are UTC.
    parsed = parse_timestamp("2026-09-13T02:14:00.500000")
    assert parsed == datetime(2026, 9, 13, 2, 14, 0, 500000, tzinfo=UTC)


def test_offset_timestamp_is_preserved() -> None:
    assert parse_timestamp("2026-09-13T02:14:00Z") == datetime(2026, 9, 13, 2, 14, tzinfo=UTC)


def test_observations_are_persisted(tmp_path: Path) -> None:
    source = tmp_path / "observations.json"
    source.write_text(json.dumps(OBSERVATIONS))
    out = tmp_path / "out"
    assert main(["--observations", str(source), "--out", str(out)]) == 0
    assert (out / "observations.json").exists()
    assert (out / "emulation_results.json").exists()
    assert (out / "emulation_report.md").exists()


def test_run_plan_records_execution_windows(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    alerts.write_text(
        json.dumps(
            [{"timestamp": "2026-09-13T02:14:07Z", "alert_type": "UNAUTHORIZED_MODBUS_WRITE"}]
        )
    )
    plan = {
        "name": "unit",
        "steps": [
            {
                "id": "s1",
                "name": "step",
                "description": "d",
                "execute": {"command": "run-something"},
                "expectations": [
                    {
                        "signal": "UNAUTHORIZED_MODBUS_WRITE",
                        "technique": "T1692.001",
                        "rule": "rules/sigma/ot/ot_modbus_unauthorized_write.yml",
                    }
                ],
            }
        ],
    }
    moments = iter(
        [
            datetime(2026, 9, 13, 2, 14, 0, tzinfo=UTC),
            datetime(2026, 9, 13, 2, 14, 30, tzinfo=UTC),
        ]
    )
    executed: list[str] = []
    observations = run_plan(
        plan,
        alerts,
        settle_seconds=0,
        runner=executed.append,
        clock=lambda: next(moments),
        sleeper=lambda _: None,
    )
    assert executed == ["run-something"]
    assert observations["s1"]["started_at"].startswith("2026-09-13T02:14:00")
    assert evaluate(plan, observations)["summary"]["expectations_detected"] == 1
