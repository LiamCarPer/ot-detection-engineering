"""Tests for the adversary emulation plan and evaluation logic."""

from __future__ import annotations

import copy
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "purple" / "runner"))

from run_emulation import (  # noqa: E402
    EmulationDataError,
    evaluate,
    load_plan,
    main,
    parse_timestamp,
    render_markdown,
    run_plan,
    validate_plan,
)

OLD_PLAN = REPO_ROOT / "purple" / "emulation" / "emulation-plan-2026-09-13.yaml"
NEW_OBSERVATIONS = REPO_ROOT / "purple" / "emulation" / "lab-observations.json"

OBSERVATIONS = {
    "enterprise-pivot-and-write": {
        "started_at": "2026-09-13T02:14:00+00:00",
        "finished_at": "2026-09-13T02:14:30+00:00",
        "alerts": [
            {
                "timestamp": "2026-09-13T02:14:07Z",
                "alert_type": "UNAUTHORIZED_MODBUS_WRITE",
                "mitre_id": "T0831",
            },
            {
                "timestamp": "2026-09-13T02:14:05Z",
                "alert_type": "CROSS_ZONE_VIOLATION",
                "mitre_id": "T0886",
            },
            {
                "timestamp": "2026-09-13T02:14:20Z",
                "alert_type": "OT_BRUTE_FORCE_SCAN",
                "mitre_id": "T0846",
            },
        ],
    },
    "physics-aware-safety-violation": {
        "started_at": "2026-09-13T02:15:00+00:00",
        "finished_at": "2026-09-13T02:15:30+00:00",
        "alerts": [
            {
                "timestamp": "2026-09-13T02:15:02Z",
                "alert_type": "PROCESS_SAFETY_VIOLATION",
                "mitre_id": "T0836",
            },
        ],
    },
}


def test_plans_are_valid() -> None:
    assert validate_plan(load_plan()) == []
    assert validate_plan(load_plan(OLD_PLAN)) == []


def test_new_plan_covers_eight_steps_and_fourteen_expectations() -> None:
    plan = load_plan()
    assert len(plan["steps"]) == 8
    assert sum(len(step["expectations"]) for step in plan["steps"]) == 14


def test_evaluate_detects_all_expectations() -> None:
    results = evaluate(load_plan(OLD_PLAN), OBSERVATIONS)
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
    summary = evaluate(load_plan(OLD_PLAN), observations)["summary"]
    assert summary["expectations_detected"] == 3
    assert summary["detection_rate_pct"] == 75.0


def test_alert_outside_window_is_ignored() -> None:
    observations = copy.deepcopy(OBSERVATIONS)
    observations["physics-aware-safety-violation"]["alerts"] = [
        {
            "timestamp": "2026-09-13T02:14:59Z",
            "alert_type": "PROCESS_SAFETY_VIOLATION",
            "mitre_id": "T0836",
        }
    ]
    summary = evaluate(load_plan(OLD_PLAN), observations)["summary"]
    assert summary["expectations_detected"] == 3


def test_plan_with_wrong_technique_mapping_is_rejected() -> None:
    plan = copy.deepcopy(load_plan())
    plan["steps"][1]["expectations"][0]["technique"] = "T0886"
    problems = validate_plan(plan)
    assert any("does not detect" in problem for problem in problems)


def test_alert_with_wrong_lab_technique_fails_loudly() -> None:
    """The lab's label must match the plan, not just the alert_type."""
    observations = copy.deepcopy(OBSERVATIONS)
    observations["enterprise-pivot-and-write"]["alerts"][0]["mitre_id"] = "T9999"
    with pytest.raises(EmulationDataError, match="expected lab technique"):
        evaluate(load_plan(OLD_PLAN), observations)


def test_plan_with_unknown_lab_technique_is_rejected() -> None:
    plan = copy.deepcopy(load_plan())
    plan["steps"][0]["expectations"][0]["lab_technique"] = "T9999"
    problems = validate_plan(plan)
    assert any("unknown lab technique" in problem for problem in problems)


def test_render_markdown_contains_summary() -> None:
    report = render_markdown(evaluate(load_plan(OLD_PLAN), OBSERVATIONS))
    assert "Adversary Emulation Results" in report
    assert "100.0%" in report


def test_new_lab_run_replays_fourteen_of_fourteen() -> None:
    observations = json.loads(NEW_OBSERVATIONS.read_text(encoding="utf-8"))
    results = evaluate(load_plan(), observations)
    summary = results["summary"]
    assert summary["expectations_total"] == 14
    assert summary["expectations_detected"] == 14
    assert summary["detection_rate_pct"] == 100.0
    assert summary["unexpected_alerts"] == 0
    assert summary["benign_passed"] is True
    assert summary["mean_mttd_seconds"] is None


def test_unexpected_alerts_are_counted() -> None:
    observations = json.loads(NEW_OBSERVATIONS.read_text(encoding="utf-8"))
    step = observations["steps"]["enterprise-cross-zone"]
    observations["alerts"].append(
        {
            "timestamp": step["window_started_at"],
            "alert_type": "C2_BEACON",
            "source_ip": "172.23.0.20",
            "mitre_id": "T0869",
        }
    )
    summary = evaluate(load_plan(), observations)["summary"]
    assert summary["unexpected_alerts"] == 1


def test_benign_window_fails_on_an_alert() -> None:
    observations = json.loads(NEW_OBSERVATIONS.read_text(encoding="utf-8"))
    observations["alerts"].append(
        {
            "timestamp": observations["benign"]["window_started_at"],
            "alert_type": "CROSS_ZONE_VIOLATION",
            "source_ip": "172.24.0.10",
            "mitre_id": "T0886",
        }
    )
    benign = evaluate(load_plan(), observations)["benign"]
    assert benign["passed"] is False
    assert len(benign["alerts"]) == 1


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
            [
                {
                    "timestamp": "2026-09-13T02:14:07Z",
                    "alert_type": "UNAUTHORIZED_MODBUS_WRITE",
                    "mitre_id": "T0831",
                }
            ]
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
