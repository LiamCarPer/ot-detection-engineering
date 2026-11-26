"""Guard the committed live-purple evidence."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "purple-live"
    / "summary.json"
)


def _summary() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_three_runs_are_recorded() -> None:
    summary = _summary()
    assert summary["runs"] == 3
    for step, entry in summary["steps"].items():
        assert entry["runs"] == 3, step
        assert entry["expected"], step


def test_no_unexpected_repository_rules() -> None:
    for step, entry in _summary()["steps"].items():
        assert entry["unexpected"] == [], step


def test_benign_windows_are_clean() -> None:
    summary = _summary()
    assert len(summary["benign_after"]) == 3
    for window in summary["benign_after"]:
        assert window["observed"] == []
        assert window["lab_alerts"] == []


def test_mttd_is_measured() -> None:
    mttd = _summary()["mttd_seconds"]
    assert mttd["samples"] > 0
    assert mttd["mean"] is not None
    assert mttd["max"] >= mttd["mean"]


def test_mttd_matches_the_per_step_runs() -> None:
    per_step: dict[str, list[float]] = {}
    for run_number in (1, 2, 3):
        run = json.loads(
            (EVIDENCE.parent / f"run-{run_number}.json").read_text(encoding="utf-8")
        )
        for step in run["steps"]:
            if not step.get("first_fire"):
                continue
            started = datetime.fromisoformat(step["started_at"].replace("Z", "+00:00"))
            for timestamp in step["first_fire"].values():
                finished = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
                per_step.setdefault(step["id"], []).append(
                    (finished - started).total_seconds()
                )
    non_process = [
        value
        for step, values in per_step.items()
        if step != "process-safety-violation"
        for value in values
    ]
    assert 2.0 <= sum(non_process) / len(non_process) <= 3.0
    process = per_step["process-safety-violation"]
    assert 120 <= sum(process) / len(process) <= 130
    assert _summary()["mttd_seconds"]["samples"] == sum(
        len(values) for values in per_step.values()
    )


def test_every_step_detects_in_every_run() -> None:
    summary = _summary()
    for step, entry in summary["steps"].items():
        assert entry["detected"] == entry["runs"], step
        assert entry["misses"] == [], step
        assert entry["unexpected"] == [], step


def test_the_process_safety_step_is_live() -> None:
    entry = _summary()["steps"]["process-safety-violation"]
    assert entry["runs"] == 3
    assert entry["detected"] == 3
    assert entry["misses"] == []
