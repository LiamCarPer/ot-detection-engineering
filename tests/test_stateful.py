"""Guard the stateful detections, their baselines and their evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from baseline.build import collect  # noqa: E402
from baseline.build_asset_behaviour import BENIGN_INPUTS  # noqa: E402
from baseline.build_asset_behaviour import build as build_asset  # noqa: E402
from baseline.build_process_values import DEFAULT_INPUT  # noqa: E402
from baseline.build_process_values import build as build_process  # noqa: E402
from tools.otde.rules import stateful_rule_paths  # noqa: E402
from tools.otde.stateful import (  # noqa: E402
    UnsupportedStatefulError,
    load_stateful_rule,
    match_stateful,
)
from tools.stateful_check import CALENDAR, CALENDAR_SCHEMA, EVIDENCE_PATH, main  # noqa: E402

PROCESS_BASELINE = REPO_ROOT / "baseline" / "process-values.json"
ASSET_BASELINE = REPO_ROOT / "baseline" / "asset-behaviour.json"
TESTCASE_SCHEMA = REPO_ROOT / "metadata" / "stateful-testcase.schema.json"
RULES = stateful_rule_paths()


def _sidecar(rule_path: Path) -> dict:
    return yaml.safe_load(rule_path.with_suffix(".test.yaml").read_text(encoding="utf-8"))


def test_stateful_rules_are_discovered() -> None:
    assert len(RULES) == 3


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_has_positive_and_negative_windows(rule_path: Path) -> None:
    sidecar = _sidecar(rule_path)
    schema = json.loads(TESTCASE_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(sidecar)
    assert any(window["expect"] == "match" for window in sidecar["windows"])
    assert any(window["expect"] == "no_match" for window in sidecar["windows"])


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_matches_its_windows(rule_path: Path) -> None:
    rule = load_stateful_rule(rule_path)
    for window in _sidecar(rule_path)["windows"]:
        observed = match_stateful(rule, window["events"])
        expected = window["expect"] == "match"
        assert observed == expected, window["name"]


def test_process_baseline_is_reproducible() -> None:
    events = [
        json.loads(line)
        for line in DEFAULT_INPUT.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    committed = json.loads(PROCESS_BASELINE.read_text(encoding="utf-8"))
    assert build_process(events) == committed


def test_asset_baseline_is_reproducible() -> None:
    events, _ = collect("suricata", BENIGN_INPUTS)
    committed = json.loads(ASSET_BASELINE.read_text(encoding="utf-8"))
    assert build_asset(events) == committed


def test_change_calendar_is_schema_valid_and_ordered() -> None:
    calendar = yaml.safe_load(CALENDAR.read_text(encoding="utf-8"))
    schema = json.loads(CALENDAR_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(calendar)
    for window in calendar["windows"]:
        assert window["starts"] < window["ends"]


def test_unknown_stateful_type_fails_loudly() -> None:
    rule = {"title": "synthetic", "stateful": {"type": "bogus"}}
    with pytest.raises(UnsupportedStatefulError, match="bogus"):
        match_stateful(rule, [])


def test_change_window_write_without_timestamp_fails_loudly() -> None:
    rule = load_stateful_rule(
        REPO_ROOT / "rules" / "stateful" / "stateful_engineering_change_window.yml"
    )
    events = [
        {
            "product": "ot_ndr",
            "service": "modbus",
            "direction": "request",
            "src_ip": "172.21.0.20",
            "dst_ip": "172.21.0.10",
            "function_code": 6,
        }
    ]
    with pytest.raises(UnsupportedStatefulError, match="timestamp"):
        match_stateful(rule, events)


def test_drift_needs_the_consecutive_sample_count() -> None:
    rule = load_stateful_rule(
        REPO_ROOT / "rules" / "stateful" / "stateful_process_value_drift.yml"
    )

    def event(index: int, value: int) -> dict:
        return {
            "timestamp": f"2026-12-01T08:0{index}:00Z",
            "product": "ot_process",
            "service": "safety_monitor",
            "event_type": "process_update",
            "asset": "plc_intake",
            "tank_level_pct": value,
        }

    assert match_stateful(rule, [event(0, 95), event(1, 96)]) is False
    assert match_stateful(rule, [event(0, 95), event(1, 96), event(2, 97)]) is True


def test_committed_evidence_is_current() -> None:
    assert main(["--check"]) == 0
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    assert evidence["summary"]["rules"] == 3
    assert evidence["summary"]["windows"] == evidence["summary"]["windows_passed"]
    assert evidence["baselines"]["process_current"] is True
    assert evidence["baselines"]["asset_current"] is True
    assert evidence["baselines"]["calendar_valid"] is True
