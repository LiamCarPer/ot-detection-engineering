"""Tests for the behaviour baseline: the artifact, the rules and the evaluator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from baseline.build import build, collect
from tools.otde.baseline import is_baseline_rule, load_baseline, load_baseline_rule, match_baseline
from tools.otde.rules import baseline_rule_paths, load_cases, technique_ids

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_RULES = baseline_rule_paths()
SUPPORTED_TYPES = {"new_asset", "new_pair", "new_function_code"}


def test_baseline_rules_are_discovered() -> None:
    assert BASELINE_RULES


@pytest.mark.parametrize("rule_path", BASELINE_RULES, ids=lambda p: p.stem)
def test_rule_metadata_is_complete(rule_path: Path) -> None:
    rule = load_baseline_rule(rule_path)
    assert is_baseline_rule(rule_path)
    for key in ("title", "id", "description", "author", "date", "level", "tags", "falsepositives"):
        assert rule.get(key), f"{rule_path.name} is missing {key}"
    assert rule["baseline"]["type"] in SUPPORTED_TYPES, rule_path.name
    known = technique_ids()
    tags = [str(tag) for tag in rule["tags"] if str(tag).startswith("attack.")]
    assert tags, f"{rule_path.name} carries no ATT&CK for ICS tag"
    for tag in tags:
        technique = tag.split(".", 1)[1].upper()
        assert technique in known, f"{rule_path.name} tags unknown technique {technique}"


@pytest.mark.parametrize("rule_path", BASELINE_RULES, ids=lambda p: p.stem)
def test_every_fixture_case_matches_the_evaluator(rule_path: Path) -> None:
    rule = load_baseline_rule(rule_path)
    baseline = load_baseline()
    cases = load_cases(rule_path)
    assert any(case.expect_match for case in cases), rule_path.name
    assert any(not case.expect_match for case in cases), rule_path.name
    for case in cases:
        assert match_baseline(rule, case.event, baseline) == case.expect_match, case.name


def test_committed_baseline_matches_the_schema() -> None:
    schema = json.loads((REPO_ROOT / "metadata" / "baseline.schema.json").read_text())
    Draft202012Validator(schema).validate(load_baseline())


def test_committed_baseline_is_reproducible() -> None:
    events, inputs = collect(
        "suricata",
        [
            "collector/samples/suricata/modbus_benign.eve.json",
            "collector/samples/suricata/dnp3_benign.eve.json",
        ],
    )
    assert build(events, inputs) == load_baseline()
