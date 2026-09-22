"""Tests for the conduit policy, its rules and the evaluator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tools.otde.conduit import (
    is_conduit_rule,
    load_conduit_rule,
    load_policy,
    match_conduit,
    observed_conduits,
    unused_conduits,
    zone_for,
)
from tools.otde.rules import conduit_rule_paths, load_cases, technique_ids

REPO_ROOT = Path(__file__).resolve().parents[1]
CONDUIT_RULES = conduit_rule_paths()
SUPPORTED_TYPES = {"undeclared_path", "undeclared_service"}


def test_conduit_rules_are_discovered() -> None:
    assert CONDUIT_RULES


@pytest.mark.parametrize("rule_path", CONDUIT_RULES, ids=lambda p: p.stem)
def test_rule_metadata_is_complete(rule_path: Path) -> None:
    rule = load_conduit_rule(rule_path)
    assert is_conduit_rule(rule_path)
    for key in ("title", "id", "description", "author", "date", "level", "tags", "falsepositives"):
        assert rule.get(key), f"{rule_path.name} is missing {key}"
    assert rule["conduit"]["type"] in SUPPORTED_TYPES, rule_path.name
    known = technique_ids()
    tags = [str(tag) for tag in rule["tags"] if str(tag).startswith("attack.")]
    assert tags, f"{rule_path.name} carries no ATT&CK for ICS tag"
    for tag in tags:
        assert tag.split(".", 1)[1].upper() in known, tag


@pytest.mark.parametrize("rule_path", CONDUIT_RULES, ids=lambda p: p.stem)
def test_every_fixture_case_matches_the_evaluator(rule_path: Path) -> None:
    rule = load_conduit_rule(rule_path)
    policy = load_policy()
    cases = load_cases(rule_path)
    assert any(case.expect_match for case in cases), rule_path.name
    assert any(not case.expect_match for case in cases), rule_path.name
    for case in cases:
        assert match_conduit(rule, case.event, policy) == case.expect_match, case.name


def test_policy_matches_the_schema() -> None:
    schema = json.loads((REPO_ROOT / "metadata" / "conduit-policy.schema.json").read_text())
    Draft202012Validator(schema).validate(load_policy())


def test_zone_lookup() -> None:
    policy = load_policy()
    assert zone_for("172.21.0.10", policy) == "control"
    assert zone_for("172.24.0.10", policy) == "it"
    assert zone_for("172.31.0.10", policy) == "field"
    assert zone_for("8.8.8.8", policy) is None


def test_observed_and_unused_conduits() -> None:
    policy = load_policy()
    events = [{"src_ip": "172.21.0.20", "dst_ip": "172.31.0.10", "dst_port": 20000}]
    assert observed_conduits(policy, events) == {("control", "field")}
    assert ["control", "field"] not in unused_conduits(policy, events)
    assert ["it", "ops"] in unused_conduits(policy, events)
