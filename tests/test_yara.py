"""Tests for the YARA file-detection family."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from tools.otde.rules import (
    load_yara_cases,
    technique_ids,
    yara_rule_paths,
    yara_techniques,
)
from tools.yara_check import evaluate

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES = yara_rule_paths()
REQUIRED_META = ("author", "description", "date", "attack_ics", "reference", "level")


def test_yara_rules_are_discovered() -> None:
    assert RULES


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_metadata_is_complete(rule_path: Path) -> None:
    text = rule_path.read_text(encoding="utf-8")
    for key in REQUIRED_META:
        assert re.search(rf'^\s*{key}\s*=\s*"', text, re.MULTILINE), (
            f"{rule_path.name} is missing meta {key}"
        )
    techniques = yara_techniques(rule_path)
    assert techniques, f"{rule_path.name} carries no ATT&CK for ICS tag"
    known = technique_ids()
    for technique in techniques:
        assert technique in known, f"{rule_path.name} tags unknown technique {technique}"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_every_rule_has_positive_and_negative_fixtures(rule_path: Path) -> None:
    cases = load_yara_cases(rule_path)
    assert any(case.expect_match for case in cases), rule_path.name
    assert any(not case.expect_match for case in cases), rule_path.name
    for case in cases:
        assert (REPO_ROOT / case.file).exists(), case.file

    schema = json.loads((REPO_ROOT / "metadata" / "yara-testcase.schema.json").read_text())
    raw = yaml.safe_load(
        rule_path.with_suffix(".test.yaml").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(raw)


def test_every_fixture_and_the_payload_scan_pass() -> None:
    evidence = evaluate()
    for row in evidence["rules"]:
        for case in row["cases"]:
            assert case["passed"], f"{row['rule']}: {case['name']}"
    assert evidence["payload_scan"]["passed"]
    assert evidence["selftest"]["eicar"] is True


def test_samples_are_documented_as_synthetic() -> None:
    readme = REPO_ROOT / "tests" / "yara" / "samples" / "README.md"
    text = readme.read_text(encoding="utf-8").lower()
    assert "synthetic" in text and "no real malware" in text
