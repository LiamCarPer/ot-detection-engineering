"""Metadata governance: rule policy, ATT&CK for ICS tags, and schema conformance."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaLevel
from support.loader import (
    METADATA_DIR,
    REPO_ROOT,
    cases_path_for,
    is_correlation_rule,
    load_catalog,
    load_sigma_rule,
    sigma_rule_paths,
    technique_ids,
)

RULE_PATHS = sigma_rule_paths()
TECHNIQUE_IDS = technique_ids()
ATTACK_TAG_RE = re.compile(r"^attack\.t(?P<number>\d{4}(?:\.\d{3})?)$")


def _path_id(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _validator(schema_name: str) -> Draft202012Validator:
    schema = json.loads((METADATA_DIR / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_attack_ics_catalog_conforms_to_schema() -> None:
    catalog = load_catalog()
    _validator("attack_ics_catalog.schema.json").validate(catalog)
    assert catalog["techniques"], "catalog has no techniques"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=_path_id)
def test_rule_metadata_is_complete(rule_path: Path) -> None:
    rule = load_sigma_rule(rule_path)
    assert uuid.UUID(str(rule.id)), "rule id must be a UUID"
    assert rule.title and rule.title.strip(), "rule must have a title"
    assert rule.description and rule.description.strip(), "rule must have a description"
    assert rule.author and rule.author.strip(), "rule must have an author"
    assert rule.date is not None, "rule must have a date"
    assert rule.level in (SigmaLevel.LOW, SigmaLevel.MEDIUM, SigmaLevel.HIGH, SigmaLevel.CRITICAL)
    assert rule.falsepositives, "rule must document false positives"
    if isinstance(rule, SigmaCorrelationRule):
        # A correlation has no logsource of its own: it inherits routing from the
        # rules it references, so those references are the thing to check.
        assert rule.rules, "correlation rule must reference at least one rule"
        assert rule.timespan is not None, "correlation rule must declare a timespan"
    else:
        assert rule.logsource.product, "rule must define a logsource product"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=_path_id)
def test_rule_has_known_ics_technique_tag(rule_path: Path) -> None:
    tags = [str(tag) for tag in load_sigma_rule(rule_path).tags]
    attack_tags = [tag for tag in tags if tag.startswith("attack.")]
    assert attack_tags, "rule must carry at least one ATT&CK tag"
    for tag in attack_tags:
        match = ATTACK_TAG_RE.match(tag)
        assert match, f"malformed ATT&CK tag: {tag}"
        technique_id = f"T{match.group('number').upper()}"
        assert technique_id in TECHNIQUE_IDS, f"{technique_id} is not in the ATT&CK for ICS catalog"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=_path_id)
def test_test_cases_conform_to_schema(rule_path: Path) -> None:
    schema = (
        "correlation-testcase.schema.json"
        if is_correlation_rule(rule_path)
        else "testcase.schema.json"
    )
    raw = yaml.safe_load(cases_path_for(rule_path).read_text(encoding="utf-8"))
    _validator(schema).validate(raw)


def test_rule_ids_are_unique() -> None:
    seen: dict[str, Path] = {}
    duplicates = []
    for rule_path in RULE_PATHS:
        rule_id = str(load_sigma_rule(rule_path).id)
        if rule_id in seen:
            duplicates.append(f"{rule_id}: {seen[rule_id]} and {rule_path}")
        seen[rule_id] = rule_path
    assert not duplicates, "duplicate rule ids:\n" + "\n".join(duplicates)
