"""Fixture-driven tests for every single-event Sigma rule in the repository.

Correlation rules are proven separately in ``test_sigma_correlations.py``: they
have no detection block and no logsource, and they are evaluated over a sequence
rather than one event, so sharing this parametrization would mean pretending two
different fixtures are the same shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from support.loader import (
    REPO_ROOT,
    cases_path_for,
    load_cases,
    load_rule,
    single_event_rule_paths,
)

from tools.otde.matcher import match

RULE_PATHS = single_event_rule_paths()


def _case_ids(rule_path: Path) -> str:
    return rule_path.stem


def test_rules_are_discovered() -> None:
    assert RULE_PATHS, "no Sigma rules found under rules/sigma"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=_case_ids)
def test_rule_has_a_test_sidecar(rule_path) -> None:
    assert cases_path_for(rule_path).exists(), (
        f"missing test cases: {cases_path_for(rule_path).relative_to(REPO_ROOT)}"
    )


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=_case_ids)
def test_rule_has_positive_and_negative_cases(rule_path) -> None:
    cases = load_cases(rule_path)
    assert any(case.expect_match for case in cases), "rule has no positive case"
    assert any(not case.expect_match for case in cases), "rule has no negative case"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=_case_ids)
def test_rule_matches_expected_cases(rule_path) -> None:
    rule = load_rule(rule_path)
    failures = []
    for case in load_cases(rule_path):
        observed = match(rule, case.event)
        if observed != case.expect_match:
            expected = "match" if case.expect_match else "no_match"
            failures.append(f"{case.name!r}: expected {expected}, observed {observed}")
    assert not failures, f"{rule_path.relative_to(REPO_ROOT)}:\n" + "\n".join(failures)
