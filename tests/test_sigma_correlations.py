"""Fixture-driven tests for every Sigma correlation rule in the repository.

Correlation rules are the one place this repository moves past per-event
signatures, so they get their own proof: a labeled event sequence that must fire
and a set of sequences that must stay quiet, evaluated by the windowed evaluator
in ``tools/otde/correlation.py``. The negative cases carry the weight here — a
counted read burst that is not an enumeration, a fan-out spread beyond the
window, and an approved reader the referenced rule filters out.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from support.loader import (
    REPO_ROOT,
    SIGMA_RULES_DIR,
    cases_path_for,
    correlation_rule_paths,
    load_correlation_cases,
    load_correlation_rule,
)

from tools.otde.correlation import UnsupportedCorrelationError, match_correlation

CORRELATION_PATHS = correlation_rule_paths()


def _case_ids(rule_path: Path) -> str:
    return rule_path.stem


def resolved_correlation_rules() -> list[SigmaCorrelationRule]:
    """Load every rule together so correlation references resolve."""
    collection = SigmaCollection.load_ruleset([SIGMA_RULES_DIR])
    return [rule for rule in collection.rules if isinstance(rule, SigmaCorrelationRule)]


def test_correlation_rules_are_discovered() -> None:
    assert CORRELATION_PATHS, "no Sigma correlation rules found under rules/sigma"


def test_references_resolve() -> None:
    for rule in resolved_correlation_rules():
        assert rule.referenced_rules, f"{rule.title} has no rule references"
        for reference in rule.referenced_rules:
            assert reference.rule is not None, (
                f"{rule.title} references {reference.reference}, which does not resolve"
            )


@pytest.mark.parametrize("rule_path", CORRELATION_PATHS, ids=_case_ids)
def test_correlation_has_a_test_sidecar(rule_path: Path) -> None:
    assert cases_path_for(rule_path).exists(), (
        f"missing test cases: {cases_path_for(rule_path).relative_to(REPO_ROOT)}"
    )


@pytest.mark.parametrize("rule_path", CORRELATION_PATHS, ids=_case_ids)
def test_correlation_has_positive_and_negative_windows(rule_path: Path) -> None:
    cases = load_correlation_cases(rule_path)
    assert any(case.expect_match for case in cases), "correlation has no positive window"
    assert any(not case.expect_match for case in cases), "correlation has no negative window"


@pytest.mark.parametrize("rule_path", CORRELATION_PATHS, ids=_case_ids)
def test_correlation_matches_expected_windows(rule_path: Path) -> None:
    rule = load_correlation_rule(rule_path)
    # Every referenced rule has to be resolved before a window can be counted.
    resolved = next(
        candidate
        for candidate in resolved_correlation_rules()
        if str(candidate.id) == str(rule.id)
    )
    failures = []
    for case in load_correlation_cases(rule_path):
        observed = match_correlation(resolved, case.events)
        if observed != case.expect_match:
            expected = "match" if case.expect_match else "no_match"
            failures.append(f"{case.name!r}: expected {expected}, observed {observed}")
    assert not failures, f"{rule_path.relative_to(REPO_ROOT)}:\n" + "\n".join(failures)


def _enumeration_rule() -> SigmaCorrelationRule:
    """The value_count rule the boundary tests were written against."""
    return next(
        rule
        for rule in resolved_correlation_rules()
        if str(rule.id) == "7c4e1b2a-6d3f-4a58-9e21-0b5c8f7a2d10"
    )


def test_window_boundary_is_exclusive() -> None:
    """The count has to fall inside the window, not merely reach it at the edge."""
    rule = _enumeration_rule()

    def event(minute: int, second: int, destination: str) -> dict:
        return {
            "timestamp": f"2026-05-01T10:{minute:02d}:{second:02d}.000Z",
            "product": "ot_ndr",
            "service": "modbus",
            "direction": "request",
            "function_code": 3,
            "src_ip": "172.24.0.10",
            "dst_ip": destination,
            "unit_id": 1,
            "register": 0,
        }

    inside = [
        event(0, 0, "172.21.0.10"),
        event(0, 30, "172.21.0.11"),
        event(0, 59, "172.21.0.12"),
    ]
    assert match_correlation(rule, inside) is True

    # Same three destinations at 0s, 30s and 300s. The window is half-open, so
    # no five-minute span contains all three and the correlation stays quiet.
    spread = [
        event(0, 0, "172.21.0.10"),
        event(0, 30, "172.21.0.11"),
        event(5, 0, "172.21.0.12"),
    ]
    assert match_correlation(rule, spread) is False


def test_unsupported_correlation_type_fails_loudly() -> None:
    """A correlation type this harness cannot evaluate must not return a result."""
    synthetic = SigmaCollection.from_yaml(
        """
        title: Synthetic Temporal Correlation
        id: 00000000-0000-4000-8000-0000000000ff
        status: experimental
        correlation:
          type: temporal
          rules:
            - db9f2530-dbb5-4aa7-8bcf-b5e59ea1c9db
          group-by:
            - src_ip
          timespan: 5m
        """,
        resolve_references=False,
    ).rules[0]
    assert isinstance(synthetic, SigmaCorrelationRule)

    with pytest.raises(UnsupportedCorrelationError, match="temporal"):
        match_correlation(synthetic, [{"timestamp": "2026-05-01T10:00:00.000Z"}])


def test_events_without_a_timestamp_fail_loudly() -> None:
    """A window cannot be evaluated without a clock, so it must not silently pass."""
    rule = _enumeration_rule()
    with pytest.raises(UnsupportedCorrelationError, match="timestamp"):
        match_correlation(
            rule,
            [
                {
                    "product": "ot_ndr",
                    "service": "modbus",
                    "direction": "request",
                    "function_code": 3,
                    "src_ip": "172.24.0.10",
                    "dst_ip": "172.21.0.10",
                }
            ],
        )


def test_negative_operator_fails_loudly() -> None:
    """`lt` on a one-event window would always be true, so it is rejected."""
    from sigma.correlations import SigmaCorrelationConditionOperator

    rule = _enumeration_rule()
    rule.condition.op = SigmaCorrelationConditionOperator.LT
    event = {
        "timestamp": "2026-05-01T10:00:00Z",
        "product": "ot_ndr",
        "service": "modbus",
        "direction": "request",
        "function_code": 3,
        "src_ip": "172.24.0.10",
        "dst_ip": "172.21.0.10",
        "register": 1,
    }
    with pytest.raises(UnsupportedCorrelationError, match="operator"):
        match_correlation(rule, [event])


def test_missing_counted_field_fails_loudly() -> None:
    rule = _enumeration_rule()
    event = {
        "timestamp": "2026-05-01T10:00:00Z",
        "product": "ot_ndr",
        "service": "modbus",
        "direction": "request",
        "function_code": 3,
        "src_ip": "172.24.0.10",
    }
    with pytest.raises(UnsupportedCorrelationError, match="dst_ip"):
        match_correlation(rule, [event])


def test_missing_group_field_fails_loudly() -> None:
    rule = _exception_rule()
    event = {
        "timestamp": "2026-05-01T10:00:00Z",
        "product": "ot_ndr",
        "service": "modbus",
        "direction": "response",
        "exception_code": 2,
    }
    with pytest.raises(UnsupportedCorrelationError, match="dst_ip"):
        match_correlation(rule, [event])


def test_mixed_naive_and_aware_timestamps_are_normalized() -> None:
    rule = _enumeration_rule()
    events = []
    for index in range(20):
        events.append(
            {
                "timestamp": (
                    f"2026-05-01T10:00:{index:02d}Z"
                    if index == 0
                    else f"2026-05-01T10:00:{index:02d}"
                ),
                "product": "ot_ndr",
                "service": "modbus",
                "direction": "request",
                "function_code": 3,
                "src_ip": "172.24.0.10",
                "dst_ip": f"172.21.0.{index + 1}",
                "register": index,
            }
        )
    assert match_correlation(rule, events) is True


def _exception_rule():
    return next(
        rule
        for rule in resolved_correlation_rules()
        if str(rule.id) == "f0d5c3a8-7b29-4e61-8a34-5c9f1d6b2e47"
    )


def test_duplicate_events_are_counted_once() -> None:
    rule = _exception_rule()
    event = {
        "timestamp": "2026-05-01T10:00:00Z",
        "product": "ot_ndr",
        "service": "modbus",
        "direction": "response",
        "src_ip": "172.21.0.10",
        "dst_ip": "172.24.0.10",
        "exception_code": 2,
    }
    assert match_correlation(rule, [event] * 10) is False
    distinct = [
        {**event, "timestamp": f"2026-05-01T10:00:{index:02d}Z"} for index in range(10)
    ]
    assert match_correlation(rule, distinct) is True
