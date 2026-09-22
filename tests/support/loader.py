"""Discovery and loading helpers shared by the test suite."""

from __future__ import annotations

from pathlib import Path

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from tools.otde.rules import (
    CATALOG_PATH,
    METADATA_DIR,
    NATIVE_RULES_DIR,
    REPO_ROOT,
    SIGMA_RULES_DIR,
    Case,
    CorrelationCase,
    cases_path_for,
    correlation_rule_paths,
    is_correlation_rule,
    load_cases,
    load_catalog,
    load_correlation_cases,
    load_sigma_rule,
    native_rule_paths,
    sigma_rule_paths,
    single_event_rule_paths,
    technique_ids,
)


def load_rule(rule_path: Path) -> SigmaRule:
    return SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))


def load_correlation_rule(rule_path: Path) -> SigmaCorrelationRule:
    rule = load_sigma_rule(rule_path)
    if not isinstance(rule, SigmaCorrelationRule):
        raise TypeError(f"{rule_path} is not a correlation rule")
    return rule


__all__ = [
    "CATALOG_PATH",
    "METADATA_DIR",
    "NATIVE_RULES_DIR",
    "REPO_ROOT",
    "SIGMA_RULES_DIR",
    "Case",
    "CorrelationCase",
    "cases_path_for",
    "correlation_rule_paths",
    "is_correlation_rule",
    "load_cases",
    "load_catalog",
    "load_correlation_cases",
    "load_correlation_rule",
    "load_rule",
    "load_sigma_rule",
    "native_rule_paths",
    "sigma_rule_paths",
    "single_event_rule_paths",
    "technique_ids",
]
