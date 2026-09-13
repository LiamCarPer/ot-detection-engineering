"""Discovery and loading helpers shared by the test suite."""

from __future__ import annotations

from sigma.rule import SigmaRule

from tools.otde.rules import (
    CATALOG_PATH,
    METADATA_DIR,
    NATIVE_RULES_DIR,
    REPO_ROOT,
    SIGMA_RULES_DIR,
    Case,
    cases_path_for,
    load_cases,
    load_catalog,
    native_rule_paths,
    sigma_rule_paths,
    technique_ids,
)


def load_rule(rule_path):
    return SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))


__all__ = [
    "CATALOG_PATH",
    "METADATA_DIR",
    "NATIVE_RULES_DIR",
    "REPO_ROOT",
    "SIGMA_RULES_DIR",
    "Case",
    "cases_path_for",
    "load_cases",
    "load_catalog",
    "load_rule",
    "native_rule_paths",
    "sigma_rule_paths",
    "technique_ids",
]
