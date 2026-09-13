"""Discovery and loading helpers shared by the test suite."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma.rule import SigmaRule

from tools.otde.rules import (
    CATALOG_PATH,
    NATIVE_RULES_DIR,
    REPO_ROOT,
    SIGMA_RULES_DIR,
    load_catalog,
    native_rule_paths,
    sigma_rule_paths,
    technique_ids,
)

METADATA_DIR = REPO_ROOT / "metadata"


@dataclass(frozen=True)
class Case:
    name: str
    expect_match: bool
    event: dict[str, Any]


def cases_path_for(rule_path: Path) -> Path:
    # Sidecars use .yaml so that `sigma check` (which globs *.yml) does not
    # mistake them for rules.
    return rule_path.with_suffix(".test.yaml")


def load_rule(rule_path: Path) -> SigmaRule:
    return SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))


def load_cases(rule_path: Path) -> list[Case]:
    raw = yaml.safe_load(cases_path_for(rule_path).read_text(encoding="utf-8"))
    return [
        Case(
            name=entry["name"],
            expect_match=entry["expect"] == "match",
            event=entry["event"],
        )
        for entry in raw["cases"]
    ]


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
