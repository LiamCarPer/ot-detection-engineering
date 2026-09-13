"""Discovery and loading helpers shared by the test suite."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma.rule import SigmaRule

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules" / "sigma"
NATIVE_RULES_DIR = REPO_ROOT / "rules" / "native"
METADATA_DIR = REPO_ROOT / "metadata"
CATALOG_PATH = METADATA_DIR / "attack_ics_catalog.json"


@dataclass(frozen=True)
class Case:
    name: str
    expect_match: bool
    event: dict[str, Any]


def sigma_rule_paths() -> list[Path]:
    return sorted(
        path for path in RULES_DIR.rglob("*.yml") if not path.name.endswith(".test.yml")
    )


def native_rule_paths() -> list[Path]:
    return sorted(NATIVE_RULES_DIR.rglob("*.rules"))


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


def load_catalog() -> dict[str, Any]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def technique_ids() -> set[str]:
    return {technique["id"] for technique in load_catalog()["techniques"]}
