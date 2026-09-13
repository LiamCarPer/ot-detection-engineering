"""Shared rule discovery and ATT&CK for ICS technique extraction.

Used by the coverage generator, the metrics layer and the test suite so that
"which techniques does this repository detect" has exactly one implementation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from sigma.rule import SigmaRule

from tools.otde.suricata import read_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_RULES_DIR = REPO_ROOT / "rules" / "sigma"
NATIVE_RULES_DIR = REPO_ROOT / "rules" / "native"
CATALOG_PATH = REPO_ROOT / "metadata" / "attack_ics_catalog.json"

ATTACK_TAG_RE = re.compile(r"^attack\.t(?P<number>\d{4}(?:\.\d{3})?)$")


def sigma_rule_paths() -> list[Path]:
    return sorted(
        path for path in SIGMA_RULES_DIR.rglob("*.yml") if not path.name.endswith(".test.yml")
    )


def native_rule_paths() -> list[Path]:
    return sorted(NATIVE_RULES_DIR.rglob("*.rules"))


def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def technique_ids() -> set[str]:
    return {technique["id"] for technique in load_catalog()["techniques"]}


def sigma_techniques(rule_path: Path) -> list[str]:
    rule = SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))
    techniques: list[str] = []
    for tag in rule.tags:
        match = ATTACK_TAG_RE.match(str(tag))
        if match:
            technique = f"T{match.group('number').upper()}"
            if technique not in techniques:
                techniques.append(technique)
    return techniques


def native_techniques(rule_path: Path) -> list[str]:
    techniques: list[str] = []
    for rule in read_rules(rule_path):
        for technique in rule.attack_ics:
            if technique not in techniques:
                techniques.append(technique)
    return techniques


def techniques_for(rule_path: Path) -> list[str]:
    """Techniques detected by a rule file, dispatching on its format."""
    if rule_path.suffix == ".rules":
        return native_techniques(rule_path)
    if rule_path.suffix in {".yml", ".yaml"}:
        return sigma_techniques(rule_path)
    raise ValueError(f"unsupported rule format: {rule_path}")


def detected_techniques() -> dict[str, list[str]]:
    """Map each detected technique to the rule sources that detect it."""
    sources: dict[str, list[str]] = {}
    for rule_path in sigma_rule_paths():
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        for technique in sigma_techniques(rule_path):
            sources.setdefault(technique, []).append(relative)
    for rule_path in native_rule_paths():
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        for technique in native_techniques(rule_path):
            sources.setdefault(technique, []).append(relative)
    return {technique: sorted(set(paths)) for technique, paths in sources.items()}
