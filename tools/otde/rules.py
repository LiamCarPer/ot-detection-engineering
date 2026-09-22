"""Shared rule discovery and ATT&CK for ICS technique extraction.

Used by the coverage generator, the metrics layer and the test suite so that
"which techniques does this repository detect" has exactly one implementation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from tools.otde.suricata import read_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_RULES_DIR = REPO_ROOT / "rules" / "sigma"
NATIVE_RULES_DIR = REPO_ROOT / "rules" / "native"
BASELINE_RULES_DIR = REPO_ROOT / "rules" / "baseline"
METADATA_DIR = REPO_ROOT / "metadata"
CATALOG_PATH = METADATA_DIR / "attack_ics_catalog.json"

ATTACK_TAG_RE = re.compile(r"^attack\.t(?P<number>\d{4}(?:\.\d{3})?)$")
CORRELATION_KEY = "correlation"
BASELINE_KEY = "baseline"


def _techniques_from_tags(tags: list[Any]) -> list[str]:
    techniques: list[str] = []
    for tag in tags:
        match = ATTACK_TAG_RE.match(str(tag))
        if match:
            technique = f"T{match.group('number').upper()}"
            if technique not in techniques:
                techniques.append(technique)
    return techniques


def sigma_rule_paths() -> list[Path]:
    # Sidecars are *.test.yaml and do not match the *.yml glob; the guard keeps a
    # sidecar named *.test.yml from ever being treated as a rule.
    return sorted(path for path in SIGMA_RULES_DIR.rglob("*.yml") if ".test." not in path.name)


def is_correlation_rule(rule_path: Path) -> bool:
    """True when the file is a Sigma correlation rule rather than a log rule.

    Detected from the raw mapping so callers can pick a parser without first
    committing to one: a correlation rule has no detection block, and a log rule
    has no correlation block.
    """
    data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    return isinstance(data, dict) and CORRELATION_KEY in data


def correlation_rule_paths() -> list[Path]:
    return [path for path in sigma_rule_paths() if is_correlation_rule(path)]


def single_event_rule_paths() -> list[Path]:
    return [path for path in sigma_rule_paths() if not is_correlation_rule(path)]


def load_sigma_rule(rule_path: Path) -> SigmaRule | SigmaCorrelationRule:
    """Parse either kind of Sigma rule, dispatching on the file's shape.

    References are not resolved here: a correlation rule names rules that live in
    other files, so resolving one in isolation is impossible by construction.
    Callers that need the referenced rules loaded together use
    ``SigmaCollection.load_ruleset``; callers that only need the rule's own
    metadata get an unresolved correlation rule whose ``rules`` field still lists
    what it references.
    """
    text = rule_path.read_text(encoding="utf-8")
    if is_correlation_rule(rule_path):
        rules = SigmaCollection.from_yaml(text, resolve_references=False).rules
        if len(rules) != 1 or not isinstance(rules[0], SigmaCorrelationRule):
            raise ValueError(f"{rule_path} is not a single correlation rule")
        return rules[0]
    return SigmaRule.from_yaml(text)



def native_rule_paths() -> list[Path]:
    return sorted(NATIVE_RULES_DIR.rglob("*.rules"))


def load_catalog() -> dict[str, Any]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def technique_ids() -> set[str]:
    return {technique["id"] for technique in load_catalog()["techniques"]}


def sigma_techniques(rule_path: Path) -> list[str]:
    return _techniques_from_tags(list(load_sigma_rule(rule_path).tags))


def baseline_rule_paths() -> list[Path]:
    # Sidecars are *.test.yaml, so they do not match the *.yml glob.
    return sorted(
        path for path in BASELINE_RULES_DIR.rglob("*.yml") if ".test." not in path.name
    )


def baseline_techniques(rule_path: Path) -> list[str]:
    data = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    return _techniques_from_tags(list(data.get("tags", [])))


def native_techniques(rule_path: Path) -> list[str]:
    techniques: list[str] = []
    for rule in read_rules(rule_path):
        for technique in rule.attack_ics:
            if technique not in techniques:
                techniques.append(technique)
    return techniques


@dataclass(frozen=True)
class Case:
    name: str
    expect_match: bool
    event: dict[str, Any]


@dataclass(frozen=True)
class CorrelationCase:
    name: str
    expect_match: bool
    events: list[dict[str, Any]]


def cases_path_for(rule_path: Path) -> Path:
    # Sidecars use .yaml so that `sigma check` (which globs *.yml) does not
    # mistake them for rules.
    return rule_path.with_suffix(".test.yaml")


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


def load_correlation_cases(rule_path: Path) -> list[CorrelationCase]:
    """Load the event sequences a correlation rule is proven against.

    A correlation needs a sequence and a window, so the sidecar schema is
    ``windows`` rather than ``cases``; everything else about the fixture is the
    same idea: one labeled positive and one labeled negative at minimum.
    """
    raw = yaml.safe_load(cases_path_for(rule_path).read_text(encoding="utf-8"))
    return [
        CorrelationCase(
            name=entry["name"],
            expect_match=entry["expect"] == "match",
            events=entry["events"],
        )
        for entry in raw["windows"]
    ]


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
    for rule_path in baseline_rule_paths():
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        for technique in baseline_techniques(rule_path):
            sources.setdefault(technique, []).append(relative)
    for rule_path in native_rule_paths():
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        for technique in native_techniques(rule_path):
            sources.setdefault(technique, []).append(relative)
    return {technique: sorted(set(paths)) for technique, paths in sources.items()}
