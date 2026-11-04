"""Per-rule precision and recall on a held-out set.

The fixtures beside each rule are a regression check: they were written with the
rule and are tuned until they pass. They cannot tell you how the rule behaves on
traffic it was not written against. This module measures the same rules on a
held-out set that is never used for tuning:

- ``positives.jsonl`` — labeled events, at least one per single-event rule.
- ``negatives.jsonl`` — generated benign telemetry from a different seed than
  the tuning corpus.
- ``near-misses.jsonl`` — one event per rule that differs in the decisive field.
- ``windows.jsonl`` — labeled sequences for correlation rules.

It reports per-rule precision, recall and false-positive rate with 95% Wilson
score intervals, plus a micro aggregate. The point is not a flattering number;
it is that the number has a sample size and an interval attached.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yara_x
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from stats import rounded_interval

from tools.otde.correlation import match_correlation
from tools.otde.matcher import match
from tools.otde.rules import (
    REPO_ROOT,
    SIGMA_RULES_DIR,
    correlation_rule_paths,
    single_event_rule_paths,
    yara_rule_paths,
)

HELDOUT_DIR = REPO_ROOT / "metrics" / "heldout"
POSITIVES_PATH = HELDOUT_DIR / "positives.jsonl"
NEGATIVES_PATH = HELDOUT_DIR / "negatives.jsonl"
NEAR_MISSES_PATH = HELDOUT_DIR / "near-misses.jsonl"
WINDOWS_PATH = HELDOUT_DIR / "windows.jsonl"
YARA_POSITIVES_PATH = HELDOUT_DIR / "yara.jsonl"
YARA_NEGATIVES_DIR = HELDOUT_DIR / "files" / "negatives"
NEGATIVE_SEED = 20260202


@dataclass(frozen=True)
class Positive:
    rule: str
    name: str
    event: dict


@dataclass(frozen=True)
class Window:
    rule: str
    name: str
    expect_match: bool
    events: list[dict]


@dataclass(frozen=True)
class YaraPositive:
    rule: str
    name: str
    file: str


def _load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_positives(path: Path = POSITIVES_PATH) -> list[Positive]:
    return [
        Positive(rule=row["rule"], name=row["name"], event=row["event"])
        for row in _load_jsonl(path)
    ]


def load_windows(path: Path = WINDOWS_PATH) -> list[Window]:
    return [
        Window(
            rule=row["rule"],
            name=row["name"],
            expect_match=row["expect"] == "match",
            events=row["events"],
        )
        for row in _load_jsonl(path)
    ]


def load_negatives(
    negatives_path: Path = NEGATIVES_PATH,
    near_misses_path: Path = NEAR_MISSES_PATH,
) -> list[dict]:
    """Generated negatives plus the authored per-rule near misses."""
    return _load_jsonl(negatives_path) + _load_jsonl(near_misses_path)


def load_yara_positives(path: Path = YARA_POSITIVES_PATH) -> list[YaraPositive]:
    return [
        YaraPositive(rule=row["rule"], name=row["name"], file=row["file"])
        for row in _load_jsonl(path)
    ]


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def _counts(tp: int, fn: int, fp: int, tn: int) -> dict:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    fp_rate = _ratio(fp, fp + tn)
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": precision,
        "precision_ci95": list(rounded_interval(tp, tp + fp)) if tp + fp else None,
        "recall": recall,
        "recall_ci95": list(rounded_interval(tp, tp + fn)) if tp + fn else None,
        "false_positive_rate": fp_rate,
        "false_positive_rate_ci95": (
            list(rounded_interval(fp, fp + tn)) if fp + tn else None
        ),
    }


def _aggregate(rows: list[dict]) -> dict:
    totals = {key: sum(row[key] for row in rows) for key in ("tp", "fn", "fp", "tn")}
    return _counts(**totals)


def resolved_rules() -> dict[str, SigmaRule | SigmaCorrelationRule]:
    collection = SigmaCollection.load_ruleset([SIGMA_RULES_DIR])
    return {str(rule.source.path): rule for rule in collection.rules}


def _single_event_metrics(
    resolved: dict[str, SigmaRule | SigmaCorrelationRule],
    positives: list[Positive],
    negatives: list[dict],
) -> dict:
    by_rule: dict[str, list[Positive]] = defaultdict(list)
    for positive in positives:
        by_rule[positive.rule].append(positive)

    rows = []
    for rule_path in single_event_rule_paths():
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        rule = resolved.get(str(rule_path))
        if not isinstance(rule, SigmaRule):
            rule = SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))
        rule_positives = by_rule.get(relative, [])
        tp = sum(1 for positive in rule_positives if match(rule, positive.event))
        fn = len(rule_positives) - tp
        fp = sum(1 for negative in negatives if match(rule, negative))
        tn = len(negatives) - fp
        rows.append(
            {
                "rule": relative,
                "title": rule.title,
                "positives": len(rule_positives),
                "negatives": len(negatives),
                **_counts(tp, fn, fp, tn),
            }
        )
    return {
        "rules_total": len(rows),
        "positives_total": len(positives),
        "negatives_total": len(negatives),
        "per_rule": rows,
        "aggregate": _aggregate(rows),
    }


def _correlation_metrics(
    resolved: dict[str, SigmaRule | SigmaCorrelationRule],
    windows: list[Window],
) -> dict:
    by_rule: dict[str, list[Window]] = defaultdict(list)
    for window in windows:
        by_rule[window.rule].append(window)

    rows = []
    for rule_path in correlation_rule_paths():
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        rule = resolved.get(str(rule_path))
        if not isinstance(rule, SigmaCorrelationRule):
            raise TypeError(f"{relative} is not a resolved correlation rule")
        rule_windows = by_rule.get(relative, [])
        tp = fn = fp = tn = 0
        for window in rule_windows:
            observed = match_correlation(rule, window.events)
            if window.expect_match and observed:
                tp += 1
            elif window.expect_match:
                fn += 1
            elif observed:
                fp += 1
            else:
                tn += 1
        rows.append(
            {
                "rule": relative,
                "title": rule.title,
                "positives": sum(1 for window in rule_windows if window.expect_match),
                "negatives": sum(1 for window in rule_windows if not window.expect_match),
                **_counts(tp, fn, fp, tn),
            }
        )
    return {
        "rules_total": len(rows),
        "positives_total": sum(row["positives"] for row in rows),
        "negatives_total": sum(row["negatives"] for row in rows),
        "per_rule": rows,
        "aggregate": _aggregate(rows),
    }


def yara_identifier(rule_path: Path) -> str:
    match = re.search(
        r"^\s*rule\s+(\w+)", rule_path.read_text(encoding="utf-8"), re.MULTILINE
    )
    if not match:
        raise ValueError(f"{rule_path} has no rule identifier")
    return match.group(1)


def _yara_metrics() -> dict:
    paths = yara_rule_paths()
    compiled = yara_x.compile(
        "\n".join(path.read_text(encoding="utf-8") for path in paths)
    )
    positives = load_yara_positives()
    negatives = sorted(path for path in YARA_NEGATIVES_DIR.iterdir() if path.is_file())

    def matches(path: Path) -> set[str]:
        results = yara_x.Scanner(compiled).scan(path.read_bytes())
        return {rule.identifier for rule in results.matching_rules}

    rows = []
    for rule_path in paths:
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        identifier = yara_identifier(rule_path)
        rule_positives = [row for row in positives if row.rule == relative]
        tp = sum(1 for row in rule_positives if identifier in matches(REPO_ROOT / row.file))
        fn = len(rule_positives) - tp
        fp = sum(1 for path in negatives if identifier in matches(path))
        tn = len(negatives) - fp
        rows.append(
            {
                "rule": relative,
                "title": identifier,
                "positives": len(rule_positives),
                "negatives": len(negatives),
                **_counts(tp, fn, fp, tn),
            }
        )
    return {
        "rules_total": len(rows),
        "positives_total": len(positives),
        "negatives_total": len(negatives),
        "per_rule": rows,
        "aggregate": _aggregate(rows),
    }


def heldout_metrics() -> dict:
    resolved = resolved_rules()
    return {
        "single_event": _single_event_metrics(
            resolved, load_positives(), load_negatives()
        ),
        "correlation": _correlation_metrics(resolved, load_windows()),
        "yara": _yara_metrics(),
    }
