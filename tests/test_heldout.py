"""Guard the held-out evaluation set.

The held-out set is only worth reporting if it is actually held out and
correctly labeled. These tests enforce both: every labeled positive names a real
rule and fires it, every correlation rule has positive and negative windows, no
held-out event duplicates a fixture event, and the generated negatives reproduce
from a seed that differs from the tuning corpus.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from sigma.correlations import SigmaCorrelationRule

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "metrics"))
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from heldout_eval import (  # noqa: E402
    NEGATIVE_SEED,
    heldout_metrics,
    load_negatives,
    load_positives,
    load_windows,
    resolved_rules,
)

from tools.make_benign import DEFAULT_SEED, build  # noqa: E402
from tools.otde.correlation import match_correlation  # noqa: E402
from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import (  # noqa: E402
    load_sigma_rule,
    sigma_rule_paths,
    single_event_rule_paths,
)

HELDOUT = REPO_ROOT / "metrics" / "heldout"
METADATA = REPO_ROOT / "metadata"


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((METADATA / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _rows(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True)


def _fixture_events() -> set[str]:
    events: set[str] = set()
    for rule_path in sigma_rule_paths():
        data = yaml.safe_load(
            rule_path.with_suffix(".test.yaml").read_text(encoding="utf-8")
        )
        if "cases" in data:
            for case in data["cases"]:
                events.add(_canonical(case["event"]))
        else:
            for window in data["windows"]:
                for event in window["events"]:
                    events.add(_canonical(event))
    return events


def test_positive_and_window_rows_conform_to_schema() -> None:
    positive_schema = _validator("heldout-positive.schema.json")
    window_schema = _validator("heldout-window.schema.json")
    for row in _rows(HELDOUT / "positives.jsonl"):
        positive_schema.validate(row)
    for row in _rows(HELDOUT / "windows.jsonl"):
        window_schema.validate(row)


def test_negatives_conform_to_the_telemetry_contract() -> None:
    telemetry_schema = _validator("telemetry.schema.json")
    for row in _rows(HELDOUT / "negatives.jsonl"):
        telemetry_schema.validate(row)
    for row in _rows(HELDOUT / "near-misses.jsonl"):
        telemetry_schema.validate(row)


def test_every_single_event_rule_has_a_held_out_positive() -> None:
    known = {
        path.relative_to(REPO_ROOT).as_posix(): path for path in single_event_rule_paths()
    }
    labeled = {positive.rule for positive in load_positives()}
    assert set(known) == labeled, (
        f"rules without held-out positives: {sorted(set(known) - labeled)}; "
        f"positives for unknown rules: {sorted(labeled - set(known))}"
    )


@pytest.mark.parametrize("positive", load_positives(), ids=lambda p: f"{p.rule}:{p.name}")
def test_every_held_out_positive_fires_its_rule(positive) -> None:
    rule = load_sigma_rule(REPO_ROOT / positive.rule)
    assert match(rule, positive.event), positive.name


def test_every_correlation_rule_has_positive_and_negative_windows() -> None:
    by_rule: dict[str, list] = {}
    for window in load_windows():
        by_rule.setdefault(window.rule, []).append(window)
    for rule_path in sigma_rule_paths():
        rule = load_sigma_rule(rule_path)
        if not isinstance(rule, SigmaCorrelationRule):
            continue
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        windows = by_rule.get(relative, [])
        assert any(window.expect_match for window in windows), relative
        assert any(not window.expect_match for window in windows), relative


@pytest.mark.parametrize("window", load_windows(), ids=lambda w: f"{w.rule}:{w.name}")
def test_every_held_out_window_matches_its_label(window) -> None:
    rule = resolved_rules()[str(REPO_ROOT / window.rule)]
    assert match_correlation(rule, window.events) == window.expect_match, window.name


def test_no_held_out_event_duplicates_a_fixture() -> None:
    fixtures = _fixture_events()
    held_out = [positive.event for positive in load_positives()]
    held_out += _rows(HELDOUT / "near-misses.jsonl")
    for window in load_windows():
        held_out += window.events
    leaked = [event for event in held_out if _canonical(event) in fixtures]
    assert not leaked, f"{len(leaked)} held-out events duplicate a fixture event"


def test_negatives_reproduce_from_a_different_seed() -> None:
    assert NEGATIVE_SEED != DEFAULT_SEED
    generated = build(1000, NEGATIVE_SEED)
    committed = _rows(HELDOUT / "negatives.jsonl")
    assert committed == generated


def test_negatives_do_not_overlap_the_tuning_corpus() -> None:
    tuning = {
        _canonical(row)
        for row in _rows(REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl")
    }
    held_out = {_canonical(event) for event in load_negatives()}
    assert not (tuning & held_out)


def test_holdout_metrics_are_internally_consistent() -> None:
    metrics = heldout_metrics()
    for section in ("single_event", "correlation"):
        rows = metrics[section]["per_rule"]
        assert rows, section
        aggregate = metrics[section]["aggregate"]
        for key in ("tp", "fn", "fp", "tn"):
            assert aggregate[key] == sum(row[key] for row in rows)
        for row in rows:
            if row["precision"] is not None:
                assert row["precision_ci95"][0] <= row["precision"] <= row["precision_ci95"][1]
            if row["recall"] is not None:
                assert row["recall_ci95"][0] <= row["recall"] <= row["recall_ci95"][1]
