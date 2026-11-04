"""Tests for the generated benign baseline corpus."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "metrics"))
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from compute import baseline_metrics  # noqa: E402

from tools.make_benign import DEFAULT_COUNT, DEFAULT_SEED, build  # noqa: E402

CORPUS = REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl"
README = REPO_ROOT / "metrics" / "baseline" / "README.md"


def _serialize(events: list[dict]) -> str:
    return "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n"


def test_the_committed_corpus_is_reproducible() -> None:
    assert CORPUS.read_text(encoding="utf-8") == _serialize(build(DEFAULT_COUNT, DEFAULT_SEED))


def test_the_corpus_is_large_enough_for_a_confidence_interval() -> None:
    # 1,000 events puts the 95% upper bound on a zero-FP rate below 0.4%.
    assert DEFAULT_COUNT >= 1_000
    assert len(CORPUS.read_text(encoding="utf-8").splitlines()) == DEFAULT_COUNT


def test_the_readme_records_how_to_regenerate_the_corpus() -> None:
    text = README.read_text(encoding="utf-8")
    assert "tools/make_benign.py" in text
    assert str(DEFAULT_SEED) in text
    assert "generated" in text.lower()
    assert "not" in text.lower() and "field" in text.lower()


def test_no_rule_fires_on_the_generated_corpus() -> None:
    events = build(DEFAULT_COUNT, DEFAULT_SEED)
    result = baseline_metrics(events)
    assert result["events_total"] == DEFAULT_COUNT
    assert result["false_positive_events"] == 0, result["details"]
    assert result["false_positive_rate_ci95"][1] < 0.004
