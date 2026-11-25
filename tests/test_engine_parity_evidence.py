"""Guard the committed engine-parity evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pipelines.convert import unescape_ppl_equality  # noqa: E402
from tools.otde.rules import single_event_rule_paths  # noqa: E402

EVIDENCE = REPO_ROOT / "deploy" / "evidence" / "engine-parity" / "summary.json"


def _summary() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_every_single_event_rule_passes_every_engine() -> None:
    summary = _summary()
    assert summary["rules"]
    for name, row in summary["rules"].items():
        for engine in ("splunk", "opensearch", "kusto"):
            result = row[engine]
            assert result["status"] == "pass", f"{name} diverged in {engine}: {result}"
            assert result["missing"] == []
            assert result["extra"] == []


def test_engines_and_corpus_are_recorded() -> None:
    summary = _summary()
    positives = (
        REPO_ROOT / "metrics" / "heldout" / "positives.jsonl"
    ).read_text(encoding="utf-8").splitlines()
    assert summary["corpus"]["events"] > 1000
    assert summary["corpus"]["positives"] == len([line for line in positives if line.strip()])
    for engine in ("splunk", "opensearch", "kusto"):
        assert summary["engines"][engine]


def test_every_single_event_rule_is_covered() -> None:
    committed = set(_summary()["rules"])
    current = {
        path.relative_to(REPO_ROOT).as_posix() for path in single_event_rule_paths()
    }
    assert committed == current, "regenerate parity evidence after adding a rule"


def test_ppl_equality_is_unescaped_but_like_patterns_are_not() -> None:
    query = (
        'source=ot_auth-hmi-* | where event_type="login\\_failure" '
        'AND request="POST /Scada-LTS/login.htm" AND (LIKE(image, "%poll\\_plc.exe"))'
    )
    fixed = unescape_ppl_equality(query)
    assert 'event_type="login_failure"' in fixed
    assert 'request="POST /Scada-LTS/login.htm"' in fixed
    assert 'LIKE(image, "%poll\\_plc.exe")' in fixed
