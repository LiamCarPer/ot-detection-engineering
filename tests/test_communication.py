"""Keep the communication docs anchored to the evidence, without personal content."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from generate_coverage import build_report  # noqa: E402

DOCS = REPO_ROOT / "docs"
DEMO = DOCS / "DEMO.md"
WRITEUP = DOCS / "WRITEUP.md"
OPERATIONS = DOCS / "OPERATIONS.md"
ROADMAP = DOCS / "ROADMAP.md"
README = REPO_ROOT / "README.md"
HEALTH = REPO_ROOT / "deploy" / "evidence" / "health" / "summary.json"
PURPLE = REPO_ROOT / "deploy" / "evidence" / "purple" / "emulation_results.json"
CASE = REPO_ROOT / "analysis" / "out" / "summary.json"

PERSONAL_TERMS = re.compile(
    r"\b(CV|curriculum vitae|interview|hiring|resume|career)\b", re.IGNORECASE
)


def test_communication_documents_exist() -> None:
    for path in (DEMO, WRITEUP, OPERATIONS, ROADMAP):
        assert path.exists(), path


def test_demo_uses_current_numbers() -> None:
    text = re.sub(r"\s+", " ", DEMO.read_text(encoding="utf-8"))
    health = json.loads(HEALTH.read_text(encoding="utf-8"))["totals"]
    purple = json.loads(PURPLE.read_text(encoding="utf-8"))["summary"]
    case = json.loads(CASE.read_text(encoding="utf-8"))
    assert str(health["rules"]) in text
    assert f"{health['stable']} stable" in text
    assert f"{purple['expectations_detected']}/{purple['expectations_total']}" in text
    assert str(case["alerts"]["raw"]) in text
    assert f"{case['episodes']['total']} one-minute episodes" in text
    assert "five operational events" in text


def test_writeup_states_its_scope() -> None:
    text = re.sub(r"\s+", " ", WRITEUP.read_text(encoding="utf-8")).lower()
    assert "not production telemetry" in text
    assert "dockerised" in text
    assert "n=4" in text


def test_docs_do_not_contain_personal_career_material() -> None:
    for path in (README, DEMO, WRITEUP, OPERATIONS, ROADMAP):
        text = path.read_text(encoding="utf-8")
        assert not PERSONAL_TERMS.search(text), f"personal career language in {path}"


def test_docs_do_not_repeat_stale_numbers() -> None:
    for path in (README, DEMO, WRITEUP, OPERATIONS, ROADMAP):
        text = path.read_text(encoding="utf-8")
        assert "17.5%" not in text
        assert "52 benign" not in text


def test_operations_walkthrough_links_a_runbook() -> None:
    text = OPERATIONS.read_text(encoding="utf-8")
    assert "runbooks/modbus-unauthorized-write.md" in text


def test_demo_uses_the_current_coverage_number() -> None:
    # The demo does not need the raw coverage number, but if it quotes it, it
    # must match the generated map.
    summary = build_report()["summary"]
    text = DEMO.read_text(encoding="utf-8")
    if "29" in text:
        assert str(summary["techniques_covered"]) in text
