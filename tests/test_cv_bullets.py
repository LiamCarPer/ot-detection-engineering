"""Keep the communication package anchored to the current evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from generate_coverage import build_report  # noqa: E402

CV = REPO_ROOT / "docs" / "CV_BULLETS.md"
WRITEUP = REPO_ROOT / "docs" / "WRITEUP.md"
DEMO = REPO_ROOT / "docs" / "DEMO.md"
OPERATIONS = REPO_ROOT / "docs" / "OPERATIONS.md"
ROADMAP = REPO_ROOT / "docs" / "ROADMAP.md"
HEALTH = REPO_ROOT / "deploy" / "evidence" / "health" / "summary.json"
PURPLE = REPO_ROOT / "deploy" / "evidence" / "purple" / "emulation_results.json"
CASE = REPO_ROOT / "analysis" / "out" / "summary.json"


def test_communication_documents_exist() -> None:
    for path in (CV, WRITEUP, DEMO, OPERATIONS, ROADMAP):
        assert path.exists(), path


def test_cv_bullets_use_current_coverage_and_catalogue_counts() -> None:
    text = CV.read_text(encoding="utf-8")
    coverage = build_report()["summary"]
    health = json.loads(HEALTH.read_text(encoding="utf-8"))
    assert f"{coverage['techniques_covered']} ATT&CK" in text
    assert str(health["totals"]["rules"]) in text
    assert f"{health['totals']['stable']} stable" in text


def test_cv_bullets_use_current_purple_and_case_numbers() -> None:
    text = CV.read_text(encoding="utf-8")
    purple = json.loads(PURPLE.read_text(encoding="utf-8"))["summary"]
    case = json.loads(CASE.read_text(encoding="utf-8"))
    assert f"{purple['expectations_detected']}/{purple['expectations_total']}" in text
    assert str(case["alerts"]["raw"]) in text
    assert f"{case['episodes']['total']} episodes" in text
    assert f"{case['campaigns']['total']} operational events" in text


def test_cv_bullets_state_their_scope() -> None:
    text = CV.read_text(encoding="utf-8")
    assert "n=4" in text
    assert "not a production plant" in text
    assert "generated or small committed samples" in text


def test_cv_bullets_do_not_repeat_stale_or_overclaimed_numbers() -> None:
    text = CV.read_text(encoding="utf-8")
    for stale in ("17.5%", "52 benign", "0.0 FPR", "field-proven", "production FPR"):
        assert stale not in text
