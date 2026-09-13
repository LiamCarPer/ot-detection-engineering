"""Tests for the derived ATT&CK for ICS coverage map."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from generate_coverage import TACTIC_ORDER, build_report, render_html, render_markdown  # noqa: E402

from tools.otde.rules import technique_ids  # noqa: E402


def test_summary_is_internally_consistent() -> None:
    report = build_report()
    summary = report["summary"]
    covered = [t for t in report["techniques"] if t["covered"]]
    assert summary["techniques_total"] == len(report["techniques"])
    assert summary["techniques_covered"] == len(covered)
    expected_pct = round(100 * len(covered) / len(report["techniques"]), 1)
    assert summary["coverage_pct"] == expected_pct


def test_covered_techniques_are_known() -> None:
    report = build_report()
    known = technique_ids()
    covered = {t["id"] for t in report["techniques"] if t["covered"]}
    assert covered <= known


def test_rule_counts_match_sources() -> None:
    for technique in build_report()["techniques"]:
        assert technique["rule_count"] == len(technique["sources"])


def test_tactics_follow_matrix_order() -> None:
    names = [tactic["shortname"] for tactic in build_report()["tactics"]]
    assert names == TACTIC_ORDER


def test_renderers_produce_output() -> None:
    report = build_report()
    assert "MITRE ATT&CK for ICS Coverage" in render_markdown(report)
    assert "<html" in render_html(report)
